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

mod ai;
mod translation;
mod auth;
mod avatar;
mod bots;
mod captcha;
mod certs;
mod crypto;
mod e2e;
mod e2e_bridge;
mod reactions;
mod keepnick;
mod email;
mod ipc_client;
mod irc;
mod lastfm;
mod logs;
mod mcp;
mod passkeys;
mod notifications;
mod paste;
mod paste_render;
mod preview;
mod sysstatus;
mod twitter;
mod upload;
#[cfg(test)]
mod version_sync;

use cryptirc::ircproto::strip_crlf;

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
    /// Per-user server-side bot config (Weather/UD triggers). Server-readable so
    /// bots run 24/7 regardless of vault state. Keyed by username.
    pub bots:                Arc<DashMap<String, bots::BotConfig>>,
    /// Set of conn_ids that have been explicitly disconnected (suppresses auto-reconnect)
    pub disconnect_requests: Arc<DashSet<String>>,
    /// conn_ids that should be dialed as soon as the irc-core IPC channel comes back up.
    pub pending_dials:       Arc<DashSet<String>>,
    /// JoinHandle of the currently-running connect() task per conn_id.
    /// Aborting this handle kills the reconnect loop deterministically — replaces
    /// the old "set flag + sleep 200ms + clear flag" race that let zombie tasks
    /// survive a disconnect and reconnect in parallel with the new task.
    pub connect_tasks:       Arc<DashMap<String, tokio::task::JoinHandle<()>>>,
    /// Whatever IPC connection to the irc-core daemon is CURRENTLY up — `None`
    /// while disconnected/reconnecting. `IrcConnection::send_raw` and every
    /// Dial/Drop/RawSend call site read through this same cell, so a daemon
    /// reconnect (which mints a fresh channel) transparently keeps every live
    /// connection able to send without updating them individually.
    pub ipc_out:             Arc<tokio::sync::Mutex<Option<tokio::sync::mpsc::UnboundedSender<cryptirc::ipc::IpcMessage>>>>,
    pub crypto:              Arc<CryptoManager>,
    pub certs:               Arc<CertStore>,
    pub logger:              Arc<EncryptedLogger>,
    pub auth:                Arc<AuthManager>,
    passkeys:                Arc<passkeys::Service>,
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
    /// Cached copy of the public news feed (cryptirc.com/news/news.json), served by
    /// /api/news. (body, fetched_at) — refreshed after NEWS_TTL; stale copy served on
    /// a fetch failure. Fixed URL ⇒ no SSRF.
    pub news_cache:          Arc<tokio::sync::Mutex<Option<(String, std::time::Instant)>>>,
    /// User avatars (avatar.rs): the per-account index, the admin on/off switch, the
    /// processing slot and the lookup limiter.
    pub avatars:             Arc<avatar::AvatarStore>,
    /// Avatars of people on other CryptIRC servers (avatar/remote.rs): fetch cache, limits.
    pub avatar_remote:       Arc<avatar::remote::RemoteAvatars>,
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

    /// Defensive backstop enforcing the invariant that every `connections` entry has a
    /// matching `conn_owners` record. A connection with no owner is unroutable —
    /// `ensure_connection_entry` resolves the owner first and returns None, and Attach
    /// reconciliation can't re-Dial it — so it would linger uselessly for the process's
    /// whole life. The known leak paths are all fixed at the source (RemoveNetwork and
    /// account teardown remove both maps together; the daemon's Disconnected echo does
    /// too), and creation always establishes `conn_owners` before `connections`, so in
    /// practice this fires only on the sub-microsecond gap between two adjacent DashMap
    /// ops or on some future bug that breaks the invariant — cheap, safe insurance
    /// either way. It deliberately does NOT reap the reverse: a `conn_owners` entry with
    /// no connection is a normal not-currently-connected network (conn_owners is seeded
    /// from disk for EVERY config at startup) and must be kept.
    pub fn prune_orphan_conn_maps(&self) {
        let orphans: Vec<String> = self.connections.iter()
            .map(|e| e.key().clone())
            .filter(|cid| !self.conn_owners.contains_key(cid))
            .collect();
        for cid in orphans {
            // Re-check owner-absence under the shard lock so a concurrent AddNetwork /
            // re-Dial that just (re)established the owner isn't clobbered.
            let removed = self.connections.remove_if(&cid, |_, _| !self.conn_owners.contains_key(&cid)).is_some();
            if removed {
                self.abort_connect_task(&cid);
                self.clear_pending_dial(&cid);
                self.clear_disconnect_request(&cid);
            }
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
        // One bucket for generic /preview and every /tweet/* route (see preview_rate_ok).
        preview_rate_ok(&self.preview_rate, username)
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
    pub fn queue_pending_dial(&self, conn_id: &str) {
        self.pending_dials.insert(conn_id.to_string());
    }
    pub fn clear_pending_dial(&self, conn_id: &str) {
        self.pending_dials.remove(conn_id);
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
        // codex P1 main.rs:372: hold the username for the WHOLE teardown. Before, the user
        // record was deleted early (inside delete_account) while uploads, bots and — last —
        // the in-memory vault key were still being torn down, so a same-name re-registration
        // in that window could log in and receive the previous owner's VaultUnlocked / E2E
        // key on its WebSocket. Now: every session is revoked and the name refuses login /
        // sessions / registration from here on; users/<name>.json is removed only as the
        // final step (after the vault purge); and the name stays reserved until the deleted
        // account's last socket has closed (release_deleted_username).
        self.auth.begin_account_deletion(&uname).await;
        // r5 (agy P1 main.rs:326): lines held while this account's vault was locked are
        // discarded — they can never be written now, they kept the deleted text in memory and
        // counted against the process-wide hold budget forever.
        crate::irc::discard_held_logs(&uname, None, None).await;
        let started = std::time::Instant::now();
        // Disconnect every IRC connection owned by this user FIRST, so no auto-
        // reconnecting task survives to keep a ghost session online as the deleted user.
        // The live sockets belong to the irc-core daemon, so this must be an IPC Drop
        // (exactly what Disconnect / RemoveNetwork send). A bare `QUIT` through send_raw
        // is not enough: the daemon sees the server close the link, auto-reconnects and
        // re-joins forever, and once conn_owners is gone nobody can ever reach it again.
        // Candidates = conn_owners entries for this user ∪ the network configs on disk
        // (belt-and-braces: a Drop for a conn_id the daemon doesn't hold is a no-op).
        let mut conns: Vec<String> = self.conn_owners.iter()
            .filter(|e| e.value() == &uname)
            .map(|e| e.key().clone())
            .collect();
        // v-srv-a NEW-1: a disk-only candidate that ANOTHER account's networks/ dir also
        // names is never Dropped (that's the other user's session, e.g. after a restart
        // left the colliding id unowned). If the other dirs can't all be read, no disk-
        // only candidate is trusted (fail closed); conn_owners-attributed ones still are.
        let (all_configs, complete) = scan_network_configs(&self.data_dir).await;
        let claimed_by_others: std::collections::HashSet<String> = all_configs.iter()
            .filter(|(u, _)| u != &uname)
            .map(|(_, stem)| stem.to_ascii_lowercase())
            .collect();
        let net_dir = std::path::PathBuf::from(&self.data_dir).join("networks").join(&uname);
        if let Ok(mut rd) = tokio::fs::read_dir(&net_dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                if let Some(cid) = path.file_stem().and_then(|s| s.to_str()) {
                    // Only canonical server-minted ids (#23: lowercase UUIDs) from disk; a
                    // legacy or re-cased stem could name another user's live connection.
                    if purge_disk_conn_id_ok(cid) && !conns.iter().any(|c| c == cid) {
                        if !complete || claimed_by_others.contains(cid) {
                            warn!("[{}] account purge of {}: another account's config names this id (or networks/ could not be fully read) — not dropping it", cid, uname);
                            continue;
                        }
                        conns.push(cid.to_string());
                    }
                }
            }
        }
        for cid in &conns {
            self.drop_conn_for_purge(&uname, cid, false).await;
        }
        // Delete account data (networks/e2e/logs/certs/sessions/user dir) — but keep the user
        // record itself until the end, so the name stays taken (see above).
        self.auth.delete_account_data(&uname).await;
        // The avatar lives in users/<name>/ (removed just above); drop its index entry too,
        // so its token stops resolving at once.
        self.avatars.purge_user(&uname).await;
        // Second pass, AFTER the configs are gone: a Connect / vault-unlock reconnect from
        // another tab that read the config before delete_account could have re-inserted
        // conn_owners and sent a fresh Dial between the first pass and the delete. Both of
        // those paths re-read the config under network_config_lock, so once this pass has
        // taken each lock no new Dial can follow; any racer that already got in is dropped.
        for cid in &conns {
            self.drop_conn_for_purge(&uname, cid, true).await;
        }
        // delete_account leaves uploaded files, push subscriptions, notif prefs and
        // abandoned chunked uploads on disk. Clear them too so deletion leaves no
        // residue — critical because a later re-registration of the SAME username
        // would otherwise inherit them (e.g. push notifications routed to the prior
        // owner's devices). Mirrors the path scheme notifications.rs uses
        // ({data_dir}/push/{safe}.json, {data_dir}/notif_prefs/{safe}.json).
        upload::clear_user_uploads(&self.data_dir, &self.upload_dir, &uname).await;
        // r4 C1-5: under the notifier's per-user lock, so a subscribe that was admitted
        // before the sessions were revoked (and is still resolving its endpoint) either
        // finishes first and is removed here, or re-checks its session after this and fails.
        self.notifier.purge_user(&uname).await;
        // r4 C1-7 (integrator decision): the account's pastes go too, as in Clear All Data —
        // they must not stay public, nor be attributed to a later same-name account.
        let n = self.paste_store.delete_by_author(&uname).await;
        if n > 0 { info!("account purge of {}: {} paste(s) deleted", uname, n); }
        if let Some(inprog) = upload::user_inprogress_dir(&self.data_dir, &uname) {
            let _ = tokio::fs::remove_dir_all(&inprog).await;
        }
        // Bot residue: bots/<user>.json (bot config: channels, enforce rules, AI toggles)
        // and botdata/<user>.json (quotes, seen, and other people's !tell / !note text),
        // plus their in-memory copies. bots::load_all keys the config map by file stem at
        // startup and the botdata cache is lazily keyed by username, so without this a
        // re-registered same-name account inherits the prior owner's bots and stored data.
        // Evict the caches first so the hourly botdata_flush_all can't write the file back.
        self.bots.remove(&uname);
        // r7 (codex P1 bots.rs:3291): queued enforcement is discarded, and bot tasks still
        // running for the account can't re-create its bot data (generation-bound, see
        // bots::BotSlot) — the deletion is already marked, the evict below makes it final.
        bots::cancel_user_bot_work(&uname);
        bots::botdata_evict(&uname);
        bots::ai_history_clear(&uname, None);
        // Live files + interrupted-save temp files + the bot-data migration backup.
        bots::purge_user_files(&self.data_dir, &uname).await;
        // Tear down the crypto vault (zeroize+drop the in-memory master key AND remove the
        // on-disk vault salt/canary/mkey) so a re-registered same-name account can't inherit
        // the prior owner's still-unlocked vault: the WS handshake calls is_unlocked(username)
        // and, if true, hands the new session VaultUnlocked + derive_e2e_enc_key(username) —
        // the PRIOR owner's E2E key — with no passphrase. (A stale on-disk vault.mkey would
        // also permanently lock the re-registered user out of their own vault.) This MUST run
        // under the vault_lock — hence purge_vault, not a bare lock()+remove_dir_all — so a
        // concurrent unlock()/change_passphrase() can't re-insert the key after teardown.
        self.crypto.purge_vault(&uname).await;
        // Only now remove the account record (and re-run the data removal for anything a
        // racing request recreated meanwhile). The name is still reserved below.
        self.auth.delete_account(&uname).await;
        let st = self.clone();
        tokio::spawn(async move { st.release_deleted_username(uname, started).await; });
    }

    /// End of purge_account: keep the deleted name reserved until no socket of the deleted
    /// account is still subscribed to its broadcasts (sessions were revoked, so each closes
    /// at its next command or within the 30 s re-validation), plus a short margin for a
    /// vault unlock that was already deriving on the blocking pool. Then purge the vault and
    /// the bot caches once more — anything such a straggler re-created — and free the name.
    /// Capped so a wedged socket can't hold a name forever.
    async fn release_deleted_username(self, uname: String, started: std::time::Instant) {
        const QUIET: std::time::Duration = std::time::Duration::from_secs(5);
        const CAP: std::time::Duration = std::time::Duration::from_secs(600);
        let mut quiet_since: Option<std::time::Instant> = None;
        loop {
            let live = self.user_events.get(&uname).map_or(0, |tx| tx.receiver_count())
                + user_bulk_receivers(&uname);
            let now = std::time::Instant::now();
            if live == 0 {
                let q = *quiet_since.get_or_insert(now);
                if now.duration_since(q) >= QUIET { break; }
            } else {
                quiet_since = None;
            }
            if now.duration_since(started) >= CAP {
                warn!("account purge of {}: {} socket(s) still open after {:?}; releasing the name anyway", uname, live, CAP);
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        self.crypto.purge_vault(&uname).await;
        self.bots.remove(&uname);
        bots::cancel_user_bot_work(&uname);
        bots::botdata_evict(&uname);
        bots::ai_history_clear(&uname, None);
        // r7: and their files once more (the name is still reserved): nothing a straggler
        // wrote between the first pass and now survives into a same-name account.
        bots::purge_user_files(&self.data_dir, &uname).await;
        // r4 C1-7 / C1-5: a paste (protected pastes hash for a while) or a subscription
        // admitted before the purge may have landed after the first pass.
        self.paste_store.delete_by_author(&uname).await;
        self.notifier.purge_user(&uname).await;
        crate::irc::discard_held_logs(&uname, None, None).await;
        self.avatars.purge_user(&uname).await;
        self.auth.end_account_deletion(&uname);
    }

    /// Account-deletion teardown of one network: tell irc-core to Drop the session (it
    /// sends `QUIT :Account deleted` and stops reconnecting) and erase the web-side
    /// bookkeeping. Runs under the same per-config lock Connect / Disconnect /
    /// RemoveNetwork / reconnect_for_user take, so it is atomic against a concurrent
    /// Connect from another tab (see purge_account's second pass). The connections /
    /// conn_owners entries are removed in the same critical section, so the daemon's
    /// Disconnected echo (and any line still in flight) finds no owner and is ignored.
    /// `only_if_live`: (second pass) skip quietly unless a racer re-created web-side state
    /// for this conn_id — checked INSIDE the lock so a Connect mid-critical-section can't
    /// slip past — to avoid a redundant Drop (and daemon warning) per network.
    /// Ownership guard (defence in depth): if conn_owners says this conn_id belongs to a
    /// DIFFERENT account, skip it entirely — no Drop, no map removal — so deleting account
    /// A can never tear down user B's live connection, even if A's networks/ dir holds a
    /// legacy (pre-#23) or re-cased file whose stem collides with B's id.
    async fn drop_conn_for_purge(&self, uname: &str, cid: &str, only_if_live: bool) {
        let cfg_lock = network_config_lock(uname, cid);
        let _cfg_guard = cfg_lock.lock().await;
        let owner = self.conn_owners.get(cid).map(|o| o.value().clone());
        if !purge_owner_ok(owner.as_deref(), uname) {
            warn!("[{}] account purge: conn_id is owned by another account — leaving it alone", cid);
            return;
        }
        if only_if_live && !self.conn_owners.contains_key(cid) && !self.connections.contains_key(cid)
            && !self.pending_dials.contains(cid) {
            return;
        }
        self.request_disconnect(cid);
        self.abort_connect_task(cid);
        self.clear_pending_dial(cid);
        ipc_client::send_drop(self, cid, "Account deleted".to_string()).await;
        self.connections.remove(cid);
        self.conn_owners.remove(cid);
        self.clear_disconnect_request(cid);
    }

}

/// Sockets of `username` still subscribed to the bulk channel (purge_account release).
fn user_bulk_receivers(username: &str) -> usize {
    // r3 WS-8 (srv-b) split the bulk channel into WS_BULK_KINDS rings; every socket
    // subscribes to all of them (user_bulk_subscribe), so the busiest ring is the count.
    user_bulk_events().get(username)
        .map_or(0, |txs| txs.iter().map(|tx| tx.receiver_count()).max().unwrap_or(0))
}

/// purge_account: may the purge of `uname` touch a conn_id whose conn_owners entry is
/// `owner`? Only if it has no owner or `uname` owns it.
fn purge_owner_ok(owner: Option<&str>, uname: &str) -> bool {
    owner.map_or(true, |o| o == uname)
}

/// purge_account: accept a networks/<user>/*.json stem as a conn_id only in the canonical
/// server-generated form (lowercase UUID, #23).
fn purge_disk_conn_id_ok(stem: &str) -> bool {
    validate_uuid(stem).as_deref() == Some(stem)
}

#[cfg(test)]
mod purge_guard_tests {
    use super::*;
    #[test]
    fn purge_never_touches_another_accounts_conn() {
        assert!(purge_owner_ok(None, "alice"));
        assert!(purge_owner_ok(Some("alice"), "alice"));
        assert!(!purge_owner_ok(Some("bob"), "alice"));
    }
    #[test]
    fn purge_disk_ids_must_be_canonical_uuids() {
        assert!(purge_disk_conn_id_ok("0f8fad5b-d9cb-469f-a165-70867728950e"));
        assert!(!purge_disk_conn_id_ok("0F8FAD5B-D9CB-469F-A165-70867728950E"));
        assert!(!purge_disk_conn_id_ok("freenode"));
        assert!(!purge_disk_conn_id_ok("../x"));
    }
}

impl AppState {
    /// #F9: Remove a user's push subscriptions + notification prefs from disk. Called on
    /// password reset / password change / admin disable — all of which purge sessions but,
    /// without this, leave push subscriptions intact. An attacker who subscribed one of THEIR
    /// devices to the victim's account would keep receiving the victim's DMs/mentions
    /// (plaintext body) even after the victim recovers the account. Removing the push records
    /// on recovery cuts that channel; the legitimate user re-subscribes on their next opt-in.
    /// Mirrors purge_account's / notifications.rs's sanitization + path scheme
    /// ({data_dir}/push/{safe}.json, {data_dir}/notif_prefs/{safe}.json).
    ///
    /// r4 C1-5 (codex P1 notifications.rs:543): removed under NotificationManager's per-user
    /// lock (purge_user). A subscribe admitted before the reset revoked the sessions used to
    /// resolve its (attacker-controlled, slow) endpoint first and write afterwards —
    /// re-creating the purged file. save_subscription now re-checks the session under that
    /// same lock, and the callers revoke sessions before calling this.
    pub async fn purge_push_subscriptions(&self, username: &str) {
        self.notifier.purge_user(username).await;
    }
}

// ─── Protocol types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    // r2: `e2e` = the E2E protocol generation the browser client speaks (current
    // app.js sends 2; older app.js and the TUI send nothing). Used to protect a stale
    // cached app.js from silently sending cleartext (see e2e_send_blocked).
    Auth             { token: String, #[serde(default)] e2e: u32 },
    UnlockVault      { passphrase: String },
    LockVault        {},
    ChangePassphrase { old: String, new: String },
    AddNetwork       { network: NetworkConfig },
    UpdateNetwork    { network: NetworkConfig },
    KeepNick         { conn_id: String, nick: Option<String>, #[serde(default)] stop: bool, #[serde(default)] import: bool },
    React            { conn_id: String, target: String, request_id: String, reaction: reactions::ReactionSend },
    RemoveNetwork    { id: String },
    Connect          { id: String },
    // `reason` carries the reason typed with `/quit <msg>`. Additive and
    // `serde(default)`, so the Disconnect button (and any older client) can keep
    // sending `{type:'disconnect',id}` with no reason and still get the configured
    // Quit Message via `quit_reason_for`. Web-only: `IpcMessage::Drop` already
    // carried a reason, so the daemon needs no change for this.
    // `from_lock` (r3 WW-2) is never read from the wire (`serde(skip)`): the WS recv loop
    // sets it on the `disconnect` frames a client sends right after its own `lock_vault`
    // (app.js _lockVaultNow, every app.js version), so a vault lock is not recorded as the
    // user's explicit Disconnect. See mark_lock_burst.
    Disconnect       { id: String, #[serde(default)] reason: Option<String>, #[serde(skip)] from_lock: bool },
    Send             { conn_id: String, raw: String },
    ListChannels     { conn_id: String, request_id: String, pattern: String },
    JoinChannel      { conn_id: String, channel: String, key: Option<String> },
    PartChannel      { conn_id: String, channel: String },
    // `before_id` (optional, additive): id of the oldest line the client shows, an exact
    // paging cursor inside the `before` second (see logs::read_logs_before_id).
    // `status_view` (optional, additive): "server" | "query" — for target "status" only,
    // return just the server's own output or just the DMs of a user nicked `status`
    // (they share one log). Absent = both, as before. See logs::StatusView.
    GetLogs          { conn_id: String, target: String, limit: Option<usize>, before: Option<i64>, #[serde(default)] before_id: Option<u64>, #[serde(default)] status_view: Option<String> },
    SearchLogs       { conn_id: String, target: String, query: String, limit: Option<usize> },
    Sync             { conn_id: String, target: String, after_id: u64, #[serde(default)] status_view: Option<String> },
    GetState         {},
    // Certificate management
    GenerateCert     { conn_id: String },
    DeleteCert       { conn_id: String },
    GetCertInfo      { conn_id: String },
    // E2E encryption — explicit renames because snake_case turns E2E into e2_e
    // `expect` (r3, optional): "" = store only if no identity is stored yet (first
    // unlock; two devices racing can't both install one). Absent = unconditional.
    #[serde(rename = "e2e_store_identity")]
    E2EStoreIdentity  { blob: String, #[serde(default)] expect: Option<String> },
    #[serde(rename = "e2e_load_identity")]
    E2ELoadIdentity   {},
    // `v` (C1 migration guard): clients that wrap blobs under the client-held key send
    // v:2. Once a user's blobs were migrated, a publish/add WITHOUT it (a stale cached
    // app.js) is refused so it can't replace the identity/prekeys it can't read.
    // `id_hash` (r3, optional): SHA-256 hex of the identity blob this bundle belongs to;
    // the publish is refused when the stored identity is a different one.
    #[serde(rename = "e2e_publish_bundle")]
    E2EPublishBundle  { bundle: KeyBundle, #[serde(default)] v: u32, #[serde(default)] id_hash: Option<String> },
    #[serde(rename = "e2e_add_otpks")]
    E2EAddOTPKs       { keys: Vec<OneTimePrekey>, #[serde(default)] v: u32 },
    // conn_id (optional, F11): the connection the nick was seen on, so the lookup
    // prefers the account actually holding that nick on that network.
    #[serde(rename = "e2e_fetch_bundle")]
    E2EFetchBundle    { username: String, #[serde(default)] conn_id: Option<String>, #[serde(default)] req: Option<String> },
    #[serde(rename = "e2e_store_session")]
    E2EStoreSession   { partner: String, blob: String,
                        // r2 (NEW-7): sending device id + "this save follows a send".
                        #[serde(default)] dv: Option<String>, #[serde(default)] snd: bool },
    #[serde(rename = "e2e_load_session")]
    E2ELoadSession    { partner: String },
    #[serde(rename = "e2e_delete_session")]
    E2EDeleteSession  { partner: String, #[serde(default)] v: u32, #[serde(default)] req: Option<String> },
    #[serde(rename = "e2e_store_channel_key")]
    E2EStoreChannelKey  { channel: String, blob: String },
    #[serde(rename = "e2e_load_channel_key")]
    E2ELoadChannelKey   { channel: String, #[serde(default)] req: Option<String> },
    #[serde(rename = "e2e_delete_channel_key")]
    E2EDeleteChannelKey { channel: String, #[serde(default)] v: u32, #[serde(default)] req: Option<String> },
    #[serde(rename = "e2e_list_channel_keys")]
    E2EListChannelKeys  {},
    #[serde(rename = "e2e_update_trust", alias = "e2e_load_trust")]
    E2ELegacyTrust    {},
    // conn_id (optional, F10): the sender's connection; from_nick and the target
    // lookup are taken from / scoped to that network.
    #[serde(rename = "e2e_relay_x3dh")]
    E2ERelayX3DH      { target_nick: String, header: serde_json::Value, #[serde(default)] conn_id: Option<String> },
    #[serde(rename = "e2e_check_otpk_count")]
    E2ECheckOTPKCount {},
    // C1: client-held keyring (wrapped E2E master key) + migration support.
    #[serde(rename = "e2e_load_keyring")]
    E2ELoadKeyring    {},
    #[serde(rename = "e2e_store_keyring")]
    E2EStoreKeyring   { blob: String, #[serde(default)] migrated: bool,
                        // r2: the keyring the client expects to replace ("" = create only).
                        #[serde(default)] expect: Option<String> },
    #[serde(rename = "e2e_rewrap_blob")]
    E2ERewrapBlob { slot: String, name: String, expect: String, blob: String },
    #[serde(rename = "e2e_list_sessions")]
    E2EListSessions   {},
    // Appearance
    SaveAppearance    { settings: String },
    LoadAppearance    {},
    SavePreferences   { prefs: String },
    LoadPreferences   {},
    /// Save/replace this user's server-side bot config (JSON of bots::BotConfig).
    SaveBotConfig     { config: String },
    LoadBotConfig     {},
    /// Owner's private bot lookup (e.g. /w, /ud, /ai) — result returns only to them.
    /// `conn_id` (optional) is the active connection, so /ai can build IRC awareness.
    BotQuery          { bot: String, query: String, #[serde(default)] conn_id: String, #[serde(default)] channel: String },
    /// Save/remove the AI bot's API key for one provider (vault-encrypted at rest).
    SaveAiKey         { provider: String, key: String },
    /// Owner directs the AI to act in a channel (/aido) — it may run its safe IRC
    /// actions there (when commands are enabled) and posts its reply to the channel.
    AiDo              { conn_id: String, target: String, query: String },
    /// Owner wipes ALL of this account's AI conversation memory.
    ClearAiHistory    {},
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
    // r10: `assets` = frontend_id() of this server (see there); a page served by an earlier
    // deploy compares it with its own CRYPTIRC_ASSETS on every (re)connect.
    AuthOk           { username: String, assets: String },
    AuthFailed       { message: String },
    VaultLocked      {},
    /// vault_verified distinguishes a passphrase-proven response from a state refresh.
    /// Older key material is sent only to a verified socket while migration requires it.
    /// e2e_enc_key is kept for older clients that still expect a string field.
    VaultUnlocked    {
        e2e_enc_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")] e2e_legacy_key: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")] e2e_pepper: Option<String>,
        #[serde(default)] e2e_migrated: bool,
        #[serde(default)] vault_verified: bool,
    },
    VaultError       { message: String },
    /// `replayed` = true when this message was re-emitted from the daemon's
    /// Attach-time ring-buffer replay (a `cryptirc.service` restart reattaching to
    /// the still-live daemon), NOT received live. The browser renders it into
    /// scrollback either way but deterministically suppresses desktop
    /// notifications + unread badges for replayed history, instead of relying on
    /// the age>60s ZNC-playback heuristic (which misses recent replayed lines).
    /// Stamped centrally by `dispatch_line`'s `send` closure. `#[serde(default)]`
    /// so it's absent-safe. `skip_serializing_if` keeps live traffic byte-identical
    /// on the wire (the common case emits nothing).
    IrcMessage       { conn_id: String, from: String, target: String, text: String, ts: i64, kind: MessageKind, msg_id: u64, #[serde(skip_serializing_if = "Option::is_none")] prefix: Option<String>, #[serde(default, skip_serializing_if = "std::ops::Not::not")] replayed: bool },
    /// Echo of user's own sent message — for multi-device sync
    IrcEcho          { conn_id: String, from: String, target: String, text: String, ts: i64, kind: MessageKind, msg_id: u64 },
    /// Remote avatars: something changed for these nicks on this connection (an announce was
    /// learned or dropped, a picture arrived) — the app asks again (POST /api/avatar/lookup).
    AvatarHint       { conn_id: String, nicks: Vec<String> },
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
    /// 329 — RPL_CREATIONTIME: the channel's creation timestamp (unix seconds; 0 when
    /// the server sent something unparseable). Its own event rather than a plain notice
    /// so the client can decide where it belongs: spelled out when the user asked with
    /// `/mode #chan`, folded into a condensed status line for the copies nobody asked
    /// for. A bare `MODE #chan` is answered with 324 AND 329, and we send bare MODEs on
    /// our own (reattach resync, Channel Modes dialog refresh) — as an un-deduped notice
    /// this stacked another "Channel created" line in the channel every single time.
    IrcChannelCreated { conn_id: String, channel: String, created: i64 },
    /// 322 — channel list entry
    IrcListEntry     { conn_id: String, channel: String, users: u32, topic: String },
    /// Identified web requests receive bounded batches rather than one event per IRC line.
    IrcListBatch     { conn_id: String, request_id: String, entries: Vec<irc::ChannelListEntry> },
    /// 323 — end of channel list
    IrcListEnd       { conn_id: String, #[serde(default, skip_serializing_if = "Option::is_none")] request_id: Option<String>, #[serde(default, skip_serializing_if = "Option::is_none")] total: Option<usize>, #[serde(default, skip_serializing_if = "Option::is_none")] message: Option<String> },
    IrcListError     { conn_id: String, request_id: String, message: String },
    LagUpdate        { conn_id: String, ms: u64 },
    CtcpRequest      { conn_id: String, from: String, command: String, prefix: Option<String> },
    KeepNickUpdated  { conn_id: String, nick: Option<String>, imported: bool },
    ReactionSupport  { conn_id: String, enabled: bool, dislike: bool },
    ReactionAnchor   { conn_id: String, target: String, msg_id: u64, reference: String },
    ReactionResult   { request_id: String, error: Option<String> },
    IrcReaction      { conn_id: String, target: String, reference: String, from: String, prefix: Option<String>, emoji: String, remove: bool, own: bool },
    SealedReaction   { conn_id: String, target: String, from: String, prefix: Option<String>, body: String, own: bool },
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
    E2EBundle        { username: String, bundle: FetchedBundle,
                       #[serde(default, skip_serializing_if = "Option::is_none")] conn_id: Option<String>,
                       #[serde(default, skip_serializing_if = "Option::is_none")] req: Option<String>,
                       #[serde(default, skip_serializing_if = "std::ops::Not::not")] bridge: bool },
    #[serde(rename = "e2e_bundle_missing")]
    E2EBundleMissing { conn_id: String, req: String, reason: &'static str },
    #[serde(rename = "e2e_identity_blob")]
    E2EIdentityBlob  { blob: String },
    #[serde(rename = "e2e_session")]
    E2ESession       { partner: String, blob: String },
    #[serde(rename = "e2e_channel_key")]
    E2EChannelKey    { channel: String, blob: String, #[serde(default, skip_serializing_if = "Option::is_none")] req: Option<String> },
    #[serde(rename = "e2e_key_deleted")]
    E2EKeyDeleted { req: String, ok: bool },
    #[serde(rename = "e2e_channel_list")]
    E2EChannelList   { channels: Vec<String> },
    #[serde(rename = "e2e_otpk_low")]
    E2EOTPKLow       { remaining: usize },
    #[serde(rename = "e2e_x3dh_header")]
    E2EX3DHHeader    { from_nick: String, header: serde_json::Value },
    // C1: reply to e2e_load_keyring. has_identity / peers / channels let a browser that
    // can't unlock E2E yet know which targets were encrypted (so it blocks rather than
    // sends cleartext) and whether to prompt for the passphrase.
    #[serde(rename = "e2e_keyring")]
    E2EKeyring       { blob: String, migrated: bool, has_identity: bool, #[serde(default)] needs_legacy: bool, peers: Vec<String>, channels: Vec<String> },
    #[serde(rename = "e2e_keyring_stored")]
    E2EKeyringStored { migrated: bool,
                       // r2: CAS lost — nothing written; `blob` is the keyring to adopt.
                       #[serde(default, skip_serializing_if = "std::ops::Not::not")] conflict: bool,
                       #[serde(default, skip_serializing_if = "Option::is_none")] blob: Option<String> },
    #[serde(rename = "e2e_blob_rewrapped")]
    E2EBlobRewrapped { slot: String, name: String, ok: bool },
    // r2 (NEW-7): another device of this user advanced the ratchet for `partner` by
    // SENDING (dv = that device's random id). Other devices re-sync before they send.
    #[serde(rename = "e2e_session_moved")]
    E2ESessionMoved  { partner: String, dv: String },
    #[serde(rename = "e2e_session_list")]
    E2ESessionList   { partners: Vec<String> },
    Appearance       { settings: String },
    Preferences      { prefs: String },
    /// This user's current bot config (JSON) in response to LoadBotConfig.
    BotConfig        { config: String },
    /// Result of an owner's private /bot lookup, shown locally in their UI.
    BotResult        { bot: String, text: String },
    /// Which AI providers currently have a key stored (so the UI shows "key set"),
    /// sent on bot-config load and after SaveAiKey. Empty while the vault is locked.
    AiKeysSet        { providers: Vec<String> },
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
    #[serde(default)]
    pub keep_nick:             Option<String>,
    /// Distinguishes an explicit stop from an old config awaiting import.
    #[serde(default)]
    pub keep_nick_managed:     bool,
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

impl NetworkConfig {
    fn has_saved_network_secrets(&self) -> bool {
        self.password.is_some() || self.sasl_plain.is_some() || self.oper_pass.is_some()
            || self.nickserv_pass.is_some() || !self.channel_keys.is_empty() || !self.perform_commands.is_empty()
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
            keep_nick: None, keep_nick_managed: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaslConfig { pub account: String, pub password: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    pub config:       NetworkConfig,
    pub connected:    bool,
    #[serde(default)]
    pub reactions:    bool,
    #[serde(default)]
    pub reaction_dislike: bool,
    pub nick:         String,
    pub channels:     Vec<ChannelState>,
    pub lag_ms:       Option<u64>,
    pub has_cert:     bool,
    pub cert_fingerprint: Option<String>,
    /// r4 (codex P2 tui/src/main.rs:615 / agy P2 / w3-ops V3O-2, additive): the server's
    /// CASEMAPPING token as this web learned it ("rfc1459" / "strict-rfc1459" / "ascii"),
    /// absent while unknown — so a client (the TUI's /cycle) can tell which saved
    /// channel-key spelling is "this channel" the way the server does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub casemapping:  Option<String>,
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

/// r3 C1-5: run one vault KDF job (UnlockVault / ChangePassphrase) on the blocking pool
/// behind `sem`, with the permit MOVED INTO the blocking closure — exactly like
/// run_auth_kdf. The WS handlers used to hold the permit in the async caller: when a
/// socket was torn down its recv task was aborted, the permit dropped, and the
/// already-running spawn_blocking derivation kept going, so the cap stopped bounding the
/// number of live 64-MiB derivations. Now the permit is released only when the derive
/// itself finishes. None = the blocking task panicked / was cancelled.
async fn run_vault_kdf<T, F>(sem: &'static Semaphore, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let permit = sem.acquire().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        f()
    }).await.ok()
}

/// rust-http #3: the HTTP auth routes (login / register / password reset / change
/// password / admin add-user) each run a 64-MiB, t=3 Argon2id hash or verify inside
/// AuthManager. Run directly on a tokio worker, two concurrent logins froze every route
/// and WebSocket on a 2-vCPU host, and nothing bounded how many 64-MiB buffers could be
/// live at once. `run_auth_kdf` moves the whole auth call onto the blocking pool behind
/// this process-wide cap (separate from KDF_SEM so an unauthenticated login flood can't
/// starve logged-in users' vault unlocks). Capped at the CPU count (2..=4): Argon2 p=1 is
/// single-threaded, so more in flight adds memory, not throughput.
static AUTH_KDF_SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
fn auth_kdf_sem() -> &'static Semaphore {
    AUTH_KDF_SEM.get_or_init(|| {
        let n = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2);
        Semaphore::new(n.clamp(2, 4))
    })
}
/// How long a request waits for an auth-KDF slot before getting a 503.
const AUTH_KDF_QUEUE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Run an AuthManager call that does Argon2 work off the async workers, holding an
/// AUTH_KDF_SEM permit for its whole duration. The permit moves INTO the blocking task,
/// so a client that disconnects mid-request (axum drops the handler future) cannot free
/// its slot while the Argon2 work is still running. Returns None when no slot frees up
/// within AUTH_KDF_QUEUE_TIMEOUT (callers answer 503) or if the task panicked.
pub(crate) async fn run_auth_kdf<T, F, Fut>(f: F) -> Option<T>
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T>,
    T: Send + 'static,
{
    let permit = match tokio::time::timeout(AUTH_KDF_QUEUE_TIMEOUT, auth_kdf_sem().acquire()).await {
        Ok(Ok(p)) => p,
        _ => return None,
    };
    let handle = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        handle.block_on(f())
    }).await.ok()
}

fn auth_busy_response() -> Response {
    (StatusCode::SERVICE_UNAVAILABLE, Json(Msg { message: "Server busy — please try again in a moment.".into() })).into_response()
}

// #33: process-wide cap on concurrently-buffered chunk uploads + per-chunk buffer
// ceiling. Each in-flight /upload/chunk POST reads its body into RAM before the
// disk append; PER_USER_MAX_INPROGRESS bounds distinct upload ids, not the number
// of chunk POSTs in flight, and the old route buffered a fixed 64 MiB per chunk
// regardless of max_upload_mb. The permit is acquired BEFORE the body is read and
// the buffer is capped via to_bytes(), so at most UPLOAD_CHUNK_MAX_CONCURRENT
// bodies of <= UPLOAD_CHUNK_MAX_BYTES are resident process-wide. Held only for the
// read + append and released on drop; load is shed (503) when saturated.
const UPLOAD_CHUNK_MAX_CONCURRENT: usize = 16;
const UPLOAD_CHUNK_MAX_BYTES: usize = 8 * 1024 * 1024;
static UPLOAD_CHUNK_SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
fn upload_chunk_sem() -> &'static Semaphore {
    UPLOAD_CHUNK_SEM.get_or_init(|| Semaphore::new(UPLOAD_CHUNK_MAX_CONCURRENT))
}

// #14: cap concurrent WebSocket connections globally and per real client IP so a
// connection flood from a few IPs can't exhaust tokio tasks / file descriptors. The
// permit + per-IP slot are released by `WsConnGuard` on disconnect.
const WS_MAX_GLOBAL_CONNS: usize = 4000;
const WS_MAX_PER_IP_CONNS: usize = 64;
static WS_SEM: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
fn ws_sem() -> &'static Semaphore {
    WS_SEM.get_or_init(|| Semaphore::new(WS_MAX_GLOBAL_CONNS))
}
fn ws_ip_counts() -> &'static dashmap::DashMap<String, usize> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, usize>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}
/// Holds a global WS permit for the connection's lifetime and decrements the per-IP
/// counter on drop (disconnect), so both caps self-heal.
struct WsConnGuard {
    _permit: tokio::sync::SemaphorePermit<'static>,
    ip: Option<String>,
}
impl Drop for WsConnGuard {
    fn drop(&mut self) {
        if let Some(ip) = &self.ip {
            if let Some(mut c) = ws_ip_counts().get_mut(ip) {
                *c = c.saturating_sub(1);
            }
            ws_ip_counts().remove_if(ip, |_, &v| v == 0);
        }
    }
}


async fn security_headers_mw(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    let page_scripts = response.extensions_mut().remove::<PageScriptNonce>();
    let h = response.headers_mut();
    // `serve_paste_app` marks its response so it may be framed by the same-origin
    // paste page; the marker is private and removed here before the response leaves.
    let is_app_frame = h.remove(HeaderName::from_static(PASTE_APP_FRAME_MARKER)).is_some();
    let is_sandbox_doc = h.remove(HeaderName::from_static(PASTE_SANDBOX_DOC_MARKER)).is_some();
    apply_security_headers(h, is_app_frame, page_scripts.as_ref());
    if is_sandbox_doc && !is_app_frame { apply_sandbox_doc_csp(h); }
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
    response
}

/// Apply the framing/CSP headers for a response. `is_app_frame` selects the
/// sandboxed-HTML-paste app policy (the ONLY route framable by the same-origin
/// paste page); every other response keeps the strict global deny policy.
///
/// Security invariants:
/// - The app document is framable only by `'self'` and runs under a CSP `sandbox`
///   directive without `allow-same-origin`, so it has an opaque origin and cannot
///   touch CryptIRC cookies/session/storage or its parent document.
/// - The global policy keeps `frame-ancestors 'none'` + `XFO: DENY`, so the
///   `frame-src 'self'` allowance (needed to frame the app route) cannot expose
///   any other route to framing.
fn apply_security_headers(h: &mut HeaderMap, is_app_frame: bool, nonce: Option<&PageScriptNonce>) {
    if is_app_frame {
        h.insert(HeaderName::from_static("x-frame-options"), HeaderValue::from_static("SAMEORIGIN"));
        // NOTE (#55): 'unsafe-inline'/'unsafe-eval' and wildcard sources are the
        // point of this isolated document — it is an opaque-origin sandbox running
        // user-supplied single-file apps (CDN scripts, API calls). None of it can
        // reach the CryptIRC origin.
        h.insert(HeaderName::from_static("content-security-policy"), HeaderValue::from_static(
            "sandbox allow-scripts allow-forms allow-modals allow-popups allow-downloads allow-pointer-lock; \
             default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; \
             script-src * 'unsafe-inline' 'unsafe-eval' data: blob:; \
             style-src * 'unsafe-inline'; \
             img-src * data: blob:; \
             media-src * data: blob:; \
             font-src * data:; \
             connect-src *; \
             worker-src * blob:; \
             frame-src *; \
             child-src *; \
             base-uri 'none'; \
             form-action *; \
             frame-ancestors 'self';"
        ));
        return;
    }
    h.insert(HeaderName::from_static("x-frame-options"),          HeaderValue::from_static("DENY"));
    const PAGE_CSP: &str =
        "default-src 'self'; object-src 'none'; base-uri 'none'; script-src 'self'; script-src-attr 'none'; \
         style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; \
         font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https:; \
         media-src 'self' blob: data: https:; \
         connect-src 'self' wss: ws: https://noembed.com https://returnyoutubedislikeapi.com https://api.urbandictionary.com https://api.giphy.com https://tenor.googleapis.com; \
         frame-src 'self' https://www.youtube.com https://www.youtube-nocookie.com; frame-ancestors 'none';";
    let policy = match nonce {
        Some(nonce) => HeaderValue::try_from(PAGE_CSP.replace("script-src 'self';",
            &format!("script-src 'self' 'nonce-{}';", nonce.0)))
            .expect("base64 nonce is a valid header value"),
        None => HeaderValue::from_static(PAGE_CSP),
    };
    h.insert(HeaderName::from_static("content-security-policy"), policy);
}

#[derive(Clone)]
struct PageScriptNonce(String);

impl PageScriptNonce {
    fn new() -> Self {
        Self(base64::Engine::encode(&base64::engine::general_purpose::STANDARD,
            rand::random::<[u8; 16]>()))
    }
}

#[cfg(test)]
mod security_headers_tests {
    use super::*;

    #[test]
    fn app_frame_gets_sameorigin_sandbox_policy() {
        let mut h = HeaderMap::new();
        apply_security_headers(&mut h, true, None);
        assert_eq!(h.get("x-frame-options").unwrap(), "SAMEORIGIN");
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'self'"), "{}", csp);
        assert!(csp.contains("sandbox allow-scripts"), "{}", csp);
        assert!(!csp.contains("allow-same-origin"), "{}", csp);
        assert!(!csp.contains("frame-ancestors 'none'"), "{}", csp);
    }

    #[test]
    fn normal_responses_keep_deny_policy() {
        let mut h = HeaderMap::new();
        apply_security_headers(&mut h, false, None);
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        let csp = h.get("content-security-policy").unwrap().to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"), "{}", csp);
        assert!(csp.contains("frame-src 'self'"), "{}", csp);
        assert!(!csp.contains("sandbox allow-scripts"), "{}", csp);
    }
}

// ─── Main ─────────────────────────────────────────────────────────────────────

/// RUST_LOG filter for the service. Same behaviour as `tracing_subscriber::fmt::init()`
/// (default: ERROR), except that the HTML tokenizer crates are always silenced: html5ever
/// logs input characters / text runs at trace level, and its input is third-party content
/// (X thread previews) that must never reach the logs, whatever RUST_LOG says. A more
/// specific user directive (e.g. `html5ever::tokenizer=trace`) would beat an added
/// `html5ever=off`, so every user directive whose target starts with one of these crates is
/// dropped first (`env` = the RUST_LOG value; `None` reads the environment).
const LOG_SILENCED_CRATES: &[&str] = &["html5ever", "markup5ever"];

fn log_filter(env: Option<&str>) -> tracing_subscriber::EnvFilter {
    let raw = match env {
        Some(directives) => directives.to_owned(),
        None => std::env::var("RUST_LOG").unwrap_or_default(),
    };
    let kept: Vec<&str> = raw
        .split(',')
        .map(str::trim)
        .filter(|directive| {
            let target = directive.split(['=', '[']).next().unwrap_or("").trim();
            !directive.is_empty() && !LOG_SILENCED_CRATES.iter().any(|c| target.starts_with(c))
        })
        .collect();
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::ERROR.into())
        .parse_lossy(kept.join(","));
    LOG_SILENCED_CRATES
        .iter()
        .filter_map(|c| format!("{c}=off").parse().ok())
        .fold(filter, |filter, directive| filter.add_directive(directive))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(log_filter(None)).init();
    let data_dir   = std::env::var("CRYPTIRC_DATA").unwrap_or_else(|_| "./data".into());
    let upload_dir = format!("{}/uploads", data_dir);
    // trim a trailing slash so every `{base_url}/paste/…`, `{base_url}/s/…` and
    // email link concatenation can't produce a double slash (`https://host//paste/…`)
    // when a self-hoster sets CRYPTIRC_BASE_URL with a trailing "/".
    let base_url    = std::env::var("CRYPTIRC_BASE_URL").unwrap_or_else(|_| "http://localhost:9000".into()).trim_end_matches('/').to_string();
    let from_email  = std::env::var("CRYPTIRC_FROM_EMAIL").unwrap_or_else(|_| "noreply@cryptirc.local".into());
    // Load admin settings from disk (persisted), fall back to env vars
    let admin_settings_path = std::path::PathBuf::from(&data_dir).join("admin_settings.json");
    // #112 / P6: parse admin_settings.json EXACTLY ONCE here and derive every
    // field below from this single parsed value. A corrupt/torn file must NOT
    // silently fall back to permissive defaults for ANY field (that would quietly
    // undo an admin lockdown), and the corruption must be logged loudly once.
    //   • admin_settings_val = Some(v)  → file present and parsed OK.
    //   • admin_settings_val = None + admin_settings_corrupt=true → present but
    //     UNPARSEABLE: every security-relevant field fails CLOSED.
    //   • admin_settings_val = None + admin_settings_corrupt=false → file absent:
    //     fall back to env vars / today's defaults.
    let (admin_settings_val, admin_settings_corrupt): (Option<serde_json::Value>, bool) =
        if admin_settings_path.exists() {
            let json = std::fs::read_to_string(&admin_settings_path).unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&json) {
                Ok(v) => (Some(v), false),
                Err(e) => {
                    tracing::error!("admin_settings.json is CORRUPT ({}). Failing CLOSED: registration disabled, email required, captcha on, GIF/Last.fm keys blank until fixed.", e);
                    (None, true)
                }
            }
        } else {
            (None, false)
        };

    // rust-http #5: registration_open / registration_code come from admin_settings.json
    // ONLY when the file actually contains that key (the admin explicitly saved it in the
    // panel). Otherwise the env var (or the built-in default) applies. The old code
    // ignored the env as soon as the file EXISTED, so saving link-preview (or GIF /
    // Last.fm) settings — which create the file without these keys — silently reopened a
    // CRYPTIRC_REGISTRATION=closed / CRYPTIRC_REG_CODE instance on the next restart.
    let env_reg_open = std::env::var("CRYPTIRC_REGISTRATION").unwrap_or_else(|_| "open".into()) != "closed";
    let env_reg_code = std::env::var("CRYPTIRC_REG_CODE").unwrap_or_default();
    let (registration_open, reg_code, max_upload_mb) = if let Some(v) = &admin_settings_val {
        let open = v.get("registration_open").and_then(|v| v.as_bool()).unwrap_or(env_reg_open);
        let code = v.get("registration_code").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| env_reg_code.clone());
        let upload_mb = v.get("max_upload_mb").and_then(|v| v.as_u64()).unwrap_or(25) as usize;
        info!("Loaded admin settings from disk (registration_open={} [{}], has_code={} [{}], max_upload_mb={})",
            open, if v.get("registration_open").is_some() { "admin panel" } else { "env/default" },
            !code.is_empty(), if v.get("registration_code").is_some() { "admin panel" } else { "env/default" },
            upload_mb);
        (open, code, upload_mb)
    } else if admin_settings_corrupt {
        // Fail CLOSED: registration disabled until the operator fixes the file.
        (false, String::new(), 25)
    } else {
        (env_reg_open, env_reg_code, 25)
    };
    // GIF picker policy (admin-controlled). Defaults preserve today's behavior
    // exactly: provider=giphy, mode=user (everyone uses their own key). On a corrupt
    // file the keys stay blank (server-key proxying disabled) — no silent re-enable.
    let (gif_provider, gif_mode, giphy_server_key, tenor_server_key) = {
        let v = admin_settings_val.as_ref();
        let provider = v.and_then(|v| v.get("gif_provider")).and_then(|x| x.as_str()).unwrap_or("giphy").to_string();
        let mode = v.and_then(|v| v.get("gif_mode")).and_then(|x| x.as_str()).unwrap_or("user").to_string();
        let gk = v.and_then(|v| v.get("giphy_server_key")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let tk = v.and_then(|v| v.get("tenor_server_key")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        (provider, mode, gk, tk)
    };
    // Email-required + signup-captcha policy (admin-controlled). Defaults: email OPTIONAL
    // (email_required=false) and captcha ON. On a CORRUPT file, fail CLOSED — require
    // email and keep captcha on — rather than reverting to the permissive default.
    let (email_required, captcha_enabled) = if admin_settings_corrupt {
        (true, true)
    } else {
        let v = admin_settings_val.as_ref();
        let er = v.and_then(|v| v.get("email_required")).and_then(|x| x.as_bool()).unwrap_or(false);
        let ce = v.and_then(|v| v.get("captcha_enabled")).and_then(|x| x.as_bool()).unwrap_or(true);
        (er, ce)
    };
    // Avatars (admin switch, default ON). A present-but-unparseable settings file fails
    // closed (off), like the sign-up policy above.
    let avatars_enabled = !admin_settings_corrupt && admin_settings_val.as_ref()
        .and_then(|v| v.get("avatars_enabled")).and_then(|x| x.as_bool()).unwrap_or(true);
    // Last.fm now-playing (admin-controlled). Default OFF; shared API key blank.
    let (lastfm_enabled, lastfm_api_key) = {
        let v = admin_settings_val.as_ref();
        let en = v.and_then(|v| v.get("lastfm_enabled")).and_then(|x| x.as_bool()).unwrap_or(false);
        let key = v.and_then(|v| v.get("lastfm_api_key")).and_then(|x| x.as_str()).unwrap_or("").to_string();
        (en, key)
    };
    // #99: harden the shared upstream client used for Giphy/Tenor proxying. Disable
    // redirect-following (a 3xx Location could carry the ?key= secret to an attacker
    // host or chain to an internal address) and disable system-proxy auto-detection.
    // Response bodies are additionally byte-capped at each call site.
    let gif_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build().unwrap_or_else(|_| reqwest::Client::new());
    // #7: create the data dir and all subtrees with mode 0700 so at-rest secrets
    // (vault salts, Argon2 hashes, VAPID key, client TLS keys, encrypted configs)
    // are not world-readable. On a host shared with other local accounts, the
    // inherited umask (0022) would otherwise leave these 0755/0644.
    create_dir_secure(&data_dir)?;
    create_dir_secure(&upload_dir)?;
    // H1 (2026-11-01): move per-user upload index files out of the served uploads
    // dir before the listener starts (idempotent; see upload::migrate_upload_index).
    upload::migrate_upload_index(&data_dir);
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
    // Remote avatars: existing bans must hold for announces from the first line on.
    let disabled_n = auth.load_disabled_users().await;
    if disabled_n > 0 { info!("{} disabled account(s)", disabled_n); }
    let vapid    = notifications::load_or_generate_vapid(&data_dir)?;
    let notifier = Arc::new(NotificationManager::new(&data_dir, vapid));
    let e2e_store = Arc::new(E2EStore::new(&data_dir));
    if let Err(e) = e2e_store.remove_legacy_trust_mirrors().await {
        warn!("[E2E] could not scan for legacy trust mirrors: {}", e);
    }
    let paste_store = Arc::new(paste::PasteStore::new(&data_dir));
    // #33: one outbound-preview permit pool, shared by generic /preview and the X adapter.
    let preview_sem = Arc::new(Semaphore::new(PREVIEW_MAX_CONCURRENT));
    let preview_service = Arc::new(preview::PreviewService::new(&data_dir, preview_sem.clone()));
    // #45: re-harden pre-existing per-user vault/e2e secret dirs+files to 0700/0600
    // (the create path is already secure; this covers dirs from before the hardening
    // or an upgraded install). Best-effort, startup-once.
    harden_secret_tree(std::path::Path::new(&format!("{}/vaults", data_dir)), 0);
    harden_secret_tree(std::path::Path::new(&format!("{}/e2e", data_dir)), 0);

    let base_path = std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into());
    let bp_trimmed = base_path.trim_end_matches('/');
    let static_index    = Arc::new(include_str!("../static/index.html").replace("/cryptirc", bp_trimmed));
    let static_manifest = Arc::new(include_str!("../static/manifest.json").replace("/cryptirc", bp_trimmed));
    let static_sw       = Arc::new(include_str!("../static/sw.js").replace("/cryptirc", bp_trimmed));
    // Serve the controls with app.js so online and cached copies use the same wiring.
    // It contains /cryptirc asset/WS paths, so it needs the same base-path rewrite.
    let static_app_js   = Arc::new(render_app_js(
        concat!(include_str!("../static/page-controls.js"), "\n", include_str!("../static/reactions.js"), "\n", include_str!("../static/app.js")),
        bp_trimmed,
        option_env!("CRYPTIRC_BUILD").unwrap_or("dev"),
        env!("CARGO_PKG_VERSION"),
    ).replace("__CRYPTIRC_ASSETS__", frontend_id()));   // r10: see frontend_id()

    // Load every user's server-side bot config into memory (read on every channel
    // message, so it can't be a per-message file read). Server-readable → 24/7.
    let bots = Arc::new(bots::load_all(&data_dir).await);
    info!("Loaded bot config for {} user(s)", bots.len());
    let avatars = Arc::new(avatar::AvatarStore::load(&data_dir, avatars_enabled).await);
    let user_events: UserEventMap = Arc::new(DashMap::new());
    let avatar_remote = Arc::new(avatar::remote::RemoteAvatars::new(&data_dir, preview_sem.clone(), user_events.clone(), &base_url));
    // Sharing with other servers needs a public base URL they can reach (else: unavailable).
    avatars.set_public_base(avatar::remote::announce_base(&base_url, avatar_remote.test_loopback()));
    if avatars.public_base().is_none() {
        info!("Avatars: sharing with other CryptIRC servers is unavailable (CRYPTIRC_BASE_URL is not a public https URL)");
    }

    let state = AppState {
        connections:         Arc::new(DashMap::new()),
        conn_owners:         Arc::new(DashMap::new()),
        bots,
        disconnect_requests: Arc::new(DashSet::new()),
        pending_dials:       Arc::new(DashSet::new()),
        connect_tasks:       Arc::new(DashMap::new()),
        ipc_out:             Arc::new(tokio::sync::Mutex::new(None)),
        crypto, certs, logger, auth, notifier, e2e_store, paste_store, preview_service,
        user_events,
        active_sessions:     Arc::new(DashMap::new()),
        passkeys: Arc::new(passkeys::Service::new(&base_url)),
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
        preview_sem,
        preview_rate: Arc::new(DashMap::new()),
        gif_provider:     Arc::new(tokio::sync::RwLock::new(gif_provider)),
        gif_mode:         Arc::new(tokio::sync::RwLock::new(gif_mode)),
        giphy_server_key: Arc::new(tokio::sync::RwLock::new(giphy_server_key)),
        tenor_server_key: Arc::new(tokio::sync::RwLock::new(tenor_server_key)),
        gif_rate:         Arc::new(DashMap::new()),
        gif_client,
        news_cache:       Arc::new(tokio::sync::Mutex::new(None)),
        avatars,
        avatar_remote,
    };

    // irc-core daemon split: AppState.connections/conn_owners are pure in-memory
    // DashMaps, wiped on every restart — including the ordinary web-code redeploy
    // this whole split exists to stop disrupting. Without this scan, a freshly
    // restarted web process has no way to resolve a conn_id the daemon reports
    // (via Attach's replay burst) back to a username, since that mapping today
    // only ever lived in memory. The file PATH alone
    // ({data_dir}/networks/{username}/{conn_id}.json) encodes ownership — this
    // needs no vault access (only the specific encrypted FIELDS inside each file
    // do), so it's safe to do before anyone has logged in. Bounded, one-time,
    // proportional to total registered users × their networks — not a hot path.
    {
        // v-srv-a NEW-1: deterministic. The old loop inserted every file stem with plain
        // `insert`, so when two accounts' networks/ dirs both held `<id>.json` (a legacy
        // pre-#23 copy, or a planted file) the LAST read_dir entry became the owner — and
        // deleting that account then sent Drop for the other user's live session. Now a
        // conn_id named by more than one account gets NO seeded owner (its real owner
        // re-claims it by Connect or vault unlock); only canonical `<uuid>.json` files
        // count (get_network_config can't read anything else anyway).
        let (configs, _complete) = scan_network_configs(&data_dir).await;
        let mut by_id: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for (user, stem) in configs {
            if validate_uuid(&stem).as_deref() != Some(stem.as_str()) { continue; }
            let owners = by_id.entry(stem).or_default();
            if !owners.contains(&user) { owners.push(user); }
        }
        let mut seeded = 0usize;
        for (conn_id, mut owners) in by_id {
            if owners.len() == 1 {
                state.conn_owners.insert(conn_id, owners.remove(0));
                seeded += 1;
            } else {
                owners.sort();
                warn!("[{}] network config is present under {} accounts ({}) — not assigning an owner at startup; the session is re-claimed by its owner's Connect / vault unlock", conn_id, owners.len(), owners.join(", "));
                // r3 C2-1: logs (logs/<id>/), the client certificate (certs/<id>/) and the
                // daemon session are keyed by the id alone, so they are SHARED by these
                // accounts. Nothing is re-keyed or deleted here; every operation on that
                // shared state re-reads the owners from the disk (network_id_ownership)
                // and is refused or narrowed unless the caller is the id's sole owner.
            }
        }
        info!("Seeded conn_owners for {} network config(s) from disk", seeded);
        // Avatars: per-connection records only for networks their owners still have.
        state.avatars.prune_sessions(&state.conn_owners);
    }

    // Connect to the irc-core daemon (a separate always-on process holding the
    // actual IRC sockets) and keep reconnecting to it for the life of this
    // process. Socket path matches the daemon's own default resolution.
    {
        let sock_path = std::env::var("CRYPTIRC_IPC_SOCK").unwrap_or_else(|_| format!("{}/irc-core.sock", data_dir.trim_end_matches('/')));
        let s = state.clone();
        tokio::spawn(async move { ipc_client::run(sock_path, s).await; });
        tokio::spawn(keepnick::poll(state.clone()));
    }

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
              // Email-required mode only: GC unverified signups that were never verified
              // (7 days old; they already stop blocking their username/email after 24h).
              let reaped = a.reap_stale_unverified(*s.email_required.read().await).await;
              if reaped > 0 { info!("[auth] reaped {} never-verified account(s)", reaped); }
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
              // Reap stale AI conversation-memory keys (bounded creep, see bots.rs).
              bots::prune_ai_history();
              // Reap stale flood-tracker keys + flush stateful bot data (seen tracker
              // is updated in memory on every message; persist it periodically).
              bots::prune_flood_tracker();
              // Reap expired command-cooldown keys and idle per-connection bot send
              // gates (both static maps that otherwise accrete over the process's life).
              bots::prune_cooldowns();
              bots::prune_bot_send_gates();
              // Defensive backstop: reap any `connections` entry left without a
              // `conn_owners` record (an unroutable half-entry). Known leak paths are
              // fixed at the source; this just enforces the invariant hourly.
              s.prune_orphan_conn_maps();
              bots::botdata_flush_all(&s.data_dir).await;
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
        .route("/pets.js",               get(serve_pets_js))
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
        // Avatars (avatar.rs): own avatar (body = the raw image, read after the session
        // check), discovery lookups, the pictures, and the admin remove.
        .route("/api/avatar/me",         get(avatar::route_me_get).post(avatar::route_me_upload)
                                         .put(avatar::route_me_settings).delete(avatar::route_me_delete)
                                         .layer(DefaultBodyLimit::max(avatar::MAX_UPLOAD_BYTES)))
        .route("/api/avatar/lookup",     post(avatar::route_lookup).layer(DefaultBodyLimit::max(avatar::LOOKUP_BODY_MAX)))
        .route("/avatar/:token",         get(avatar::route_image))
        // Remote avatars: an owner's public picture for other servers, and pictures fetched
        // from other servers for this instance's sessions.
        .route("/avatar/pub/:file",      get(avatar::route_public_image))
        .route("/avatar/remote/:rid",    get(avatar::remote::route_remote_image))
        .route("/admin/user/:username/avatar", axum::routing::delete(avatar::route_admin_remove))
        .route("/admin/users",           get(route_admin_users))
        .route("/admin/status",          get(route_admin_status))
        .route("/admin/user/:username",  axum::routing::delete(route_admin_delete_user))
        .route("/admin/user/:username/disable", post(route_admin_disable_user))
        .route("/admin/user/:username/approve", post(route_admin_approve_user))
        .route("/admin/user/:username/email", post(route_admin_set_email).layer(DefaultBodyLimit::max(8_192)))
        .route("/admin/user/:username/upload-permission", post(route_admin_toggle_upload))
        .route("/admin/settings",        get(route_admin_get_settings).put(route_admin_put_settings))
        .route("/admin/adduser",         post(route_admin_add_user).layer(DefaultBodyLimit::max(4_096)))
        .route("/auth/login",            post(route_login).layer(DefaultBodyLimit::max(8_192)))
        .merge(passkeys::routes())
        .merge(mcp::routes())
        .route("/auth/logout",           post(route_logout))
        .route("/auth/verify",           get(route_verify))
        .route("/auth/forgot",           post(route_forgot).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/reset",            get(route_reset_page))
        .route("/auth/reset",            post(route_reset_password).layer(DefaultBodyLimit::max(8_192)))
        .route("/auth/me",               get(route_me))
        .route("/auth/change-password",  post(route_change_password).layer(DefaultBodyLimit::max(8_192)))
        .route("/upload",                post(route_upload).layer(DefaultBodyLimit::max(legacy_upload_limit)))
        .route("/upload/init",           post(route_upload_init).layer(DefaultBodyLimit::max(4_096)))
        // #33/#4: no DefaultBodyLimit here — route_upload_chunk extracts the raw Body
        // and caps it via to_bytes() against max_upload_mb, gated by a semaphore. This
        // supersedes finding #4's 64->2 MiB DefaultBodyLimit lowering: a Body extractor
        // ignores DefaultBodyLimit entirely and the real per-request cap now lives in
        // to_bytes(), while the semaphore bounds aggregate resident chunk memory.
        .route("/upload/chunk/:id",      post(route_upload_chunk))
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
        .route("/paste/:id/raw",        get(route_paste_raw).post(route_paste_raw_post))
        .route("/paste/:id/app",        get(route_paste_app).post(route_paste_app_post))
        .route("/s",                    post(route_short_create).layer(DefaultBodyLimit::max(4_096)))
        .route("/s/:id",                get(route_short_redirect))
        .route("/api/translation",      post(translation::translate).layer(DefaultBodyLimit::max(16_384)))
        .route("/preview",              get(route_link_preview))
        .route("/tweet/config",         get(route_tweet_config))
        .route("/tweet/preview",        get(route_tweet_preview))
        .route("/tweet/thread",         get(route_tweet_thread))
        .route("/tweet/media",          get(route_tweet_media))
        .route("/tweet/media/sign",     post(route_tweet_media_sign).layer(DefaultBodyLimit::max(8_192)))
        .route("/admin/link-preview",   get(route_admin_get_preview_settings).put(route_admin_put_preview_settings))
        .route("/api/gif/config",       get(route_gif_config))
        .route("/api/news",             get(route_news))
        .route("/api/gif/search",       get(route_gif_search))
        .route("/push/vapid-public-key", get(route_push_vapid_key))
        .route("/push/subscribe",        post(route_push_subscribe).layer(DefaultBodyLimit::max(4_096)))
        .route("/push/subscribe",        axum::routing::delete(route_push_unsubscribe).layer(DefaultBodyLimit::max(2_048)))
        .route("/push/settings",         get(route_push_get_settings))
        .route("/push/settings",         axum::routing::put(route_push_put_settings).layer(DefaultBodyLimit::max(262_144)))
        .route("/push/test",             post(route_push_test))
        // E2E public key bundle (unauthenticated — public keys are public)
        .route("/e2e/bundle/:username",  get(route_e2e_get_bundle))
        .route("/ws",                    get(ws_handler));

    let bp = &state.base_path;
    let app = if bp.is_empty() || bp == "/" {
        // Base path is root — no nesting needed
        inner
            .layer(middleware::from_fn(security_headers_mw))
            .layer(middleware::from_fn(client_ip_mw))
            .with_state(state)
    } else {
        Router::new()
            .nest(bp, inner)
            .route(&format!("{}/", bp), get(serve_index))
            .layer(middleware::from_fn(security_headers_mw))
            .layer(middleware::from_fn(client_ip_mw))
            .with_state(state)
    };

    let port: u16 = std::env::var("CRYPTIRC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(9001);
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("CryptIRC v{} listening on http://{}", env!("CARGO_PKG_VERSION"), addr);
    // ConnectInfo gives client_ip_mw the real TCP peer, so forwarding headers are only
    // believed when they come from a trusted proxy (#12).
    axum::serve(tokio::net::TcpListener::bind(addr).await?, app.into_make_service_with_connect_info::<SocketAddr>()).await?;
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
    let nonce = PageScriptNonce::new();
    let html = state.static_index.replace("__CRYPTIRC_SCRIPT_NONCE__", &nonce.0);
    (axum::Extension(nonce), [(header::CACHE_CONTROL, NO_CACHE)], Html(html))
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
// The five above are one standalone script per pet. Everything added after them
// shares ONE engine in pets.js (see that file's header for why), so this single
// route covers all of them however many there are.
async fn serve_pets_js()   -> impl IntoResponse { ([(header::CONTENT_TYPE,"application/javascript; charset=utf-8"),(header::CACHE_CONTROL,NO_CACHE)], include_str!("../static/pets.js")) }

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
        // The Lounge's notification sound (WAV), bundled as CryptIRC's default.
        "lounge.wav"        => Some(include_bytes!("../static/sounds/lounge.wav")),
        _ => None,
    };
    let ct = if name.ends_with(".wav") { "audio/wav" } else { "audio/mpeg" };
    match bytes {
        Some(b) => ([(header::CONTENT_TYPE, ct), (header::CACHE_CONTROL, "public, max-age=604800")], b).into_response(),
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

async fn serve_file_public(Path(name): Path<String>, headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    if name.contains("..") || name.starts_with('.') { return StatusCode::BAD_REQUEST.into_response(); }
    // The unauthenticated /pub route serves EVERY upload by its unguessable-UUID filename —
    // an "anyone with the link" share model (like Slack/Discord CDN links, owner's choice
    // since v0.4.0 / 343fc82) so a copied link loads for anyone, in-app or not; that
    // includes documents/archives/text, which go out as attachments. XSS-safe:
    // content_type_for is an ALLOWLIST — only image/video/audio/pdf/text get a real inline
    // type; anything unknown (.html/.svg/.js/…) falls through to application/octet-stream,
    // which with X-Content-Type-Options:nosniff the browser DOWNLOADS instead of executing
    // in our origin. Media + PDF preview inline; everything else is sent as an attachment.
    // H1: internal names (per-user upload index, temps, _inprogress) are never served.
    if upload::is_reserved_upload_name(&name) { return StatusCode::NOT_FOUND.into_response(); }
    let path = std::path::PathBuf::from(&state.upload_dir).join(&name);
    let inline = upload::is_public_media(&name) || name.to_lowercase().ends_with(".pdf");
    stream_upload_file(&path, &name, &headers, "public, max-age=86400", inline).await
}

async fn serve_file(Path(name): Path<String>, headers: HeaderMap, State(state): State<AppState>) -> impl IntoResponse {
    let token = headers.get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(';').find_map(|c| {
                let c = c.trim();
                c.strip_prefix("cryptirc_token=").map(|t| t.to_string())
            }))
        .or_else(|| bearer_token(&headers).map(|s| s.to_string()))
        .unwrap_or_default();
    if state.auth.validate_session(&token).is_none() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let name: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.').collect();
    if name.contains("..") || name.starts_with('.') { return StatusCode::BAD_REQUEST.into_response(); }
    // H1: never hand out another user's upload index (or temps / _inprogress).
    if upload::is_reserved_upload_name(&name) { return StatusCode::NOT_FOUND.into_response(); }
    let path = std::path::PathBuf::from(&state.upload_dir).join(&name);
    stream_upload_file(&path, &name, &headers, "private, max-age=86400", upload::is_image(&name)).await
}

// ─── Streamed upload serving (rust-http #2) ─────────────────────────────────
// /pub and /files used to tokio::fs::read() the whole file (up to max_upload_mb)
// into RAM per request, with no connection limit, so a few slow readers could pin
// GBs of RSS. They now stream from an open file in FILE_SERVE_CHUNK pieces with
// single-range `Range:` support (seekable video, Safari playback), and every
// in-flight response holds a global + per-client-IP slot until its body finishes
// or the client goes away. Waiting for a slot QUEUES (up to FILE_SERVE_QUEUE_WAIT)
// instead of failing at once, so a chat page that fires dozens of image requests
// in a burst just loads them slightly staggered; only sustained saturation 503s.

/// Global cap on concurrently-streaming /pub + /files responses (fds / tasks).
const FILE_SERVE_MAX_CONCURRENT: usize = 256;
/// Per real-client-IP cap (X-Real-IP / XFF via client_ip). Requests without a
/// proxy IP header only count against the global cap.
const FILE_SERVE_MAX_PER_IP: usize = 32;
/// How long a request may queue for a slot before it gets 503 + Retry-After.
const FILE_SERVE_QUEUE_WAIT: std::time::Duration = std::time::Duration::from_secs(15);
/// Read size per body chunk (bounded RAM per in-flight response).
const FILE_SERVE_CHUNK: usize = 64 * 1024;

fn file_serve_sem() -> &'static Arc<Semaphore> {
    static SEM: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    SEM.get_or_init(|| Arc::new(Semaphore::new(FILE_SERVE_MAX_CONCURRENT)))
}
fn file_serve_ip_sems() -> &'static DashMap<String, Arc<Semaphore>> {
    static M: std::sync::OnceLock<DashMap<String, Arc<Semaphore>>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// Held by a streaming file body; releases both slots when the body is dropped
/// (fully sent, errored, or the client disconnected) and reaps the idle per-IP
/// semaphore so the map can't grow without bound.
struct FileServeGuard {
    _global: tokio::sync::OwnedSemaphorePermit,
    ip: Option<(String, tokio::sync::OwnedSemaphorePermit)>,
}
impl Drop for FileServeGuard {
    fn drop(&mut self) {
        if let Some((ip, permit)) = self.ip.take() {
            drop(permit);
            // count==1 ⇒ only the map holds it: no live permit and no waiter (a
            // waiter holds its own clone). DashMap's shard lock serializes this
            // against the entry().or_insert().clone() in acquire_file_serve_slot.
            reap_file_serve_ip(&ip);
        }
    }
}

fn reap_file_serve_ip(ip: &str) {
    file_serve_ip_sems().remove_if(ip, |_, s| Arc::strong_count(s) == 1);
}

async fn acquire_file_serve_slot(headers: &HeaderMap) -> Option<FileServeGuard> {
    let ip_part = match client_ip(headers) {
        Some(ip) => {
            let sem = file_serve_ip_sems()
                .entry(ip.clone())
                .or_insert_with(|| Arc::new(Semaphore::new(FILE_SERVE_MAX_PER_IP)))
                .clone();
            let got = tokio::time::timeout(FILE_SERVE_QUEUE_WAIT, sem.acquire_owned()).await;
            match got {
                Ok(Ok(p)) => Some((ip, p)),
                _ => { reap_file_serve_ip(&ip); return None; }
            }
        }
        None => None,
    };
    match tokio::time::timeout(FILE_SERVE_QUEUE_WAIT, file_serve_sem().clone().acquire_owned()).await {
        Ok(Ok(global)) => Some(FileServeGuard { _global: global, ip: ip_part }),
        _ => {
            if let Some((ip, p)) = ip_part { drop(p); reap_file_serve_ip(&ip); }
            None
        }
    }
}

/// Outcome of parsing a `Range:` header against a file of `len` bytes.
#[derive(Debug, PartialEq)]
enum ByteRange {
    /// No (usable) Range header — send the whole file with 200.
    Full,
    /// Inclusive start..=end — send 206.
    Partial(u64, u64),
    /// Syntactically valid but unsatisfiable — send 416.
    Unsatisfiable,
}

/// Single-range `bytes=` parser (RFC 9110 §14). Multi-range, other units and
/// malformed values are ignored (→ Full), which the RFC permits.
fn parse_byte_range(value: Option<&str>, len: u64) -> ByteRange {
    let v = match value { Some(v) => v.trim(), None => return ByteRange::Full };
    let spec = match v.strip_prefix("bytes=") { Some(s) => s.trim(), None => return ByteRange::Full };
    if spec.contains(',') { return ByteRange::Full; }
    let (a, b) = match spec.split_once('-') { Some(p) => (p.0.trim(), p.1.trim()), None => return ByteRange::Full };
    let num = |s: &str| if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) { s.parse::<u64>().ok() } else { None };
    if a.is_empty() {
        // Suffix range: the last N bytes.
        let n = match num(b) { Some(n) => n, None => return ByteRange::Full };
        if n == 0 || len == 0 { return ByteRange::Unsatisfiable; }
        let n = n.min(len);
        return ByteRange::Partial(len - n, len - 1);
    }
    let start = match num(a) { Some(n) => n, None => return ByteRange::Full };
    let end = if b.is_empty() { None } else { match num(b) { Some(n) => Some(n), None => return ByteRange::Full } };
    if let Some(e) = end { if e < start { return ByteRange::Full; } }
    if start >= len { return ByteRange::Unsatisfiable; }
    let end = end.map_or(len - 1, |e| e.min(len - 1));
    ByteRange::Partial(start, end)
}

/// Stream one file from the uploads dir with the shared /pub + /files headers.
/// `name` is the already-sanitized, non-reserved file name (drives content type).
async fn stream_upload_file(path: &std::path::Path, name: &str, headers: &HeaderMap, cache: &'static str, inline: bool) -> axum::response::Response {
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    // codex P1 main.rs:1772: take the global + per-IP slot BEFORE opening the file. The
    // file used to be opened first, so every request queued behind a full slot pool held
    // an open descriptor for up to FILE_SERVE_QUEUE_WAIT — the caps bounded streaming
    // bodies but not open files. Now a queued request holds no file descriptor at all.
    let guard = match acquire_file_serve_slot(headers).await {
        Some(g) => g,
        None => return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")], "Busy — retry shortly").into_response(),
    };
    let mut file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    // A directory opens fine on Linux; only regular files are servable.
    let len = match file.metadata().await {
        Ok(m) if m.is_file() => m.len(),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    // RFC 9110 If-Range: we emit no validators, so any If-Range can't match →
    // ignore Range and send the full representation.
    let range_hdr = if headers.contains_key(header::IF_RANGE) { None }
        else { headers.get(header::RANGE).and_then(|v| v.to_str().ok()) };
    let range = parse_byte_range(range_hdr, len);
    let base = |b: axum::http::response::Builder| b
        .header(header::CONTENT_TYPE, upload::content_type_for(name))
        .header(header::CACHE_CONTROL, cache)
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(HeaderName::from_static("content-disposition"), if inline { "inline" } else { "attachment" })
        .header(header::ACCEPT_RANGES, "bytes");
    if range == ByteRange::Unsatisfiable {
        return base(Response::builder().status(StatusCode::RANGE_NOT_SATISFIABLE))
            .header(header::CONTENT_RANGE, format!("bytes */{}", len))
            .body(Body::empty())
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }
    let (status, start, count) = match range {
        ByteRange::Partial(s, e) => (StatusCode::PARTIAL_CONTENT, s, e - s + 1),
        _ => (StatusCode::OK, 0, len),
    };
    if start > 0 && file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let reader = file.take(count);
    let stream = futures_util::stream::unfold(Some((reader, guard)), |st| async move {
        let (mut r, g) = st?;
        let mut buf = vec![0u8; FILE_SERVE_CHUNK];
        match r.read(&mut buf).await {
            Ok(0) => None,
            Ok(n) => { buf.truncate(n); Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(buf)), Some((r, g)))) }
            Err(e) => Some((Err(e), None)),
        }
    });
    let mut b = base(Response::builder().status(status)).header(header::CONTENT_LENGTH, count);
    if status == StatusCode::PARTIAL_CONTENT {
        b = b.header(header::CONTENT_RANGE, format!("bytes {}-{}/{}", start, start + count - 1, len));
    }
    b.body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

#[cfg(test)]
mod file_serve_tests {
    use super::*;

    #[test]
    fn range_parsing() {
        assert_eq!(parse_byte_range(None, 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("bytes=0-"), 100), ByteRange::Partial(0, 99));
        assert_eq!(parse_byte_range(Some("bytes=10-19"), 100), ByteRange::Partial(10, 19));
        assert_eq!(parse_byte_range(Some("bytes=90-500"), 100), ByteRange::Partial(90, 99));
        assert_eq!(parse_byte_range(Some("bytes=-10"), 100), ByteRange::Partial(90, 99));
        assert_eq!(parse_byte_range(Some("bytes=-1000"), 100), ByteRange::Partial(0, 99));
        assert_eq!(parse_byte_range(Some("bytes=100-"), 100), ByteRange::Unsatisfiable);
        assert_eq!(parse_byte_range(Some("bytes=-0"), 100), ByteRange::Unsatisfiable);
        assert_eq!(parse_byte_range(Some("bytes=0-"), 0), ByteRange::Unsatisfiable);
        // Ignored → full body.
        assert_eq!(parse_byte_range(Some("bytes=0-1,5-6"), 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("items=0-1"), 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("bytes=5-1"), 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("bytes=a-b"), 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("bytes=+1-2"), 100), ByteRange::Full);
        assert_eq!(parse_byte_range(Some("bytes=99999999999999999999999-"), 100), ByteRange::Full);
    }
}

// ─── Auth routes ──────────────────────────────────────────────────────────────

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .and_then(validate_uuid)
}

/// Internal request header that carries the rate-limit client key computed by
/// `client_ip_mw`. The middleware strips any client-sent copy before setting it, so a
/// request can never choose its own key through this header.
const CLIENT_KEY_HEADER: &str = "x-cryptirc-client-key";

/// #15: the client's rate-limit key, as computed by `client_ip_mw` (TCP peer + trusted
/// proxy headers, IPv6 grouped per /64). Returns None if no client address could be
/// determined (e.g. a direct-to-:9001 request with no proxy headers), in which case the
/// auth limiter falls back to a shared bucket. The value is used only as a rate-limit
/// dimension — never logged or persisted (see audit #108). Signature unchanged so every
/// existing caller (auth routes, paste routes, the WS per-IP cap) gets the same key.
fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers.get(CLIENT_KEY_HEADER).and_then(|v| v.to_str().ok()).map(str::to_string)
}

/// Middleware: compute the client rate-limit key ONCE per request from the real TCP
/// peer (ConnectInfo) and, only when that peer is a trusted proxy, the forwarding
/// headers; store it in CLIENT_KEY_HEADER for `client_ip` to read.
async fn client_ip_mw(mut req: Request<Body>, next: Next) -> Response {
    let peer = req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let cfg = client_ip_config();
    let key = resolve_client_key(peer, req.headers(), cfg);
    if cfg.header != RealIpHeader::Off && peer.map_or(false, |p| is_trusted_proxy(p, cfg)) {
        note_forwarded_identity(req.headers(), key.as_deref(), cfg);
    }
    let h = req.headers_mut();
    h.remove(CLIENT_KEY_HEADER);
    if let Some(v) = key.and_then(|k| HeaderValue::from_str(&k).ok()) {
        h.insert(HeaderName::from_static(CLIENT_KEY_HEADER), v);
    }
    next.run(req).await
}

/// Which forwarding header(s) to believe from a trusted proxy (CRYPTIRC_REAL_IP_HEADER).
#[derive(Clone, Copy, Debug, PartialEq)]
enum RealIpHeader { Auto, XForwardedFor, XRealIp, Off }

struct ClientIpConfig {
    /// Extra trusted proxy addresses/CIDRs (CRYPTIRC_TRUSTED_PROXIES); loopback is
    /// always trusted because the server only listens on 127.0.0.1.
    trusted: Vec<(std::net::IpAddr, u8)>,
    header: RealIpHeader,
}

fn client_ip_config() -> &'static ClientIpConfig {
    static CFG: std::sync::OnceLock<ClientIpConfig> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let trusted_env = std::env::var("CRYPTIRC_TRUSTED_PROXIES").unwrap_or_default();
        let header_env = std::env::var("CRYPTIRC_REAL_IP_HEADER").unwrap_or_default();
        let cfg = parse_client_ip_config(&trusted_env, &header_env);
        if !trusted_env.trim().is_empty() || !header_env.trim().is_empty() {
            info!("client IP: {} extra trusted proxy range(s), header mode {:?}", cfg.trusted.len(), cfg.header);
        }
        cfg
    })
}

fn parse_client_ip_config(trusted: &str, header: &str) -> ClientIpConfig {
    let mut list = Vec::new();
    for tok in trusted.split(|c: char| c == ',' || c.is_whitespace()).filter(|t| !t.is_empty()) {
        let (addr, bits) = match tok.split_once('/') {
            Some((a, b)) => (a, b.parse::<u8>().ok()),
            None => (tok, None),
        };
        match addr.parse::<std::net::IpAddr>() {
            Ok(ip) => {
                let max = if ip.is_ipv4() { 32 } else { 128 };
                list.push((ip, bits.unwrap_or(max).min(max)));
            }
            Err(_) => warn!("CRYPTIRC_TRUSTED_PROXIES: ignoring unparseable entry {:?}", tok),
        }
    }
    let header = match header.trim().to_ascii_lowercase().as_str() {
        "x-forwarded-for" | "xff" => RealIpHeader::XForwardedFor,
        "x-real-ip" => RealIpHeader::XRealIp,
        "off" | "none" => RealIpHeader::Off,
        _ => RealIpHeader::Auto,
    };
    ClientIpConfig { trusted: list, header }
}

/// IPv4-mapped IPv6 (::ffff:a.b.c.d) → plain IPv4, so a dual-stack proxy can't make
/// every IPv4 client share one ::ffff:0:0/64 bucket.
fn canonical_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

fn ip_in_cidr(ip: std::net::IpAddr, net: std::net::IpAddr, bits: u8) -> bool {
    match (canonical_ip(ip), canonical_ip(net)) {
        (std::net::IpAddr::V4(a), std::net::IpAddr::V4(n)) => {
            let bits = bits.min(32) as u32;
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(n) & mask)
        }
        (std::net::IpAddr::V6(a), std::net::IpAddr::V6(n)) => {
            let bits = bits.min(128) as u32;
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

fn is_trusted_proxy(ip: std::net::IpAddr, cfg: &ClientIpConfig) -> bool {
    canonical_ip(ip).is_loopback() || cfg.trusted.iter().any(|(n, b)| ip_in_cidr(ip, *n, *b))
}

/// Parse one forwarding-header entry: a bare IP, or `ip:port` / `[v6]:port` (some
/// proxies include the port). Anything else is rejected (#114: no garbage keys).
fn parse_forwarded_ip(s: &str) -> Option<std::net::IpAddr> {
    let s = s.trim();
    s.parse::<std::net::IpAddr>().ok()
        .or_else(|| s.parse::<SocketAddr>().ok().map(|sa| sa.ip()))
        .map(canonical_ip)
}

/// #4: the rate-limit bucket for an address. IPv4 is keyed per address (unchanged);
/// IPv6 per /64 — one host/LAN normally owns a whole /64, so per-address keys let a
/// single machine rotate through 2^64 fresh buckets and bypass every per-IP limiter.
fn client_bucket_key(ip: std::net::IpAddr) -> String {
    match canonical_ip(ip) {
        std::net::IpAddr::V4(v4) => v4.to_string(),
        std::net::IpAddr::V6(v6) => {
            let net = u128::from(v6) & (u128::MAX << 64);
            format!("{}/64", std::net::Ipv6Addr::from(net))
        }
    }
}

/// #12: decide the client address. Forwarding headers are believed ONLY when the TCP
/// peer is a trusted proxy (loopback — prod nginx and the installers' Caddy both connect
/// from 127.0.0.1 — or CRYPTIRC_TRUSTED_PROXIES); any other peer is keyed by its own
/// address. From a trusted proxy, the default "auto" mode has to be safe for BOTH kinds
/// of proxy: an nginx with only `proxy_set_header X-Real-IP $remote_addr` passes the
/// client's own X-Forwarded-For through (XFF forgeable), while Caddy without `header_up
/// X-Real-IP`, HAProxy and Apache append XFF but pass X-Real-IP through (X-Real-IP
/// forgeable). So: R = X-Real-IP unless it is itself a trusted-proxy address (CDN ->
/// nginx chains put the CDN edge there); F = X-Forwarded-For walked right-to-left past
/// trusted hops (proxies APPEND what they saw). One of them → use it; both naming the
/// same bucket → use it; both untrusted and DIFFERENT → one is client-forged, so neither
/// is believed: the request goes to the single shared AMBIGUOUS_FWD_KEY bucket (a forger
/// can't escape into fresh buckets, and every shipped config — Frozen's nginx, the
/// installers' Caddy — sets both headers to the same address, so it never happens there)
/// and a rate-limited warning tells the operator to pin CRYPTIRC_REAL_IP_HEADER.
/// `peer == None` (no ConnectInfo; never happens under `main`) keeps the legacy
/// header-only behaviour.
fn resolve_client_key(peer: Option<std::net::IpAddr>, headers: &HeaderMap, cfg: &ClientIpConfig) -> Option<String> {
    if let Some(p) = peer {
        if !is_trusted_proxy(p, cfg) { return Some(client_bucket_key(p)); }
    }
    let xff_walk = || -> Option<std::net::IpAddr> {
        // All XFF lines joined in order; the right-most entry is the nearest hop.
        let joined: Vec<&str> = headers.get_all("x-forwarded-for").iter()
            .filter_map(|v| v.to_str().ok()).collect();
        let joined = joined.join(",");
        let mut fallback = None;
        for entry in joined.rsplit(',') {
            // An unparseable hop ends the walk: never skip past it into client-written
            // entries. Whatever trusted hop we already passed is the best answer.
            let Some(ip) = parse_forwarded_ip(entry) else { break };
            if !is_trusted_proxy(ip, cfg) { return Some(ip); }
            fallback = Some(ip);
        }
        fallback
    };
    let xrip = || headers.get("x-real-ip").and_then(|v| v.to_str().ok()).and_then(parse_forwarded_ip);
    let ip = match cfg.header {
        // "off": never believe forwarding headers — key on the TCP peer itself.
        RealIpHeader::Off => peer.map(canonical_ip),
        RealIpHeader::XForwardedFor => xff_walk(),
        RealIpHeader::XRealIp => xrip(),
        RealIpHeader::Auto => {
            let r_raw = xrip();
            let f_raw = xff_walk();
            let r = r_raw.filter(|ip| !is_trusted_proxy(*ip, cfg));
            let f = f_raw.filter(|ip| !is_trusted_proxy(*ip, cfg));
            match (r, f) {
                (Some(a), Some(b)) if client_bucket_key(a) != client_bucket_key(b) => {
                    warn_forwarding_headers_disagree(a, b);
                    return Some(AMBIGUOUS_FWD_KEY.to_string());
                }
                (Some(a), _) => Some(a),
                (None, Some(b)) => Some(b),
                // Only trusted addresses anywhere (e.g. a local client through the proxy).
                (None, None) => f_raw.or(r_raw),
            }
        }
    };
    ip.map(client_bucket_key)
}

/// Shared rate-limit bucket for requests whose X-Real-IP and X-Forwarded-For name
/// different untrusted clients (one of them is forged; see resolve_client_key).
const AMBIGUOUS_FWD_KEY: &str = "ambiguous-fwd";

/// NEW-6 (verify v-srv-a): behind a CDN / load balancer that is NOT listed in
/// CRYPTIRC_TRUSTED_PROXIES, every request reaches us with the edge's address in both
/// X-Real-IP and X-Forwarded-For, so every user silently shares ONE rate-limit bucket
/// (one attacker's lockout hits everybody). That looks exactly like a single-user server,
/// so the tell-tale is used instead: all proxied requests in a window resolve to one
/// client key while the requests carry several DIFFERENT upstream client addresses
/// (X-Forwarded-For entries left of the one we chose, or a CDN's client header). Then a
/// warning is logged (at most once per hour) naming the settings to fix. Only hashes of
/// the addresses are kept, and no address is logged (#108).
const FWD_STATS_WINDOW_SECS: u64 = 600;
const FWD_STATS_MIN_REQUESTS: u64 = 50;
struct FwdStats { window_start: u64, requests: u64, key: Option<u64>, multi_key: bool, upstream: Vec<u64> }
fn fwd_stats() -> &'static std::sync::Mutex<FwdStats> {
    static S: std::sync::OnceLock<std::sync::Mutex<FwdStats>> = std::sync::OnceLock::new();
    S.get_or_init(|| std::sync::Mutex::new(FwdStats { window_start: 0, requests: 0, key: None, multi_key: false, upstream: Vec::new() }))
}
fn fwd_hash(s: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}
/// Upstream client identities a proxied request carries besides the key we resolved:
/// X-Forwarded-For entries in a different bucket than `key`, and the client headers
/// CDNs add (Cloudflare, Akamai/Cloudflare Enterprise, Fastly).
fn fwd_upstream_ids(headers: &HeaderMap, key: &str, cfg: &ClientIpConfig) -> Vec<u64> {
    let mut out = Vec::new();
    for v in headers.get_all("x-forwarded-for").iter().filter_map(|v| v.to_str().ok()) {
        for e in v.split(',') {
            if let Some(ip) = parse_forwarded_ip(e) {
                if !is_trusted_proxy(ip, cfg) {
                    let k = client_bucket_key(ip);
                    if k != key { out.push(fwd_hash(&k)); }
                }
            }
        }
    }
    for h in ["cf-connecting-ip", "true-client-ip", "fastly-client-ip"] {
        if let Some(ip) = headers.get(h).and_then(|v| v.to_str().ok()).and_then(parse_forwarded_ip) {
            let k = client_bucket_key(ip);
            if k != key { out.push(fwd_hash(&k)); }
        }
    }
    out
}
fn note_forwarded_identity(headers: &HeaderMap, key: Option<&str>, cfg: &ClientIpConfig) {
    let Some(key) = key else { return };
    let ups = fwd_upstream_ids(headers, key, cfg);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let kh = fwd_hash(key);
    let warn_now = {
        let Ok(mut st) = fwd_stats().lock() else { return };
        fwd_stats_observe(&mut st, now, kh, ups)
    };
    if warn_now { warn_single_forwarded_identity(now); }
}
/// Record one proxied request; returns true when the window that just closed looked like
/// an untrusted CDN/load balancer (see FWD_STATS_WINDOW_SECS).
fn fwd_stats_observe(st: &mut FwdStats, now: u64, key_hash: u64, ups: Vec<u64>) -> bool {
    let mut suspicious = false;
    if st.window_start == 0 { st.window_start = now; }
    if now.saturating_sub(st.window_start) >= FWD_STATS_WINDOW_SECS {
        suspicious = st.requests >= FWD_STATS_MIN_REQUESTS && !st.multi_key && st.upstream.len() >= 2;
        *st = FwdStats { window_start: now, requests: 0, key: None, multi_key: false, upstream: Vec::new() };
    }
    st.requests += 1;
    match st.key {
        None => st.key = Some(key_hash),
        Some(k) if k != key_hash => st.multi_key = true,
        _ => {}
    }
    for u in ups {
        if st.upstream.len() >= 3 { break; }
        if !st.upstream.contains(&u) { st.upstream.push(u); }
    }
    suspicious
}
fn warn_single_forwarded_identity(now: u64) {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let last = LAST.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < 3600 { return; }
    if LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() { return; }
    warn!("client IP: for the last {} minutes EVERY request resolved to the same client address, although the \
           requests carried several different upstream client addresses (X-Forwarded-For / CDN client header). \
           CryptIRC is probably behind a CDN or load balancer that is not trusted, so all users share ONE \
           rate-limit and per-IP bucket. List that proxy's address ranges in CRYPTIRC_TRUSTED_PROXIES \
           (comma-separated IPs/CIDRs; ONLY the proxy's own ranges, never your users' networks), and set \
           CRYPTIRC_REAL_IP_HEADER if needed (auto | x-forwarded-for | x-real-ip | off). (logged at most once per hour)",
          FWD_STATS_WINDOW_SECS / 60);
}

/// At most one warning per hour that X-Real-IP and X-Forwarded-For disagree (header
/// values only at debug level — they are client data and #108 keeps client IPs out of
/// the normal logs).
fn warn_forwarding_headers_disagree(real: std::net::IpAddr, xff_client: std::net::IpAddr) {
    static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    tracing::debug!("client IP: X-Real-IP={} but X-Forwarded-For client={} -> bucket {}", real, xff_client, AMBIGUOUS_FWD_KEY);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let last = LAST.load(Ordering::Relaxed);
    if last != 0 && now.saturating_sub(last) < 3600 { return; }
    if LAST.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed).is_err() { return; }
    warn!("client IP: the reverse proxy sent X-Real-IP and X-Forwarded-For naming DIFFERENT clients, so one of them \
           is client-controlled; such requests share ONE rate-limit bucket (\"{}\"). Tell CryptIRC which header your \
           proxy sets: CRYPTIRC_REAL_IP_HEADER=x-forwarded-for if it does not set X-Real-IP itself (Caddy without \
           `header_up X-Real-IP`, HAProxy, Apache), or CRYPTIRC_REAL_IP_HEADER=x-real-ip if it sets X-Real-IP but \
           passes the client's X-Forwarded-For through (nginx without a proxy_set_header X-Forwarded-For line). \
           (logged at most once per hour)", AMBIGUOUS_FWD_KEY);
}

#[cfg(test)]
mod client_ip_tests {
    use super::*;
    use std::net::IpAddr;

    fn hdrs(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(HeaderName::from_bytes(k.as_bytes()).unwrap(), HeaderValue::from_str(v).unwrap());
        }
        h
    }
    fn ip(s: &str) -> Option<IpAddr> { Some(s.parse().unwrap()) }
    fn cfg() -> ClientIpConfig { parse_client_ip_config("", "") }

    /// verify v-srv-a NEW-6: an unconfigured CDN in front of nginx looks like one client
    /// whose requests carry many different upstream addresses → warn; a single-user server,
    /// a normal multi-client server, or too little traffic → no warning.
    #[test]
    fn untrusted_cdn_is_detected_but_single_user_is_not() {
        let fresh = || FwdStats { window_start: 0, requests: 0, key: None, multi_key: false, upstream: Vec::new() };
        let c = cfg();
        // CDN edge 198.51.100.9 in X-Real-IP and as the last XFF hop; varying real clients before it.
        let run = |reqs: &[(String, String)], st: &mut FwdStats| -> bool {
            let mut warned = false;
            for (k, (xrip, xff)) in reqs.iter().enumerate() {
                let h = hdrs(&[("x-real-ip", xrip.as_str()), ("x-forwarded-for", xff.as_str())]);
                let key = resolve_client_key(ip("127.0.0.1"), &h, &c).unwrap();
                let ups = fwd_upstream_ids(&h, &key, &c);
                warned |= fwd_stats_observe(st, 1000 + k as u64, fwd_hash(&key), ups);
            }
            // close the window
            warned |= fwd_stats_observe(st, 1000 + FWD_STATS_WINDOW_SECS + 5000, 1, vec![]);
            warned
        };
        let cdn: Vec<(String, String)> = (0..60).map(|k| ("198.51.100.9".to_string(), format!("203.0.113.{}, 198.51.100.9", k % 7 + 1))).collect();
        assert!(run(&cdn, &mut fresh()), "unconfigured CDN must warn");
        let single: Vec<(String, String)> = (0..60).map(|_| ("203.0.113.5".to_string(), "203.0.113.5".to_string())).collect();
        assert!(!run(&single, &mut fresh()), "one real user must not warn");
        let many: Vec<(String, String)> = (0..60).map(|k| { let a = format!("203.0.113.{}", k % 9 + 1); (a.clone(), a) }).collect();
        assert!(!run(&many, &mut fresh()), "many real clients must not warn");
        assert!(!run(&cdn[..20].to_vec(), &mut fresh()), "too little traffic must not warn");
        // Trusted CDN (CRYPTIRC_TRUSTED_PROXIES covers the edge): keys differ → no warning.
        let c2 = parse_client_ip_config("198.51.100.0/24", "");
        let mut st = fresh(); let mut warned = false;
        for (k, (xrip, xff)) in cdn.iter().enumerate() {
            let h = hdrs(&[("x-real-ip", xrip.as_str()), ("x-forwarded-for", xff.as_str())]);
            let key = resolve_client_key(ip("127.0.0.1"), &h, &c2).unwrap();
            warned |= fwd_stats_observe(&mut st, 1000 + k as u64, fwd_hash(&key), fwd_upstream_ids(&h, &key, &c2));
        }
        warned |= fwd_stats_observe(&mut st, 1000 + FWD_STATS_WINDOW_SECS + 5000, 1, vec![]);
        assert!(!warned);
    }

    #[test]
    fn registration_code_compare() {
        assert!(registration_code_matches("Sesame-42", "Sesame-42"));
        for bad in ["", "sesame-42", "Sesame-4", "Sesame-422", "Sesame-42 ", &"x".repeat(8000)] {
            assert!(!registration_code_matches("Sesame-42", bad), "{:?}", bad);
        }
    }

    #[test]
    fn preview_log_drops_path_and_query() {
        assert_eq!(preview_log_host("https://neverssl.com/secret-path-from-chat?q=private"), "neverssl.com");
        assert_eq!(preview_log_host("https://user:pw@Example.COM:8443/x?y#z"), "example.com");
        assert_eq!(preview_log_host("not a url /secret"), "?");
        let e = anyhow::anyhow!("Domain not in whitelist");
        assert_eq!(preview_error_class(&e), "Domain not in whitelist");
    }

    #[test]
    fn ipv4_key_is_the_address() {
        assert_eq!(client_bucket_key("198.51.100.7".parse().unwrap()), "198.51.100.7");
        // IPv4-mapped IPv6 collapses to the IPv4 address (no shared ::ffff:0:0/64 bucket).
        assert_eq!(client_bucket_key("::ffff:198.51.100.7".parse().unwrap()), "198.51.100.7");
    }

    #[test]
    fn ipv6_key_is_the_slash_64() {
        let a = client_bucket_key("2001:db8:dead:beef::1".parse().unwrap());
        let b = client_bucket_key("2001:db8:dead:beef:ffff:1234:5678:9abc".parse().unwrap());
        let c = client_bucket_key("2001:db8:dead:bef0::1".parse().unwrap());
        assert_eq!(a, "2001:db8:dead:beef::/64");
        assert_eq!(a, b, "same /64 must share one bucket");
        assert_ne!(a, c, "different /64 must not");
    }

    #[test]
    fn loopback_peer_trusts_x_real_ip_and_xff() {
        let c = cfg();
        // prod nginx: X-Real-IP $remote_addr + XFF $proxy_add_x_forwarded_for (agree)
        let h = hdrs(&[("x-real-ip", "203.0.113.9"), ("x-forwarded-for", "6.6.6.6, 203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // installer Caddy: both headers = {remote_host}
        let h = hdrs(&[("x-real-ip", "2001:db8::5"), ("x-forwarded-for", "2001:db8::5")]);
        assert_eq!(resolve_client_key(ip("::1"), &h, &c).as_deref(), Some("2001:db8::/64"));
        // only X-Real-IP / only XFF
        let h = hdrs(&[("x-real-ip", "203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        let h = hdrs(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // no headers from loopback → None (shared "noip" bucket, as before)
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &HeaderMap::new(), &c), None);
    }

    #[test]
    fn untrusted_peer_headers_are_ignored() {
        let c = cfg();
        let h = hdrs(&[("x-real-ip", "1.2.3.4"), ("x-forwarded-for", "1.2.3.4")]);
        assert_eq!(resolve_client_key(ip("198.51.100.20"), &h, &c).as_deref(), Some("198.51.100.20"));
        assert_eq!(resolve_client_key(ip("2001:db8:1:2::77"), &h, &c).as_deref(), Some("2001:db8:1:2::/64"));
    }

    #[test]
    fn auto_mode_disagreeing_headers_share_one_bucket() {
        let c = cfg();
        let amb = Some(AMBIGUOUS_FWD_KEY);
        // nginx with ONLY `proxy_set_header X-Real-IP $remote_addr`: the client's own forged
        // X-Forwarded-For arrives untouched → ambiguous, and rotating it stays in ONE bucket.
        for forged in ["6.6.6.6", "1.2.3.4, 6.6.6.7", "2001:db8:6666::1"] {
            let h = hdrs(&[("x-real-ip", "203.0.113.9"), ("x-forwarded-for", forged)]);
            assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), amb, "{}", forged);
        }
        // Caddy without `header_up X-Real-IP` (sets XFF only) + a client-forged X-Real-IP.
        for forged in ["9.9.9.9", "9.9.9.10", "2001:db8:9999::1"] {
            let h = hdrs(&[("x-real-ip", forged), ("x-forwarded-for", "203.0.113.9")]);
            assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), amb, "{}", forged);
        }
        // A forged header naming a TRUSTED address is simply ignored (no ambiguity).
        let h = hdrs(&[("x-real-ip", "203.0.113.9"), ("x-forwarded-for", "127.0.0.1")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        let h = hdrs(&[("x-real-ip", "127.0.0.1"), ("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // Same /64 is the same bucket either way → not ambiguous.
        let h = hdrs(&[("x-real-ip", "2001:db8:1:2::5"), ("x-forwarded-for", "2001:db8:1:2::6")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("2001:db8:1:2::/64"));
        // Local client through the proxy: everything is trusted → keyed on that address.
        let h = hdrs(&[("x-real-ip", "127.0.0.1"), ("x-forwarded-for", "127.0.0.1")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("127.0.0.1"));
        // unparseable X-Real-IP → just the XFF walk
        let h = hdrs(&[("x-real-ip", "garbage"), ("x-forwarded-for", "6.6.6.6, 203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn auto_mode_cdn_chain_ignores_trusted_x_real_ip() {
        // CDN (trusted via CRYPTIRC_TRUSTED_PROXIES) → nginx on loopback: X-Real-IP is the
        // CDN edge, XFF is "<client>, <edge>".
        let c = parse_client_ip_config("198.18.0.0/15", "");
        let h = hdrs(&[("x-real-ip", "198.18.0.5"), ("x-forwarded-for", "203.0.113.9, 198.18.0.5")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // a client prepending junk can't move its bucket
        let h = hdrs(&[("x-real-ip", "198.18.0.5"), ("x-forwarded-for", "6.6.6.6, 203.0.113.9, 198.18.0.5")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
    }

    #[test]
    fn pinned_xff_mode_ignores_forged_x_real_ip() {
        // HAProxy / Caddy-without-header_up: XFF appended by the proxy, X-Real-IP forged.
        let c = parse_client_ip_config("", "x-forwarded-for");
        let h = hdrs(&[("x-real-ip", "9.9.9.9"), ("x-forwarded-for", "9.9.9.9, 203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // garbage values never become keys
        let h = hdrs(&[("x-real-ip", "evil"), ("x-forwarded-for", "also-evil")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c), None);
        // multiple XFF lines: the last line's last entry is the nearest hop
        let h = hdrs(&[("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        // ip:port forms
        let h = hdrs(&[("x-forwarded-for", "[2001:db8::9]:443")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("2001:db8::/64"));
    }

    #[test]
    fn configured_trusted_proxies_and_header_pinning() {
        let c = parse_client_ip_config("10.0.0.0/8, 2001:db8:ffff::/48 bogus", "");
        assert_eq!(c.trusted.len(), 2);
        // a peer inside a configured range is trusted; XFF walks past trusted hops
        let h = hdrs(&[("x-forwarded-for", "6.6.6.6, 203.0.113.9, 10.1.2.3")]);
        assert_eq!(resolve_client_key(ip("10.9.9.9"), &h, &c).as_deref(), Some("203.0.113.9"));
        assert_eq!(resolve_client_key(ip("11.0.0.1"), &h, &c).as_deref(), Some("11.0.0.1"));
        // CRYPTIRC_REAL_IP_HEADER=x-real-ip pins X-Real-IP (never consults XFF)
        let c = parse_client_ip_config("", "x-real-ip");
        let h0 = hdrs(&[("x-forwarded-for", "203.0.113.9")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h0, &c), None);
        let h = hdrs(&[("x-real-ip", "203.0.113.9"), ("x-forwarded-for", "6.6.6.6")]);
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("203.0.113.9"));
        let c = parse_client_ip_config("", "off");
        assert_eq!(resolve_client_key(ip("127.0.0.1"), &h, &c).as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn home_href_follows_base_path() {
        assert_eq!(app_home_href(""), "/");
        assert_eq!(app_home_href("/cryptirc"), "/cryptirc");
    }
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
    let mut users = state.auth.list_users().await;
    for u in users.iter_mut() {
        let name = u.get("username").and_then(|n| n.as_str()).unwrap_or("").to_string();
        u["avatar"] = avatar::admin_roster_info(&state.avatars, &name);
    }
    Json(users).into_response()
}

// Read-only host + process metrics for the admin Server Status panel. Admin-gated
// like the other /admin routes. Reads /proc + statvfs in THIS process only — never
// contacts or restarts the irc-core daemon (it just reads the daemon's /proc RSS).
async fn route_admin_status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let status = sysstatus::collect(&state.data_dir, state.connections.len()).await;
    Json(status).into_response()
}

async fn route_admin_delete_user(State(state): State<AppState>, headers: HeaderMap, Path(target): Path<String>) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !state.auth.is_admin(&user).await {
        return StatusCode::FORBIDDEN.into_response();
    }
    // Canonicalise exactly the way purge_account / delete_account do (trim + lowercase)
    // BEFORE the self-check: comparing the raw path segment let `DELETE /admin/user/%20alice`
    // slip past "Cannot delete yourself" and then purge alice anyway (the purge trims).
    let target = target.trim().to_lowercase();
    if !auth::is_safe_username(&target) {
        return (StatusCode::BAD_REQUEST, Json(Msg { message: "Invalid username.".into() })).into_response();
    }
    if target == user.trim().to_lowercase() {
        return (StatusCode::BAD_REQUEST, Json(Msg { message: "Cannot delete yourself.".into() })).into_response();
    }
    // r3: a name with no account record answers 404 instead of a misleading "deleted"
    // (it used to run the whole purge on nothing and report success). The record is the
    // last thing a purge removes, so an account whose earlier purge was interrupted still
    // has it and can be deleted again here.
    if !state.auth.account_exists(&target).await {
        return (StatusCode::NOT_FOUND, Json(Msg { message: format!("No account named '{}'.", target) })).into_response();
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
        Ok(_) => {
            // #F9: disabling an account revokes its sessions; also drop its push
            // subscriptions so a device previously subscribed to it stops receiving the
            // account's DMs/mentions. Lowercase to match the on-disk (sanitized, lowercase)
            // username filename regardless of the case the admin typed in the URL.
            state.purge_push_subscriptions(&target.to_lowercase()).await;
            // Remote avatars: a disabled account's IRC session may live on; clear its value.
            avatar::remote::republish(&state.auth, &state.avatars, &state.connections, &state.conn_owners, &target.to_lowercase()).await;
            (StatusCode::OK, Json(Msg { message: format!("User '{}' disabled.", target) })).into_response()
        }
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
    Json(admin_settings(&state).await).into_response()
}

async fn admin_settings(state: &AppState) -> serde_json::Value {
    let open = *state.registration_open.read().await;
    let code_set = !state.registration_code.read().await.is_empty();
    let upload_mb = *state.max_upload_mb.read().await;
    let giphy_key = state.giphy_server_key.read().await.clone();
    let tenor_key = state.tenor_server_key.read().await.clone();
    let lastfm_key = state.lastfm_api_key.read().await.clone();
    serde_json::json!({
        "registration_open": open,
        "registration_code_set": code_set,
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
        "avatars_enabled": state.avatars.enabled(),
    })
}

#[derive(Deserialize)]
struct AdminSettings {
    registration_open: Option<bool>,
    registration_code: Option<String>,
    new_registration_code: Option<String>,
    #[serde(default)]
    clear_registration_code: bool,
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
    // Avatars on/off (optional; omitted = keep current).
    avatars_enabled: Option<bool>,
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
    // #3: Argon2 hash off the async workers, behind the auth-KDF cap.
    let reg_res = {
        let (auth, u, p) = (state.auth.clone(), body.username.clone(), body.password.clone());
        match run_auth_kdf(move || async move { auth.register(&u, &email, &p, None, false).await }).await {
            Some(r) => r,
            None => return auth_busy_response(),
        }
    };
    match reg_res {
        Ok(outcome) => {
            // #F12 regression guard: register() now returns a success-shaped outcome (not Err)
            // when the email is already in use, creating NO account. The public route
            // deliberately masks that for anti-enumeration, but the admin route must NOT — it
            // would report "created" while set_verified silently no-ops on a nonexistent user.
            // Admins are trusted and there is no enumeration concern here, so surface the real
            // failure.
            if outcome.email_in_use {
                return (StatusCode::CONFLICT, Json(Msg { message: "That email is already in use by another account.".into() })).into_response();
            }
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
    save_admin_settings(&state, body).await
}

async fn save_admin_settings(state: &AppState, body: AdminSettings) -> axum::response::Response {
    // Old clients sent whatever was displayed in the invite-code field on every
    // settings change. Once reads omit the code, those writes must never replace it.
    let legacy_code = body.registration_code.is_some();
    if legacy_code && (body.registration_open.is_none() || body.new_registration_code.is_some() || body.clear_registration_code) {
        return (StatusCode::BAD_REQUEST, Json(Msg {
            message: "Refresh CryptIRC or use new_registration_code to set an invite code.".into(),
        })).into_response();
    }
    let reg_code = match (body.new_registration_code, body.clear_registration_code) {
        (Some(_), true) => return (StatusCode::BAD_REQUEST, Json(Msg {
            message: "Set or clear the invite code in a single request.".into(),
        })).into_response(),
        (Some(code), false) if code.trim().is_empty() => return (StatusCode::BAD_REQUEST, Json(Msg {
            message: "Use clear_registration_code to clear the invite code.".into(),
        })).into_response(),
        (None, true) => Some(String::new()),
        (code, false) => code,
    };
    let _guard = state.admin_settings_lock.lock().await;
    // #5: remember whether THIS save explicitly set the registration fields. Only then
    // (or if the file already holds them) are they persisted — a GIF / Last.fm save must
    // not freeze the env-derived CRYPTIRC_REGISTRATION / CRYPTIRC_REG_CODE into the file.
    let set_reg_open = body.registration_open.is_some();
    if let Some(open) = body.registration_open {
        *state.registration_open.write().await = open;
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
    let avatars_switched = body.avatars_enabled.map_or(false, |on| on != state.avatars.enabled());
    if let Some(on) = body.avatars_enabled { state.avatars.set_enabled(on); }
    if let Some(k) = body.lastfm_api_key {
        let k = k.trim();
        if !k.is_empty() { *state.lastfm_api_key.write().await = k.to_string(); }
    }
    let path = std::path::PathBuf::from(&state.data_dir).join("admin_settings.json");
    let mut existing: serde_json::Value = match tokio::fs::read_to_string(&path).await {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(v) => v,
            // #17: file present but UNPARSEABLE — refuse to overwrite. Vivifying an
            // empty object here would drop registration_open/captcha/etc. and silently
            // re-open registration on next boot, defeating the fail-CLOSED boot logic.
            Err(e) => {
                drop(_guard);
                tracing::error!("admin_settings.json present but unparseable; refusing to overwrite: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(Msg { message: "Failed to save settings.".into() })).into_response();
            }
        },
        Err(_) => serde_json::json!({}),
    };
    if set_reg_open || existing.get("registration_open").is_some() {
        existing["registration_open"] = serde_json::json!(*state.registration_open.read().await);
    }
    if let Some(code) = &reg_code {
        existing["registration_code"] = serde_json::json!(code);
    } else if existing.get("registration_code").is_some() {
        existing["registration_code"] = serde_json::json!(*state.registration_code.read().await);
    }
    existing["max_upload_mb"] = serde_json::json!(*state.max_upload_mb.read().await);
    existing["email_required"] = serde_json::json!(*state.email_required.read().await);
    existing["captcha_enabled"] = serde_json::json!(*state.captcha_enabled.read().await);
    existing["gif_provider"] = serde_json::json!(*state.gif_provider.read().await);
    existing["gif_mode"] = serde_json::json!(*state.gif_mode.read().await);
    existing["giphy_server_key"] = serde_json::json!(*state.giphy_server_key.read().await);
    existing["tenor_server_key"] = serde_json::json!(*state.tenor_server_key.read().await);
    existing["lastfm_enabled"] = serde_json::json!(*state.lastfm_enabled.read().await);
    existing["lastfm_api_key"] = serde_json::json!(*state.lastfm_api_key.read().await);
    existing["avatars_enabled"] = serde_json::json!(state.avatars.enabled());
    if let Err(e) = write_secret_json_atomic(&path, &existing).await { // #30/#112
        drop(_guard);
        tracing::error!("failed to persist admin_settings.json: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(Msg { message: "Failed to save settings.".into() })).into_response();
    }
    if let Some(code) = reg_code {
        *state.registration_code.write().await = code;
    }
    drop(_guard);
    if avatars_switched {
        avatar::remote::republish_all(&state.auth, &state.avatars, &state.connections, &state.conn_owners).await;
    }
    // Old panels also set registration/captcha policy in this request. Keep
    // those changes even for clients that don't check the response status.
    if legacy_code {
        return (StatusCode::CONFLICT, Json(Msg {
            message: "Other settings saved. Invite code unchanged. Refresh CryptIRC to set an invite code.".into(),
        })).into_response();
    }
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
        // Timing-safe comparison with no length oracle: compare fixed-size SHA-256 digests
        // in constant time, so the work never depends on either string's length (the old
        // byte loop ran max(len) iterations, i.e. as long as the attacker's input).
        if !registration_code_matches(&req_code, &body.code) {
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
    // #3: Argon2 hash off the async workers, behind the auth-KDF cap.
    let reg_res = {
        let (auth, u, e, p, ipc) = (state.auth.clone(), body.username.clone(), body.email.clone(), body.password.clone(), ip.clone());
        match run_auth_kdf(move || async move { auth.register(&u, &e, &p, ipc.as_deref(), email_required).await }).await {
            Some(r) => r,
            None => return auth_busy_response(),
        }
    };
    match reg_res {
        Ok(outcome) => {
            // #F12: the email is already in use. auth.register() deliberately does NOT create a
            // duplicate account, mint a token, or bail — it returns a success-shaped outcome so
            // this route can mirror the genuine-signup response (same status + body). Bailing
            // here produced a 400 + distinct message vs. the 200 of a free email, a clean
            // email-existence oracle. No mail is sent (there is no token). The equalization is
            // per-mode so the response is identical to what a real new signup would return in the
            // same mode: verify-mode → "check your inbox"; immediate-login mode → "sign in now".
            if outcome.email_in_use {
                let msg = if email_required {
                    "Registered! Check your email to verify your account."
                } else {
                    "Account created! You can sign in now."
                };
                return (StatusCode::OK, Json(Msg { message: msg.into() })).into_response();
            }
            if let Some(token) = outcome.verify_token {
                // Email verification required → mail the link (email is non-empty here).
                let (email, uname, base, from) = (body.email.clone(), body.username.to_lowercase(), state.base_url.clone(), state.from_email.clone());
                // #F27: email::send_* calls the blocking lettre SmtpTransport::send. Run it on
                // the blocking pool (spawn_blocking) instead of a tokio::spawn async task so a
                // slow/hanging SMTP server can't pin a runtime worker. Still fire-and-forget.
                tokio::task::spawn_blocking(move || {
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
            let safe = if ["Username","Password","Email","email","taken","already","attempts","Invalid","required","busy"].iter().any(|w| msg.contains(w)) { msg } else { "Registration failed".into() };
            (StatusCode::BAD_REQUEST, Json(Msg { message: safe })).into_response()
        }
    }
}

/// Constant-time registration-code check over fixed-length digests (see route_register).
fn registration_code_matches(expected: &str, given: &str) -> bool {
    use sha2::{Digest, Sha256};
    use subtle::ConstantTimeEq;
    let a = Sha256::digest(expected.as_bytes());
    let b = Sha256::digest(given.as_bytes());
    bool::from(a.as_slice().ct_eq(b.as_slice()))
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

#[derive(Deserialize)] struct EmailBody {
    #[serde(default)] email: String,
    /// The caller's current login password. Required by the self-service route for any
    /// actual change (the recovery address decides where password resets go, so a bare
    /// session token must not be enough to redirect it). Ignored by the admin route.
    #[serde(default)] current_password: String,
}

/// POST /auth/set-email — the logged-in user sets / updates / clears their own email (Profile).
async fn route_set_email(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<EmailBody>) -> impl IntoResponse {
    let Some(token) = bearer_token(&headers) else { return StatusCode::UNAUTHORIZED.into_response(); };
    let Some(user) = state.auth.validate_session(&token) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };
    // Throttle email changes (per IP + per user) so this can't be used to spray reset mail
    // to many addresses or churn the email-lock table.
    let ip = client_ip(&headers);
    if state.auth.check_ip_rate_limit("set_email", ip.as_deref()).is_err()
        || state.auth.check_user_create_rate_limit(&user, "set_email").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many changes — try again later.".into() })).into_response();
    }
    // Re-authenticate any real change (set, replace or clear) with the current password,
    // like change-password does: a stolen session token alone could otherwise point the
    // recovery address at the attacker and then take the account over via /auth/forgot.
    // Saving the address that is already on file stays a no-op without a password.
    // codex P1 main.rs:2860: the credential the password is verified against is carried into
    // set_email_reauthed, which re-checks it (and this session) under the account lock — a
    // password reset that commits while the slow verify runs makes the change fail instead
    // of installing an address the reset already de-authorized.
    let unchanged = state.auth.current_email(&user).await
        .map_or(false, |cur| cur == body.email.trim().to_lowercase());
    let mut verified: Option<(String, i64)> = None;
    if !unchanged {
        if body.current_password.is_empty() {
            return (StatusCode::FORBIDDEN, Json(Msg { message: auth::EMAIL_CHANGE_NEEDS_PASSWORD.into() })).into_response();
        }
        let res = {
            let (auth, u, p, ipc) = (state.auth.clone(), user.clone(), body.current_password.clone(), ip.clone());
            match run_auth_kdf(move || async move { auth.verify_current_password(&u, &p, ipc.as_deref()).await }).await {
                Some(r) => r,
                None => return auth_busy_response(),
            }
        };
        match res {
            Ok(cred) => verified = Some(cred),
            Err(e) => {
                let m = e.to_string();
                let (code, msg) = if m.contains("Too many") { (StatusCode::TOO_MANY_REQUESTS, "Too many attempts — try again later.") }
                                  else { (StatusCode::FORBIDDEN, "Current password is incorrect.") };
                return (code, Json(Msg { message: msg.into() })).into_response();
            }
        }
    }
    let reauth = auth::EmailChangeAuth { verified: verified.as_ref(), session_token: &token };
    match state.auth.set_email_reauthed(&user, &body.email, reauth).await {
        Ok(_) => {
            let msg = if body.email.trim().is_empty() { "Email removed." } else { "Email saved." };
            (StatusCode::OK, Json(Msg { message: msg.into() })).into_response()
        }
        Err(e) => {
            let m = e.to_string();
            let code = if m == auth::EMAIL_CHANGE_NEEDS_PASSWORD || m == auth::EMAIL_CHANGE_STALE { StatusCode::FORBIDDEN }
                       else if m == auth::ADMIN_LOCK_BUSY { StatusCode::SERVICE_UNAVAILABLE }
                       else { StatusCode::BAD_REQUEST };
            (code, Json(Msg { message: m })).into_response()
        }
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
    // #42: couple shared-key use to identity. Split resolution so we know whether we
    // ended up on the ADMIN's shared key; if so, the target MUST be the caller's own
    // linked username (case-insensitive) — otherwise any authenticated account could
    // spend the admin's quota on arbitrary ?user= lookups (quota drain / anonymizing
    // relay). A caller with their OWN key keeps unrestricted ?user= lookups.
    let own = me.as_ref().map(|u| u.lastfm_key.clone()).unwrap_or_default();
    let using_shared = own.is_empty();
    let key = if !using_shared { own } else { state.lastfm_api_key.read().await.clone() };
    if key.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"No Last.fm API key — set your own in Profile, or ask the admin to add a shared key."}))).into_response();
    }
    if using_shared {
        let own_user = me.as_ref().map(|u| u.lastfm_user.clone()).unwrap_or_default();
        if own_user.is_empty() || !own_user.eq_ignore_ascii_case(&target) {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error":"Set your own Last.fm API key in Profile to look up other users."}))).into_response();
        }
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
    // #18: Throttle every login POST per IP up front, BEFORE canonical_login_id() below —
    // which for an email identifier read_dir+JSON-parses every users/ file (O(N)). Gating the
    // scan behind the per-IP limit stops a flood of email-shaped identifiers from multiplying
    // server work by the user count ahead of any rate limit. Also bounds brute force AND the
    // wrong-captcha early-return path below (which would otherwise never reach login()'s own
    // rate limit). The captcha hint here is keyed on the raw identifier (identical to the
    // account key for username logins; may under-report for an email login, harmless on an
    // already-rejected 429) — resolving the canonical id here would re-run the scan we gate.
    if state.auth.check_ip_rate_limit("login_attempt", ip.as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(LoginErr { message: "Too many attempts — try again later.".into(), captcha_required: state.auth.login_captcha_required(ip.as_deref(), &body.username) })).into_response();
    }
    // #7: resolve username-OR-email to the canonical account username and key the captcha
    // gate + fail-counter on THAT, so an account reachable by both username and email
    // doesn't get two independent captcha/fail buckets (double the brute-force budget).
    let acct = state.auth.canonical_login_id(&body.username).await;
    // After enough recent failures from this IP, require a captcha BEFORE checking the
    // password, so password-guessing is captcha-gated. Normal logins are unaffected.
    if state.auth.login_captcha_required(ip.as_deref(), &acct) {
        if !verify_captcha(&state, &body.captcha_id, &body.captcha_answer) {
            return (StatusCode::UNAUTHORIZED, Json(LoginErr { message: "Please complete the captcha to continue.".into(), captcha_required: true })).into_response();
        }
    }
    // #3: Argon2 verify off the async workers, behind the auth-KDF cap.
    let login_res = {
        let (auth, u, p, ipc) = (state.auth.clone(), body.username.clone(), body.password.clone(), ip.clone());
        match run_auth_kdf(move || async move { auth.login(&u, &p, ipc.as_deref()).await }).await {
            Some(r) => r,
            None => return auth_busy_response(),
        }
    };
    match login_res {
        // login() resolves the identifier (username OR email) to the real account
        // username — return THAT so the client's identity isn't set to an email.
        Ok((token, username)) => {
            state.auth.reset_login_fails(ip.as_deref(), &acct);
            (StatusCode::OK, Json(AuthOkBody { token, username })).into_response()
        }
        Err(e) => {
            state.auth.record_login_fail(ip.as_deref(), &acct);
            let msg = e.to_string();
            // #56: login now returns one generic "Invalid username or password" for
            // nonexistent/unverified/wrong-password — "verified" is no longer emitted,
            // so drop it from the whitelist to avoid ever reflecting that oracle.
            let safe = if ["Invalid","attempts"].iter().any(|w| msg.contains(w)) { msg } else { "Login failed".into() };
            // Tell the client whether the NEXT attempt will need a captcha (>= threshold fails).
            (StatusCode::UNAUTHORIZED, Json(LoginErr { message: safe, captcha_required: state.auth.login_captcha_required(ip.as_deref(), &acct) })).into_response()
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

/// rust-http #6: the app's home URL for links on the server-rendered verify/reset pages,
/// from the configured base path ("" for CRYPTIRC_BASE_PATH=/, else e.g. "/cryptirc")
/// instead of a hard-coded "/cryptirc", which 404s on every installer deployment.
fn app_home_href(base_path: &str) -> String {
    if base_path.is_empty() { "/".to_string() } else { base_path.to_string() }
}

async fn route_verify(State(state): State<AppState>, headers: HeaderMap, Query(q): Query<VerifyQuery>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let home = html_escape(&app_home_href(&state.base_path));
    match state.auth.verify_email(&q.token, ip.as_deref()).await {
        Ok(_) => Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Verified</title>
<style>body{{background:#0b0d0f;color:#c8d8e8;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
.b{{background:#111418;border:1px solid #2a3444;border-radius:12px;padding:32px 40px;text-align:center;}}
h2{{background:linear-gradient(135deg,#00d4aa,#0099ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;}}
a{{color:#00d4aa;text-decoration:none;}}</style></head>
<body><div class="b"><h2>✓ Email Verified</h2><p>Your account is now active.</p><br><a href="{}">Open CryptIRC →</a></div></body></html>"#, home)),
        Err(e) => Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Error</title>
<style>body{{background:#0b0d0f;color:#ff4466;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;}}
a{{color:#00d4aa;}}</style></head><body><p>{}</p><a href="{}">← Back</a></body></html>"#, html_escape(&e.to_string()), home)),
    }
}

async fn route_forgot(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ForgotBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    let (email_addr, base, from) = (body.email.clone(), state.base_url.clone(), state.from_email.clone());
    match state.auth.request_password_reset(&body.email, ip.as_deref()).await {
        Ok(Some((token, username))) => {
            // #F27: run the blocking lettre SMTP send on the blocking pool so a slow SMTP
            // server can't pin a tokio runtime worker. Still fire-and-forget + error-logged.
            tokio::task::spawn_blocking(move || {
                if let Err(e) = email::send_password_reset(&email_addr, &username, &token, &base, &from) { error!("Reset email: {}", e); }
            });
        }
        _ => {} // Don't reveal whether the email exists
    }
    // Always return success to prevent email enumeration
    (StatusCode::OK, Json(Msg { message: "If that email is registered, a reset link has been sent.".into() }))
}

async fn route_reset_page(State(state): State<AppState>, Query(q): Query<ResetQuery>) -> impl IntoResponse {
    // #6: link home and POST the reset to the CONFIGURED base path (see app_home_href).
    let home = html_escape(&app_home_href(&state.base_path));
    let reset_url = js_escape(&format!("{}/auth/reset", state.base_path));
    let nonce = PageScriptNonce::new();
    let html = Html(format!(r#"<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
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
  <button id="rp-btn">Set New Password</button>
</div>
<div id="reset-ok" style="display:none" class="ok">
  ✓ Password reset!<br>You can now <a href="{home}">sign in</a> with your new password.
</div>
<script nonce="{nonce}">
const TOKEN="{token}";
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
    const r=await fetch("{reset_url}",{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:TOKEN,password:pass}})}});
    const d=await r.json();
    if(!r.ok){{err.textContent=d.message||'Reset failed';return;}}
    document.getElementById('reset-form').style.display='none';
    document.getElementById('reset-ok').style.display='';
  }}catch(e){{err.textContent='Network error';}}
  finally{{btn.disabled=false;btn.textContent='Set New Password';}}
}}
document.getElementById('rp-btn').addEventListener('click',doReset);
document.querySelectorAll('input').forEach(i=>i.addEventListener('keydown',e=>{{if(e.key==='Enter')doReset();}}));
</script>
</div></body></html>"#, home = home, token = js_escape(&q.token), reset_url = reset_url, nonce = nonce.0));
    (axum::Extension(nonce), [(header::CACHE_CONTROL, NO_CACHE)], html)
}

async fn route_reset_password(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<ResetPasswordBody>) -> impl IntoResponse {
    let ip = client_ip(&headers);
    // #3: Argon2 hash off the async workers, behind the auth-KDF cap.
    let reset_res = {
        let (auth, t, p) = (state.auth.clone(), body.token.clone(), body.password.clone());
        match run_auth_kdf(move || async move { auth.reset_password(&t, &p, ip.as_deref()).await }).await {
            Some(r) => r,
            None => return auth_busy_response(),
        }
    };
    match reset_res {
        Ok(username) => {
            info!("Password reset for user: {}", username);
            // #F9: a reset means the account may have been compromised — drop any push
            // subscriptions so an attacker's device can't keep receiving the victim's
            // DMs/mentions post-recovery. The user re-subscribes on next opt-in.
            state.purge_push_subscriptions(&username).await;
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
    // r4 V3S-1: the account generation this request was authorized for (see below).
    let epoch = state.auth.account_epoch(&user);
    // #3: Argon2 verify + hash off the async workers, behind the auth-KDF cap.
    let chpw_res = {
        let (auth, u, o, n) = (state.auth.clone(), user.clone(), body.old_password.clone(), body.new_password.clone());
        match run_auth_kdf(move || async move { auth.change_password(&u, &o, &n, ip.as_deref()).await }).await {
            Some(r) => r,
            None => return auth_busy_response(),
        }
    };
    match chpw_res {
        Ok(_) => {
            // #F9: a password change also invalidates any push subscriptions a prior
            // (possibly hostile) session left behind — drop them so they can't keep
            // receiving the user's DMs/mentions. `user` is the resolved session username.
            state.purge_push_subscriptions(&user).await;
            // change_password() purges ALL sessions (incl. this caller's) for security; re-issue
            // a fresh session so the user who just changed their own password stays logged in
            // (other devices remain logged out — that's the intent). Client swaps to this token.
            // r4 V3S-1: not if the account was deleted meanwhile — a token minted after the
            // purge's last session sweep used to stay valid for a later same-name account.
            let Some(token) = state.auth.issue_session_if_live(&user, epoch) else {
                return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response();
            };
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
            // r4 (C1-1 class): the account generation this upload is for — see below.
            let epoch = state.auth.account_epoch(&user);
            if !state.auth.can_upload(&user).await {
                return (StatusCode::FORBIDDEN, Json(Msg { message: "Upload permission not granted. Contact an admin.".into() })).into_response();
            }
            // #32: per-user rate limit so an at-quota/abusive account can't flood the
            // RAM/ffmpeg metadata-strip path. Runs before handle_upload so a throttled
            // request never pays the strip cost. Shared 10/60s budget (same "upload"
            // bucket as /upload/init; matches paste/short creation limits).
            if state.auth.check_user_create_rate_limit(&user, "upload").is_err() {
                return (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: "Too many uploads — slow down".into() })).into_response();
            }
            let max_bytes = *state.max_upload_mb.read().await * 1024 * 1024;
            // Codex P1 (upload.rs:232): handle_upload buffers the whole file in RAM (and the
            // metadata strip makes a second copy) before any quota check, so concurrent legacy
            // uploads had no aggregate bound. Reserve the request's worst case from a
            // process-wide budget and cap per-account concurrency; over budget → 503.
            let _admit = match LegacyUploadAdmission::acquire(&user, &headers, max_bytes) {
                Some(a) => a,
                None => return (StatusCode::SERVICE_UNAVAILABLE, [(header::RETRY_AFTER, "5")],
                    Json(Msg { message: "Server busy — too many uploads in progress, try again shortly.".into() })).into_response(),
            };
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
                    // r4 (C1-1 class): the body may stream for minutes. If the account was
                    // deleted meanwhile, purge_account's upload sweep may already have run, and
                    // this record + file would be inherited by a later same-name account.
                    if !state.auth.account_ticket_live(&user, epoch) {
                        upload::delete_user_upload(&state.data_dir, &state.upload_dir, &user, &r.filename).await;
                        return (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response();
                    }
                    (StatusCode::OK, Json(r)).into_response()
                }
                Err(e) => (StatusCode::BAD_REQUEST, Json(Msg { message: e.to_string() })).into_response(),
            }
        }
    }
}

/// Process-wide RAM budget for the legacy multipart /upload, in MiB. One request reserves
/// twice its body size (the buffered file + the metadata-strip copy, both live until
/// handle_upload returns), so the largest allowed upload (500 MB setting) still fits on
/// its own while several default-size (25 MB) uploads run side by side.
const LEGACY_UPLOAD_BUDGET_MIB: u32 = 1024;
/// Concurrent legacy uploads per account.
const LEGACY_UPLOAD_MAX_PER_USER: usize = 2;
fn legacy_upload_budget() -> &'static Arc<Semaphore> {
    static S: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    S.get_or_init(|| Arc::new(Semaphore::new(LEGACY_UPLOAD_BUDGET_MIB as usize)))
}
fn legacy_upload_user_counts() -> &'static DashMap<String, usize> {
    static M: std::sync::OnceLock<DashMap<String, usize>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}
/// Admission ticket for one legacy /upload request; releases its budget + slot on drop.
struct LegacyUploadAdmission { user: String, _permit: tokio::sync::OwnedSemaphorePermit }
impl LegacyUploadAdmission {
    fn acquire(user: &str, headers: &HeaderMap, max_bytes: usize) -> Option<Self> {
        const MIB: u64 = 1024 * 1024;
        // Declared body size (axum's DefaultBodyLimit still enforces the hard cap while
        // reading); without Content-Length assume the largest allowed file.
        let declared = headers.get(header::CONTENT_LENGTH).and_then(|v| v.to_str().ok())
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(max_bytes as u64 + MIB);
        let need = (declared.min(max_bytes as u64 + MIB).div_ceil(MIB).max(1) * 2)
            .min(LEGACY_UPLOAD_BUDGET_MIB as u64) as u32;
        {
            let mut c = legacy_upload_user_counts().entry(user.to_string()).or_insert(0);
            if *c >= LEGACY_UPLOAD_MAX_PER_USER { return None; }
            *c += 1;
        }
        match legacy_upload_budget().clone().try_acquire_many_owned(need) {
            Ok(p) => Some(Self { user: user.to_string(), _permit: p }),
            Err(_) => { Self::release_slot(user); None }
        }
    }
    fn release_slot(user: &str) {
        if let Some(mut c) = legacy_upload_user_counts().get_mut(user) { *c = c.saturating_sub(1); }
        legacy_upload_user_counts().remove_if(user, |_, v| *v == 0);
    }
}
impl Drop for LegacyUploadAdmission {
    fn drop(&mut self) { Self::release_slot(&self.user); }
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
    if !body.source_target.is_empty() && body.source_target != "status" {
        let blocked = match state.e2e_store.protected_names(&user).await {
            Ok((channels, peers)) => match_e2e_target(&body.source_target, &body.source_conn_id, channels, peers).is_some(),
            Err(_) => true,
        };
        if blocked {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({
                "error": "Server-hosted files are unavailable in encrypted chats"
            }))).into_response();
        }
    }
    // #32: per-user rate limit on the chunked-upload entry point. Gating init bounds
    // how many new uploads (and thus finalize-time metadata strips) one account can
    // start; the per-chunk route stays unlimited so large multi-chunk files still
    // work. Shared 10/60s "upload" bucket (same as the legacy /upload route).
    if state.auth.check_user_create_rate_limit(&user, "upload").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many uploads — slow down"}))).into_response();
    }
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

/// rust-http #10: per-account cap on concurrent /upload/chunk bodies (a share of
/// the UPLOAD_CHUNK_MAX_CONCURRENT global slots). The frontend runs one chunk at a
/// time per file, so this only bites when one account uploads many files at once —
/// and then the extra chunks just get the usual retried 503.
const UPLOAD_CHUNK_MAX_PER_USER: usize = 6;
/// No body bytes for this long → give the slot back (408; the client retries).
const UPLOAD_CHUNK_IDLE: std::time::Duration = std::time::Duration::from_secs(30);
/// Hard ceiling for one chunk body (~1 MiB from the frontend): ≈8.7 KB/s minimum.
const UPLOAD_CHUNK_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

fn chunk_user_counts() -> &'static DashMap<String, usize> {
    static M: std::sync::OnceLock<DashMap<String, usize>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}
struct ChunkUserSlot(String);
impl ChunkUserSlot {
    fn acquire(user: &str) -> Option<Self> {
        let mut c = chunk_user_counts().entry(user.to_string()).or_insert(0);
        if *c >= UPLOAD_CHUNK_MAX_PER_USER { return None; }
        *c += 1;
        Some(ChunkUserSlot(user.to_string()))
    }
}
impl Drop for ChunkUserSlot {
    fn drop(&mut self) {
        if let Some(mut c) = chunk_user_counts().get_mut(&self.0) { *c = c.saturating_sub(1); }
        chunk_user_counts().remove_if(&self.0, |_, v| *v == 0);
    }
}

enum ChunkReadError { TooLarge, Timeout, Io }

/// Buffer a chunk body (≤ `cap` bytes) with an idle timeout between frames and an
/// overall deadline (rust-http #10). Same size semantics as axum::body::to_bytes.
async fn read_chunk_body(body: axum::body::Body, cap: usize) -> Result<axum::body::Bytes, ChunkReadError> {
    let deadline = tokio::time::Instant::now() + UPLOAD_CHUNK_DEADLINE;
    let mut stream = body.into_data_stream();
    let mut buf: Vec<u8> = Vec::new();
    loop {
        let wait = std::cmp::min(UPLOAD_CHUNK_IDLE, deadline.saturating_duration_since(tokio::time::Instant::now()));
        match tokio::time::timeout(wait, stream.next()).await {
            Err(_) => return Err(ChunkReadError::Timeout),
            Ok(None) => return Ok(axum::body::Bytes::from(buf)),
            Ok(Some(Err(_))) => return Err(ChunkReadError::Io),
            Ok(Some(Ok(bytes))) => {
                if buf.len().saturating_add(bytes.len()) > cap { return Err(ChunkReadError::TooLarge); }
                buf.extend_from_slice(&bytes);
            }
        }
    }
}

#[derive(Deserialize)]
struct ChunkQuery { offset: usize }

async fn route_upload_chunk(
    State(state): State<AppState>, headers: HeaderMap,
    Path(id): Path<String>, Query(q): Query<ChunkQuery>,
    body: axum::body::Body,
) -> impl IntoResponse {
    let user = match upload_auth(&state, &headers).await { Ok(u) => u, Err(e) => return e.into_response() };
    // rust-http #10: don't let a request hold a shared slot for an id that can't
    // take a chunk anyway (unknown / not-in-progress → the same 400 append_chunk
    // returns, so the client's existing re-sync path is unchanged).
    if !upload::chunk_target_exists(&state.data_dir, &user, &id).await {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Upload not initialized"}))).into_response();
    }
    // rust-http #10: one account may hold at most UPLOAD_CHUNK_MAX_PER_USER of the
    // UPLOAD_CHUNK_MAX_CONCURRENT global slots, so a single slow uploader can't
    // starve everyone else. 503 is retried by the frontend chunk-pump.
    let _user_slot = match ChunkUserSlot::acquire(&user) {
        Some(g) => g,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"Server busy — retry shortly"}))).into_response(),
    };
    // #33: bound total RAM from concurrent in-flight chunk bodies. Take a
    // process-wide permit BEFORE buffering so at most UPLOAD_CHUNK_MAX_CONCURRENT
    // chunk bodies are resident at once; shed (503) when saturated rather than
    // queueing — the frontend chunk-pump retries transient 503s with backoff.
    let _permit = match upload_chunk_sem().try_acquire() {
        Ok(p)  => p,
        Err(_) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"Server busy — retry shortly"}))).into_response(),
    };
    // Enforce the admin max-upload limit against the cumulative file size.
    let max_bytes = *state.max_upload_mb.read().await * 1024 * 1024;
    // #33: cap the single-chunk buffer to the configured limit (+1 MiB for the
    // client's ~1 MiB chunk size), never above UPLOAD_CHUNK_MAX_BYTES, instead of
    // the old fixed 64 MiB — so a chunk POST can't force a 64 MiB allocation
    // regardless of max_upload_mb. Oversized reads error out early.
    let chunk_cap = std::cmp::min(UPLOAD_CHUNK_MAX_BYTES, max_bytes.saturating_add(1024 * 1024));
    // rust-http #10: read under an idle timeout (no bytes for UPLOAD_CHUNK_IDLE) and
    // an overall deadline (UPLOAD_CHUNK_DEADLINE), so a body that trickles or stalls
    // releases its slot instead of holding it forever.
    let body = match read_chunk_body(body, chunk_cap).await {
        Ok(b)  => b,
        Err(ChunkReadError::TooLarge) => return (StatusCode::PAYLOAD_TOO_LARGE, Json(serde_json::json!({"error":"Chunk too large"}))).into_response(),
        Err(ChunkReadError::Timeout) => return (StatusCode::REQUEST_TIMEOUT, Json(serde_json::json!({"error":"Upload chunk timed out — retrying"}))).into_response(),
        Err(ChunkReadError::Io) => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Chunk read failed"}))).into_response(),
    };
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
        // r4 F1-1: a storage failure (stored file / upload list not written) keeps the
        // staged bytes and the Uploading record, so the client's finalize retry can still
        // succeed — 503, and the upload is NOT marked failed (app.js retries any non-401).
        Err(e) if e.downcast_ref::<upload::FinalizeRetryable>().is_some() => {
            (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": e.to_string()}))).into_response()
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
    match state.e2e_store.fetch_bundle(&safe, &caller).await {
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
    // r4 C1-7: the account generation this paste is created for (see the check below).
    let epoch = state.auth.account_epoch(&user);
    // Per-user rate limit: each paste writes a file, so cap creation to keep one
    // account from filling the disk. The budget is generous for normal use.
    if state.auth.check_user_create_rate_limit(&user, "paste").is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many pastes — slow down"}))).into_response();
    }
    if let Err(e) = body.validate_field_lengths() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": e.to_string()}))).into_response();
    }
    // codex P1 paste.rs:208: a password-protected paste hashes its password with Argon2
    // inside create(); run that on the blocking pool behind the process-wide auth-KDF
    // admission (like login and paste unlock), never on an async worker. Busy → 503.
    let protected = body.password.as_deref().map_or(false, |p| !p.is_empty());
    let created = if protected {
        let (store, u) = (state.paste_store.clone(), user.clone());
        match run_auth_kdf(move || async move { store.create(&body, &u).await }).await {
            Some(r) => r,
            None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error":"Server busy — please try again in a moment."}))).into_response(),
        }
    } else {
        state.paste_store.create(&body, &user).await
    };
    // r4 C1-7: a protected paste hashes for a while; if the account was deleted meanwhile
    // (purge_account has already swept its pastes), don't leave this one behind for a later
    // same-name account.
    if let Ok(paste) = created.as_ref() {
        if !state.auth.account_ticket_live(&user, epoch) {
            state.paste_store.delete(&paste.id).await;
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
        }
    }
    match created {
        Ok(paste) => {
            let url = format!("{}/paste/{}", state.base_url, paste.id);
            Json(serde_json::json!({
                "id": paste.id,
                "url": url,
                "content_type": paste.content_type.as_str(),
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
    Query(_params): Query<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    // #F24: never honor ?password on the GET path. A protected paste is unlocked only via the
    // POST form (route_paste_view_post) so the password can't land in the URL / proxy access
    // log / browser history / Referer. Passing an empty password here leaves public pastes
    // fully viewable (their password is unused) and makes a protected paste render the POST
    // unlock form instead of accepting a query-string password.
    render_paste(&state, &id, &headers, "").await
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

// POST unlock for the sandboxed app view: the hidden form on the paste page
// posts the already-verified password here (never a URL), mirroring
// route_paste_view_post's rate-limit + verify path.
async fn route_paste_app_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let pw = form.get("password").map(|s| s.as_str()).unwrap_or("");
    serve_paste_app(&state, &id, &headers, pw).await
}

// GET: public html pastes only. A protected paste is refused so the password can
// never be supplied via the URL (audit #F24); the POST form above is the only way in.
async fn route_paste_app(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    serve_paste_app(&state, &id, &headers, "").await
}

/// Serve an `html` paste as a runnable, sandboxed document for the paste page's
/// iframe. Only this route ever returns a paste body as text/html — the raw route
/// stays text/plain, so no paste ever executes with CryptIRC origin privileges.
/// The response carries the private marker that `security_headers_mw` turns into
/// the app framing policy (frame-ancestors 'self' + CSP sandbox) and then removes.
async fn serve_paste_app(state: &AppState, id: &str, headers: &HeaderMap, pw: &str) -> axum::response::Response {
    // Same per-IP view budget as the paste page so app loads can't outpace views.
    if state.auth.check_ip_rate_limit("paste_view", client_ip(headers).as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests — try again later.").into_response();
    }
    match state.paste_store.get(id).await {
        Ok(Some(paste)) => {
            if paste.content_type != paste::PasteKind::Html {
                // Only HTML pastes have an app view; text/markdown are 404 here.
                return (StatusCode::NOT_FOUND, "Not found").into_response();
            }
            if paste.password_hash.is_some() {
                // GET never unlocks (the password would travel in the URL); only the
                // hidden POST form from the unlocked paste page may.
                if pw.is_empty() {
                    return (StatusCode::FORBIDDEN, "Password required").into_response();
                }
                // Unauthenticated + 64-MiB Argon2id derive: rate-limit per client IP
                // before the derive and run it off the async workers (as render_paste).
                if state.auth.check_ip_rate_limit("paste_unlock", client_ip(headers).as_deref()).is_err() {
                    return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts — try again later.").into_response();
                }
                // NEW-2: through the shared auth-KDF cap (bounded concurrency + memory),
                // not an uncapped spawn_blocking; None = no slot → 503.
                let verify_ok = match paste_password_ok(&paste, pw).await {
                    Some(ok) => ok,
                    None => return (StatusCode::SERVICE_UNAVAILABLE, "Server busy — please try again in a moment.").into_response(),
                };
                if !verify_ok {
                    return (StatusCode::FORBIDDEN, "Password required").into_response();
                }
            }
            let mut resp = (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8"), (header::CACHE_CONTROL, NO_CACHE)],
                paste.content,
            ).into_response();
            // Consumed and removed by security_headers_mw.
            resp.headers_mut().insert(HeaderName::from_static(PASTE_APP_FRAME_MARKER), HeaderValue::from_static("1"));
            resp
        }
        Ok(None) => (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Error loading paste.").into_response(),
    }
}

// ── Paste view styles/constants ─────────────────────────────────────────────
// The paste view is rendered per paste type (text/markdown/html). Styles live in
// constants so the format! calls below never need escaped braces.
/// Private marker header consumed by `security_headers_mw`: a response carrying it
/// gets the sandboxed-app framing policy (frame-ancestors 'self'; CSP sandbox)
/// instead of the global DENY/none policy. Only `serve_paste_app` ever sets it, and
/// the middleware removes it before the response leaves the server.
const PASTE_APP_FRAME_MARKER: &str = "x-cryptirc-app-frame";
/// Private marker header (set by `render_paste` for Markdown pastes, consumed and
/// removed by `security_headers_mw`) asking for `PASTE_SANDBOX_DOC_CSP` on top of
/// the normal global policy.
const PASTE_SANDBOX_DOC_MARKER: &str = "x-cryptirc-sandbox-doc";
/// Extra CSP for a rendered Markdown paste. Sent as a SECOND CSP header (browsers
/// enforce both), so the global policy still applies; this adds a `sandbox` with no
/// `allow-scripts` and no `allow-same-origin`: the page gets an opaque origin, so
/// author-controlled `<img src>`/links can't make same-origin (cookie-bearing)
/// requests, and nothing can script it. allow-forms keeps the protected-paste
/// "raw" button working; allow-popups(+escape) keeps ctrl/middle-click on links
/// opening normal, unsandboxed tabs. Looks identical (inline <style> still OK).
const PASTE_SANDBOX_DOC_CSP: &str = "sandbox allow-forms allow-popups allow-popups-to-escape-sandbox";

/// Append the Markdown-paste sandbox CSP (see PASTE_SANDBOX_DOC_CSP).
fn apply_sandbox_doc_csp(h: &mut HeaderMap) {
    h.append(HeaderName::from_static("content-security-policy"), HeaderValue::from_static(PASTE_SANDBOX_DOC_CSP));
}
const PASTE_BASE_CSS: &str =
    "body{background:#0b0d0f;color:#e0e0e0;font-family:monospace;margin:0}a{color:#00d4aa}";
const PASTE_TEXT_CSS: &str = "body{padding:16px}\
    .hdr{display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid #2a2e3e;margin-bottom:12px;flex-wrap:wrap;gap:8px}\
    .meta{font-size:12px;color:#888}\
    pre{background:#141620;padding:16px;border-radius:8px;overflow-x:auto;border:1px solid #2a2e3e;white-space:pre-wrap;word-break:break-word;line-height:1.5}";
const PASTE_MD_CSS: &str =
    ".md{background:#141620;padding:18px 22px;border-radius:8px;border:1px solid #2a2e3e;line-height:1.65;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;font-size:15px;overflow-wrap:break-word}\
    .md h1,.md h2{border-bottom:1px solid #2a2e3e;padding-bottom:6px;margin:18px 0 10px}\
    .md h1{font-size:26px}.md h2{font-size:21px}\
    .md h3,.md h4,.md h5,.md h6{margin:14px 0 8px}\
    .md p{margin:10px 0}\
    .md ul,.md ol{padding-left:24px}.md li{margin:3px 0}\
    .md code{font-family:monospace;background:#0b0d0f;padding:2px 5px;border-radius:4px;font-size:13px}\
    .md pre{background:#0b0d0f;padding:12px;border-radius:6px;overflow-x:auto;border:1px solid #2a2e3e;white-space:pre-wrap;word-break:break-word}\
    .md pre code{background:none;padding:0}\
    .md blockquote{margin:10px 0;padding:6px 14px;border-left:3px solid #00d4aa;background:#10131c;color:#b8b8b8}\
    .md table{border-collapse:collapse;margin:12px 0;display:block;overflow-x:auto}\
    .md th,.md td{border:1px solid #2a2e3e;padding:6px 10px}\
    .md img{max-width:100%}.md input[type=checkbox]{margin-right:6px}\
    .md hr{border:none;border-top:1px solid #2a2e3e;margin:16px 0}";
const PASTE_APP_CSS: &str = "body{height:100vh;display:flex;flex-direction:column;overflow:hidden}\
    .toolbar{display:flex;align-items:center;gap:8px;padding:8px 12px;border-bottom:1px solid #2a2e3e;background:#141620;flex-wrap:wrap}\
    .toolbar .spacer{flex:1}\
    .meta{font-size:12px;color:#888}\
    .tab{padding:5px 12px;border-radius:5px;border:1px solid #2a2e3e;background:#1a1e2e;color:#e0e0e0;cursor:pointer;font:inherit;font-size:12px;text-decoration:none}\
    .tab.active{background:#00d4aa;color:#000;font-weight:700;border-color:#00d4aa}\
    .pane{flex:1;min-height:0;position:relative}\
    .pane iframe{width:100%;height:100%;border:0;background:#fff}\
    #pane-src{display:none;flex:1;min-height:0;overflow:auto;padding:16px}\
    #pane-src pre{margin:0;background:#141620;padding:16px;border-radius:8px;border:1px solid #2a2e3e;white-space:pre-wrap;word-break:break-word;line-height:1.5}";
/// Iframe sandbox tokens for a running HTML paste. `allow-same-origin` is
/// deliberately absent: the app gets an opaque origin and cannot touch CryptIRC
/// cookies/session/storage or the parent document. Top-navigation is allowed for
/// no token. The app route repeats this isolation with a CSP `sandbox` directive.
const PASTE_APP_SANDBOX: &str =
    "allow-scripts allow-forms allow-modals allow-popups allow-downloads allow-pointer-lock";
const PASTE_APP_TOGGLE_JS: &str = "(function(){\
    var t=document.getElementById('tab-app'),s=document.getElementById('tab-src');\
    function show(n){var a=document.getElementById('pane-app'),p=document.getElementById('pane-src');\
    var isApp=n==='app';a.style.display=isApp?'block':'none';p.style.display=isApp?'none':'block';\
    t.classList.toggle('active',isApp);s.classList.toggle('active',!isApp);}\
    t.addEventListener('click',function(){show('app');});\
    s.addEventListener('click',function(){show('src');});\
    var f=document.getElementById('app-auth');if(f){f.submit();}})();";

/// NEW-2 (verify v-srv-a): a paste-password check (Argon2) run through the shared
/// auth-KDF cap (`run_auth_kdf`: bounded concurrency, so a burst of wrong unlocks from
/// many IPs can't hold an unbounded number of Argon2 buffers or starve the workers).
/// Some(ok) = checked; None = no slot within the queue timeout (caller answers 503).
/// Reject empty or over-limit passwords before taking a KDF slot.
async fn paste_password_ok(paste: &paste::Paste, pw: &str) -> Option<bool> {
    if pw.is_empty() || !paste.allows_password_length(pw) { return Some(false); }
    let (paste, pw) = (paste.clone(), pw.to_string());
    run_auth_kdf(move || async move { paste::PasteStore::verify_password(&paste, &pw) }).await
}

async fn render_paste(state: &AppState, id: &str, headers: &HeaderMap, pw: &str) -> axum::response::Response {
    // #19/#45: the paste id is an unguessable full-UUID capability; still rate-limit
    // view/raw per client IP so unknown-id probing can't be done at full speed, and so
    // a missing id (404) and a present one are not distinguishable by request rate.
    if state.auth.check_ip_rate_limit("paste_view", client_ip(headers).as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, Html("Too many requests — try again later.".to_string())).into_response();
    }
    match state.paste_store.get(id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                // This endpoint is unauthenticated, and verify_password runs a
                // 64-MiB Argon2id derive. Without a limit an attacker can spray
                // guesses to exhaust CPU. Rate-limit per client IP BEFORE the
                // derive, and run the derive off the async workers so it can't pin
                // one. A legitimate single unlock stays well under the budget.
                // Just opening the link (no password yet) shows the form without a
                // derive and without spending the unlock budget.
                if !pw.is_empty() && state.auth.check_ip_rate_limit("paste_unlock", client_ip(headers).as_deref()).is_err() {
                    return (StatusCode::TOO_MANY_REQUESTS,
                        Html("Too many attempts — try again later.".to_string())).into_response();
                }
                // NEW-2: through the shared auth-KDF cap (bounded concurrency + memory),
                // not an uncapped spawn_blocking; None = no slot → 503.
                let verify_ok = match paste_password_ok(&paste, pw).await {
                    Some(ok) => ok,
                    None => return (StatusCode::SERVICE_UNAVAILABLE, "Server busy — please try again in a moment.").into_response(),
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
            let id_esc = html_escape(id);
            let lang = html_escape(&paste.language);
            let created = chrono::DateTime::from_timestamp(paste.created_at, 0)
                .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string()).unwrap_or_default();
            let expires = paste.expires_at.and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                .map(|d| format!("Expires: {}", d.format("%Y-%m-%d %H:%M UTC"))).unwrap_or_else(|| "No expiration".into());
            // Build URLs from the configured base path; never hardcode /cryptirc
            // (that breaks root deployments and was the legacy behaviour here).
            let base = state.base_path.as_str();
            // rust-http #9: a protected paste's raw text is fetched by POSTing the
            // already-verified password (never a URL); public pastes keep the plain link.
            let is_protected = paste.password_hash.is_some();
            let raw_link = |class: &str| if is_protected {
                format!(
                    "<form method=\"post\" action=\"{}/paste/{}/raw\" style=\"display:inline;margin:0\">\
                     <input type=\"hidden\" name=\"password\" value=\"{}\">\
                     <button type=\"submit\" class=\"{}\" style=\"{}\">raw</button></form>",
                    base, id_esc, html_escape(pw), class,
                    if class.is_empty() { "background:none;border:0;padding:0;color:#00d4aa;font:inherit;cursor:pointer;text-decoration:underline" } else { "" }
                )
            } else if class.is_empty() {
                format!("<a href=\"{}/paste/{}/raw\">raw</a>", base, id_esc)
            } else {
                format!("<a class=\"{}\" href=\"{}/paste/{}/raw\">raw</a>", class, base, id_esc)
            };
            let meta = format!(
                "{} · {} · by {} · {} · {}",
                lang, created, html_escape(&paste.author), expires, raw_link("")
            );
            let hdr = format!(
                "<div class=\"hdr\"><span><a href=\"{}/\">CryptIRC</a> Paste</span><span class=\"meta\">{}</span></div>",
                base, meta
            );
            let mut page_scripts = None;
            let (style, body) = match paste.content_type {
                paste::PasteKind::Text => (
                    format!("{}{}", PASTE_BASE_CSS, PASTE_TEXT_CSS),
                    format!("{}<pre>{}</pre>", hdr, escaped),
                ),
                paste::PasteKind::Markdown => {
                    // The Markdown page runs sandboxed (opaque origin, see
                    // PASTE_SANDBOX_DOC_CSP), so cookie-authenticated /files/ images
                    // can no longer load there. Every upload is public-by-link on
                    // /pub/ anyway, so point this server's own /files/ images at /pub/
                    // (exactly what the app does for its own links) — nothing that
                    // loaded before stops loading.
                    let md = paste_render::render_markdown(&paste.content)
                        .replace(&format!("src=\"{}/files/", base), &format!("src=\"{}/pub/", base))
                        .replace(&format!("src=\"{}/files/", state.base_url), &format!("src=\"{}/pub/", state.base_url));
                    (
                        format!("{}{}{}", PASTE_BASE_CSS, PASTE_TEXT_CSS, PASTE_MD_CSS),
                        format!("{}<article class=\"md\">{}</article>", hdr, md),
                    )
                }
                paste::PasteKind::Html => {
                    let nonce = PageScriptNonce::new();
                    let scripts = format!("<script nonce=\"{}\">{}</script>", nonce.0, PASTE_APP_TOGGLE_JS);
                    page_scripts = Some(nonce);
                    // The app runs only on this dedicated route (never the raw URL,
                    // which stays text/plain) inside a sandbox with an opaque origin.
                    let app_url = format!("{}/paste/{}/app", base, id_esc);
                    // A protected paste was already unlocked by the POST that reached
                    // this render; pass the verified password to the app route through
                    // a hidden auto-submitting form (targets the same iframe) so the
                    // secret never appears in a URL (audit #F24). Public pastes use a
                    // plain iframe src.
                    let (frame, open_link, auth_form) = if paste.password_hash.is_none() {
                        (
                            format!(
                                "<iframe name=\"cryptirc-app\" title=\"Pasted app\" sandbox=\"{}\" referrerpolicy=\"no-referrer\" src=\"{}\"></iframe>",
                                PASTE_APP_SANDBOX, app_url
                            ),
                            format!(
                                "<a class=\"tab\" href=\"{}\" target=\"_blank\" rel=\"noopener\">open app</a>",
                                app_url
                            ),
                            String::new(),
                        )
                    } else {
                        (
                            format!(
                                "<iframe name=\"cryptirc-app\" title=\"Pasted app\" sandbox=\"{}\" referrerpolicy=\"no-referrer\"></iframe>",
                                PASTE_APP_SANDBOX
                            ),
                            String::new(),
                            format!(
                                "<form id=\"app-auth\" method=\"post\" action=\"{}\" target=\"cryptirc-app\"><input type=\"hidden\" name=\"password\" value=\"{}\"></form>",
                                app_url, html_escape(pw)
                            ),
                        )
                    };
                    let raw_tab = raw_link("tab");
                    let toolbar = format!(
                        "<div class=\"toolbar\"><span><a href=\"{}/\">CryptIRC</a> Paste</span>\
                         <button class=\"tab active\" id=\"tab-app\" type=\"button\">App</button>\
                         <button class=\"tab\" id=\"tab-src\" type=\"button\">Source</button>{}{}\
                         <span class=\"spacer\"></span><span class=\"meta\">{}</span></div>",
                        base, open_link, raw_tab, meta
                    );
                    (
                        format!("{}{}", PASTE_BASE_CSS, PASTE_APP_CSS),
                        format!(
                            "{}<div class=\"pane\" id=\"pane-app\">{}</div><div id=\"pane-src\"><pre>{}</pre></div>{}{}",
                            toolbar, frame, escaped, auth_form, scripts
                        ),
                    )
                }
            };
            let mut resp = Html(format!(
                "<!DOCTYPE html><html><head><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>CryptIRC Paste — {}</title><style>{}</style></head><body>{}</body></html>",
                id_esc, style, body
            )).into_response();
            let has_page_scripts = page_scripts.is_some();
            if let Some(nonce) = page_scripts {
                resp.extensions_mut().insert(nonce);
            }
            if paste.content_type == paste::PasteKind::Markdown {
                // rust-content LOW: rendered Markdown (user-authored <img>/links) runs
                // in an opaque-origin, script-less sandbox instead of the app origin.
                resp.headers_mut().insert(HeaderName::from_static(PASTE_SANDBOX_DOC_MARKER), HeaderValue::from_static("1"));
            }
            if is_protected || has_page_scripts {
                // Protected forms carry the password. Script nonces are per response.
                resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
            }
            resp
        }
        Ok(None) => (StatusCode::NOT_FOUND, Html("Paste not found or expired.".to_string())).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Html("Error loading paste.".to_string())).into_response(),
    }
}

async fn route_paste_raw(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // rust-http #9: like the view/app routes (#F24), the raw route no longer takes
    // `?password=` from the URL (it leaked into proxy logs / history / Referer). A
    // protected paste's raw text is reached via the POST below (the unlocked page's
    // "raw" button) or, for scripts, an `X-Paste-Password` request header.
    let pw = headers.get(PASTE_PASSWORD_HEADER).and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
    paste_raw_response(&state, &id, &headers, &pw).await
}

async fn route_paste_raw_post(
    State(state): State<AppState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> impl IntoResponse {
    let pw = form.get("password").map(|s| s.as_str()).unwrap_or("");
    paste_raw_response(&state, &id, &headers, pw).await
}

/// Header a script may use to unlock a protected paste's raw text (never the URL).
const PASTE_PASSWORD_HEADER: &str = "x-paste-password";

async fn paste_raw_response(state: &AppState, id: &str, headers: &HeaderMap, pw: &str) -> axum::response::Response {
    // #19/#45: rate-limit raw view per IP (see render_paste).
    if state.auth.check_ip_rate_limit("paste_view", client_ip(headers).as_deref()).is_err() {
        return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response();
    }
    match state.paste_store.get(id).await {
        Ok(Some(paste)) => {
            if paste.password_hash.is_some() {
                if pw.is_empty() {
                    return (StatusCode::FORBIDDEN, "Password required").into_response();
                }
                // Unauthenticated + 64-MiB Argon2id derive: rate-limit per client
                // IP before the derive and run the derive off the async workers.
                if state.auth.check_ip_rate_limit("paste_unlock", client_ip(headers).as_deref()).is_err() {
                    return (StatusCode::TOO_MANY_REQUESTS, "Too many attempts").into_response();
                }
                // NEW-2: through the shared auth-KDF cap (bounded concurrency + memory),
                // not an uncapped spawn_blocking; None = no slot → 503.
                let verify_ok = match paste_password_ok(&paste, pw).await {
                    Some(ok) => ok,
                    None => return (StatusCode::SERVICE_UNAVAILABLE, "Server busy — please try again in a moment.").into_response(),
                };
                if !verify_ok {
                    return (StatusCode::FORBIDDEN, "Password required").into_response();
                }
            }
            let mut resp = ([(axum::http::header::CONTENT_TYPE, "text/plain; charset=utf-8")], paste.content).into_response();
            if paste.password_hash.is_some() {
                // Unlocked protected content must not linger in shared caches.
                resp.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(NO_CACHE));
            }
            resp
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
    // #44: propagate serialization/write failures with a 500 instead of returning a
    // success id that later 404s (the file may never have been written).
    let body = match serde_json::to_string(&data) {
        Ok(b) => b,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"Failed to create short link"}))).into_response(),
    };
    if tokio::fs::write(format!("{}/{}.json", dir, id), body).await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error":"Failed to create short link"}))).into_response();
    }
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
                    // #44: re-validate the scheme at redirect time (defense in depth) — a
                    // stored `javascript:`/`data:` URL must never reach an href even if a
                    // future write path failed to validate at creation.
                    if !url.starts_with("http://") && !url.starts_with("https://") {
                        return (StatusCode::NOT_FOUND, Html("Not found".to_string())).into_response();
                    }
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

// ─── X previews (rich X/Twitter cards) ──────────────────────────────────────
// Port of the community rich-X-previews reference. Every provider is OFF unless the
// operator sets its startup flag (INSTALL.md "X post preview provider"); with no flag
// set these routes answer locally and nothing contacts X or any third party.

/// The per-user /preview budget, shared by generic link previews and every X route.
fn preview_rate_ok(rates: &DashMap<String, (std::time::Instant, u32)>, username: &str) -> bool {
    let now = std::time::Instant::now();
    let mut bucket = rates.entry(username.to_owned()).or_insert((now, 0));
    if now.duration_since(bucket.0) > std::time::Duration::from_secs(PREVIEW_RATE_WINDOW_SECS) {
        *bucket = (now, 1);
    } else {
        bucket.1 = bucket.1.saturating_add(1);
    }
    bucket.1 <= PREVIEW_RATE_MAX
}

/// Max simultaneous signed-media fallback streams, process-wide.
const MEDIA_PROXY_MAX_STREAMS: usize = 16;
/// Max simultaneous fallback streams per account (signatures are bound to the account).
const MEDIA_PROXY_MAX_STREAMS_PER_ACCOUNT: usize = 3;
/// Signed fallback URLs live this long (seconds).
const MEDIA_SIGN_TTL_SECS: i64 = 900;
/// Hard byte cap per proxied response.
const MAX_MEDIA_PROXY_BYTES: u64 = 128 * 1024 * 1024;
/// DNS resolution, connect and the upstream response headers must all complete within this
/// (one deadline around the whole fetch, so a stalled resolver can't hold stream slots).
const MEDIA_PROXY_HEADER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(12);
/// Longest stall (upstream not sending, or the client not reading), and longest stream.
const MEDIA_PROXY_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const MEDIA_PROXY_MAX_DURATION: std::time::Duration = std::time::Duration::from_secs(300);

/// Per-stream bounds of the media fallback (overridable in tests).
#[derive(Clone, Copy, Debug)]
struct MediaLimits {
    headers: std::time::Duration,
    max_duration: std::time::Duration,
    idle: std::time::Duration,
    per_account: usize,
}
impl Default for MediaLimits {
    fn default() -> Self {
        Self {
            headers: MEDIA_PROXY_HEADER_TIMEOUT,
            max_duration: MEDIA_PROXY_MAX_DURATION,
            idle: MEDIA_PROXY_IDLE_TIMEOUT,
            per_account: MEDIA_PROXY_MAX_STREAMS_PER_ACCOUNT,
        }
    }
}

fn media_stream_permits() -> Arc<Semaphore> {
    static PERMITS: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
    PERMITS.get_or_init(|| Arc::new(Semaphore::new(MEDIA_PROXY_MAX_STREAMS))).clone()
}

type MediaAccounts = Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>;
fn media_active_accounts() -> MediaAccounts {
    static ACTIVE: std::sync::OnceLock<MediaAccounts> = std::sync::OnceLock::new();
    ACTIVE.get_or_init(Default::default).clone()
}

fn media_upstream_http() -> Arc<dyn MediaUpstream> {
    static HTTP: std::sync::OnceLock<Arc<dyn MediaUpstream>> = std::sync::OnceLock::new();
    HTTP.get_or_init(|| Arc::new(HttpMediaUpstream)).clone()
}

#[derive(Clone)]
struct TweetRouteState {
    auth: Arc<AuthManager>,
    service: Arc<preview::PreviewService>,
    rates: Arc<DashMap<String, (std::time::Instant, u32)>>,
    base_path: String,
    media_streams: Arc<Semaphore>,
    media_accounts: MediaAccounts,
    media_upstream: Arc<dyn MediaUpstream>,
    media_limits: MediaLimits,
}

impl axum::extract::FromRef<AppState> for TweetRouteState {
    fn from_ref(state: &AppState) -> Self {
        Self {
            auth: state.auth.clone(),
            service: state.preview_service.clone(),
            rates: state.preview_rate.clone(),
            base_path: state.base_path.clone(),
            media_streams: media_stream_permits(),
            media_accounts: media_active_accounts(),
            media_upstream: media_upstream_http(),
            media_limits: MediaLimits::default(),
        }
    }
}

type TweetQuery = Result<
    Query<std::collections::HashMap<String, String>>,
    axum::extract::rejection::QueryRejection,
>;

fn tweet_session_user(state: &TweetRouteState, headers: &HeaderMap) -> Option<String> {
    bearer_token(headers).and_then(|token| state.auth.validate_session(&token))
}

fn private_tweet_response(mut response: Response) -> Response {
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    response.headers_mut().insert(header::VARY, HeaderValue::from_static("Authorization"));
    response
}

fn tweet_error_body(status: StatusCode, code: &str, retryable: bool, delay: Option<u64>) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({"schema_version":1,"error":{
            "code":code,"retryable":retryable,"retry_after_seconds":delay}})),
    )
        .into_response();
    if let Some(delay) = delay {
        if let Ok(value) = HeaderValue::from_str(&delay.max(1).to_string()) {
            response.headers_mut().insert(header::RETRY_AFTER, value);
        }
    }
    private_tweet_response(response)
}

fn tweet_unauthorized() -> Response {
    tweet_error_body(StatusCode::UNAUTHORIZED, "unauthorized", false, None)
}

fn tweet_error(error: twitter::PreviewError) -> Response {
    use twitter::PreviewError::*;
    let (status, code, retryable, delay) = match error {
        InvalidUrl => (StatusCode::BAD_REQUEST, "invalid_url", false, None),
        RateLimited(delay) => (StatusCode::TOO_MANY_REQUESTS, "rate_limited", true, Some(delay)),
        Busy => (StatusCode::SERVICE_UNAVAILABLE, "busy", true, None),
        Timeout => (StatusCode::SERVICE_UNAVAILABLE, "timeout", true, None),
        ProviderChanged => (StatusCode::SERVICE_UNAVAILABLE, "provider_changed", true, None),
        UpstreamFailure => (StatusCode::SERVICE_UNAVAILABLE, "upstream_failure", true, None),
    };
    tweet_error_body(status, code, retryable, delay)
}

/// What this server can offer right now, so a browser on an unconfigured install renders
/// plain links and makes no preview requests at all. Auth required; no upstream traffic.
async fn route_tweet_config(State(state): State<TweetRouteState>, headers: HeaderMap) -> Response {
    if tweet_session_user(&state, &headers).is_none() {
        return tweet_unauthorized();
    }
    let (preview, thread) = state.service.tweet_capabilities().await;
    private_tweet_response(
        Json(serde_json::json!({"schema_version":1,"preview":preview,"thread":thread})).into_response(),
    )
}

async fn route_tweet_preview(State(state): State<TweetRouteState>, headers: HeaderMap, params: TweetQuery) -> Response {
    route_x_operation(state, headers, params, false).await
}

async fn route_tweet_thread(State(state): State<TweetRouteState>, headers: HeaderMap, params: TweetQuery) -> Response {
    route_x_operation(state, headers, params, true).await
}

/// `GET /tweet/preview|thread?url=<status URL>[&refresh=1]`. Session and the shared
/// per-user budget are checked before anything else (including a cached result). Logs
/// stay coarse: never the URL, ID, token, text or provider body.
async fn route_x_operation(state: TweetRouteState, headers: HeaderMap, params: TweetQuery, thread: bool) -> Response {
    let Some(user) = tweet_session_user(&state, &headers) else {
        return tweet_unauthorized();
    };
    if !preview_rate_ok(&state.rates, &user) {
        return tweet_error(twitter::PreviewError::RateLimited(PREVIEW_RATE_WINDOW_SECS));
    }
    let Ok(Query(params)) = params else {
        return tweet_error(twitter::PreviewError::InvalidUrl);
    };
    if params.keys().any(|k| !matches!(k.as_str(), "url" | "refresh"))
        || params.get("refresh").is_some_and(|v| v != "1")
    {
        return tweet_error(twitter::PreviewError::InvalidUrl);
    }
    let Some(identity) = params.get("url").and_then(|v| twitter::parse_tweet_url(v)) else {
        return tweet_error(twitter::PreviewError::InvalidUrl);
    };
    let refresh = params.contains_key("refresh");
    let result = if thread {
        state.service.fetch_tweet_thread(&user, &identity.id, refresh).await
    } else {
        state.service.fetch_tweet_preview(&user, &identity.id, refresh).await
    };
    match result {
        Ok(preview) => private_tweet_response(Json(preview.as_ref()).into_response()),
        Err(error) => tweet_error(error),
    }
}

fn media_sign_key() -> &'static [u8; 32] {
    // Per-process random key: a restart invalidates every outstanding signed URL.
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    KEY.get_or_init(rand::random)
}

/// Opaque, per-process subject for an account: binds a signed URL to the account that
/// asked for it (per-account stream cap) without putting the username in the URL.
fn media_subject(username: &str) -> String {
    use base64::Engine as _;
    use hmac::Mac;
    let Ok(mut mac) = hmac::Hmac::<sha2::Sha256>::new_from_slice(media_sign_key()) else {
        return String::new();
    };
    mac.update(b"subject\n");
    mac.update(username.to_lowercase().as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mac.finalize().into_bytes()[..12])
}

fn media_mac(expires: i64, subject: &str, normalized: &str) -> Option<hmac::Hmac<sha2::Sha256>> {
    use hmac::Mac;
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(media_sign_key()).ok()?;
    mac.update(format!("media\n{expires}\n{subject}\n{normalized}").as_bytes());
    Some(mac)
}

#[derive(Deserialize)]
struct MediaSignRequest {
    urls: Vec<String>,
}

#[derive(Serialize)]
struct MediaSignedUrl {
    url: String,
    proxy_url: String,
}

/// Sign one recognized X CDN asset (twitter::validate_proxy_media_url) for the
/// same-origin fallback, bound to `subject` (media_subject of the requesting account).
/// Returns (normalized URL, proxy path+query, expiry).
fn sign_media_path(base_path: &str, raw: &str, subject: &str) -> Option<(String, String, i64)> {
    use base64::Engine as _;
    use hmac::Mac;
    if subject.is_empty() {
        return None;
    }
    let (normalized, _) = twitter::validate_proxy_media_url(raw)?;
    let expires = chrono::Utc::now().timestamp() + MEDIA_SIGN_TTL_SECS;
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(media_mac(expires, subject, &normalized)?.finalize().into_bytes());
    let mut proxy = reqwest::Url::parse("https://media.invalid/").ok()?;
    proxy.set_path(&format!("{}/tweet/media", base_path.trim_end_matches('/')));
    proxy
        .query_pairs_mut()
        .append_pair("url", &normalized)
        .append_pair("exp", &expires.to_string())
        .append_pair("a", subject)
        .append_pair("sig", &sig);
    Some((normalized, format!("{}?{}", proxy.path(), proxy.query().unwrap_or("")), expires))
}

/// Verify a signed fallback URL (constant-time MAC check, expiry window, recognized
/// asset). Returns the normalized URL and its media kind.
fn verify_media_signature(
    raw: &str,
    expires: i64,
    subject: &str,
    sig: &str,
) -> Option<(String, twitter::ProxyMediaKind)> {
    use base64::Engine as _;
    use hmac::Mac;
    let now = chrono::Utc::now().timestamp();
    if expires < now
        || expires > now + MEDIA_SIGN_TTL_SECS + 60
        || sig.len() > 64
        || subject.is_empty()
        || subject.len() > 32
    {
        return None;
    }
    let (normalized, kind) = twitter::validate_proxy_media_url(raw)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(sig).ok()?;
    media_mac(expires, subject, &normalized)?.verify_slice(&decoded).ok()?;
    Some((normalized, kind))
}

/// `POST /tweet/media/sign {urls:[…≤16]}` → short-lived same-origin URLs for assets
/// whose direct CDN load failed (privacy extensions block third-party twimg requests).
/// Session, shared budget, current admin policy + configured provider, recognized
/// asset paths, and "this viewer retrieved these assets" are all required.
async fn route_tweet_media_sign(
    State(state): State<TweetRouteState>,
    headers: HeaderMap,
    body: Result<Json<MediaSignRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Some(user) = tweet_session_user(&state, &headers) else {
        return tweet_unauthorized();
    };
    if !preview_rate_ok(&state.rates, &user) {
        return tweet_error(twitter::PreviewError::RateLimited(PREVIEW_RATE_WINDOW_SECS));
    }
    let Ok(Json(body)) = body else {
        return tweet_error(twitter::PreviewError::InvalidUrl);
    };
    if body.urls.is_empty() || body.urls.len() > 16 {
        return tweet_error(twitter::PreviewError::InvalidUrl);
    }
    if !state.service.tweet_media_allowed().await {
        return tweet_error_body(StatusCode::FORBIDDEN, "provider_disabled", false, None);
    }
    let subject = media_subject(&user);
    let mut urls = Vec::with_capacity(body.urls.len());
    let mut keys = Vec::with_capacity(body.urls.len());
    for raw in &body.urls {
        let Some((url, proxy_url, _)) = sign_media_path(&state.base_path, raw, &subject) else {
            return tweet_error(twitter::PreviewError::InvalidUrl);
        };
        let Some(key) = twitter::media_asset_key(&url) else {
            return tweet_error(twitter::PreviewError::InvalidUrl);
        };
        keys.push(key);
        urls.push(MediaSignedUrl { url, proxy_url });
    }
    if !state.service.tweet_media_retrieved(&user, &keys) {
        return tweet_error_body(StatusCode::FORBIDDEN, "not_retrieved", false, None);
    }
    private_tweet_response(
        Json(serde_json::json!({"urls": urls, "expires_in": MEDIA_SIGN_TTL_SECS})).into_response(),
    )
}

type MediaChunk = Result<axum::body::Bytes, std::io::Error>;
type MediaBodyStream = futures_util::stream::BoxStream<'static, MediaChunk>;

/// One upstream media response: status, the headers the fallback may forward, and the
/// body as a stream that only the pump task (below) ever polls.
struct UpstreamMedia {
    status: u16,
    content_type: Option<String>,
    content_length: Option<u64>,
    content_range: Option<String>,
    accept_ranges: Option<String>,
    etag: Option<String>,
    last_modified: Option<String>,
    body: MediaBodyStream,
}

type MediaFetchFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Result<UpstreamMedia, ()>> + Send>>;

/// Where the fallback gets bytes from. Production: pinned HTTPS to the exact CDN host;
/// tests substitute a local stream so no test ever resolves or contacts a CDN.
trait MediaUpstream: Send + Sync {
    fn fetch(&self, target: String, kind: twitter::ProxyMediaKind, range: Option<String>) -> MediaFetchFuture;
}

struct HttpMediaUpstream;
impl MediaUpstream for HttpMediaUpstream {
    fn fetch(&self, target: String, kind: twitter::ProxyMediaKind, range: Option<String>) -> MediaFetchFuture {
        Box::pin(async move {
            let host = reqwest::Url::parse(&target).ok().and_then(|u| u.host_str().map(str::to_owned)).ok_or(())?;
            let addrs = preview::resolve_and_validate_host(&host, Some(443)).await.map_err(|_| ())?;
            let client = preview::build_pinned_media_client(&host, &addrs).map_err(|_| ())?;
            // No cookies, credentials or Referer are ever attached; redirects are refused.
            let mut request = client.get(&target).header(header::ACCEPT, match kind {
                twitter::ProxyMediaKind::Image => "image/avif,image/webp,image/png,image/jpeg,image/gif",
                twitter::ProxyMediaKind::Mp4 => "video/mp4",
            });
            if let Some(range) = &range {
                request = request.header(header::RANGE, range);
            }
            // (Bounded, together with DNS and connect, by the caller's MediaLimits::headers.)
            let response = request.send().await.map_err(|_| ())?;
            let get = |name: header::HeaderName| {
                response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned)
            };
            let (content_type, content_range, accept_ranges, etag, last_modified) = (
                get(header::CONTENT_TYPE),
                get(header::CONTENT_RANGE),
                get(header::ACCEPT_RANGES),
                get(header::ETAG),
                get(header::LAST_MODIFIED),
            );
            let status = response.status().as_u16();
            let content_length = response.content_length();
            let body = futures_util::stream::unfold(Some(response), |slot| async move {
                let mut response = slot?;
                match response.chunk().await {
                    Ok(Some(chunk)) => Some((Ok(chunk), Some(response))),
                    Ok(None) => None,
                    Err(_) => Some((Err(std::io::Error::other("media upstream failed")), None)),
                }
            });
            Ok(UpstreamMedia {
                status,
                content_type,
                content_length,
                content_range,
                accept_ranges,
                etag,
                last_modified,
                body: Box::pin(body),
            })
        })
    }
}

/// One slot of the per-account fallback stream cap; released on drop.
struct MediaAccountSlot {
    accounts: MediaAccounts,
    subject: String,
}
impl Drop for MediaAccountSlot {
    fn drop(&mut self) {
        let mut accounts = self.accounts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = accounts.get_mut(&self.subject) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                accounts.remove(&self.subject);
            }
        }
    }
}
fn media_account_slot(accounts: &MediaAccounts, subject: &str, limit: usize) -> Option<MediaAccountSlot> {
    let mut map = accounts.lock().unwrap_or_else(|e| e.into_inner());
    let count = map.entry(subject.to_owned()).or_insert(0);
    if *count >= limit {
        return None;
    }
    *count += 1;
    Some(MediaAccountSlot { accounts: accounts.clone(), subject: subject.to_owned() })
}

/// Everything a running fallback stream holds; dropping it frees the global stream
/// permit and the account slot.
struct MediaStreamGuards {
    _permit: tokio::sync::OwnedSemaphorePermit,
    _slot: MediaAccountSlot,
}

/// Aborts the pump when the response body is dropped (client gone).
struct AbortPump(tokio::task::JoinHandle<()>);
impl Drop for AbortPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Stream `upstream` to the client through a spawned pump task that owns the upstream
/// body and the guards. The pump enforces the byte cap, the idle bound (upstream silent
/// OR the client not reading for `idle`) and the total deadline on its own timers, so a
/// client that stops reading cannot hold an upstream connection, a global permit or an
/// account slot past the deadline. The body ends (truncated) when the pump stops.
fn media_pump_body(upstream: MediaBodyStream, guards: MediaStreamGuards, limits: MediaLimits) -> Body {
    let (tx, rx) = tokio::sync::mpsc::channel::<MediaChunk>(4);
    let pump = tokio::spawn(async move {
        let _guards = guards;
        let mut upstream = upstream;
        let deadline = tokio::time::sleep(limits.max_duration);
        tokio::pin!(deadline);
        let mut total = 0u64;
        loop {
            let next = tokio::select! {
                _ = &mut deadline => break,
                next = tokio::time::timeout(limits.idle, upstream.next()) => next,
            };
            let chunk = match next {
                Ok(Some(Ok(chunk))) => chunk,
                Ok(None) => break,
                Ok(Some(Err(_))) | Err(_) => break,
            };
            total = total.saturating_add(chunk.len() as u64);
            if total > MAX_MEDIA_PROXY_BYTES {
                break;
            }
            let sent = tokio::select! {
                _ = &mut deadline => false,
                sent = tokio::time::timeout(limits.idle, tx.send(Ok(chunk))) => matches!(sent, Ok(Ok(()))),
            };
            if !sent {
                break; // client gone, or not reading for `idle`
            }
        }
        // Dropping `upstream` and `_guards` here closes the CDN connection and frees the
        // global permit and the account slot; dropping `tx` ends the client body.
    });
    let body = futures_util::stream::unfold((rx, AbortPump(pump)), |(mut rx, pump)| async move {
        let item = rx.recv().await?;
        Some((item, (rx, pump)))
    });
    Body::from_stream(body)
}

/// `GET /tweet/media?url&exp&a&sig` — stream one signed CDN asset on our origin. No
/// session token in the URL: the HMAC binds the exact normalized URL, the expiry and the
/// requesting account's opaque subject (`a`), which the per-account stream cap uses.
async fn route_tweet_media(State(state): State<TweetRouteState>, headers: HeaderMap, params: TweetQuery) -> Response {
    let Ok(Query(params)) = params else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if params.keys().any(|k| !matches!(k.as_str(), "url" | "exp" | "a" | "sig")) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (Some(raw), Some(expires), Some(subject), Some(sig)) = (
        params.get("url"),
        params.get("exp").and_then(|v| v.parse::<i64>().ok()),
        params.get("a"),
        params.get("sig"),
    ) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some((target, kind)) = verify_media_signature(raw, expires, subject, sig) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let range = match headers.get(header::RANGE) {
        None => None,
        Some(value) => match value.to_str() {
            Ok(v) if twitter::valid_media_range(v) => Some(v.to_owned()),
            _ => return StatusCode::RANGE_NOT_SATISFIABLE.into_response(),
        },
    };
    // Re-check the admin policy / provider configuration at redemption time.
    if !state.service.tweet_media_allowed().await {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(slot) = media_account_slot(&state.media_accounts, subject, state.media_limits.per_account) else {
        let mut response = StatusCode::TOO_MANY_REQUESTS.into_response();
        response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        return response;
    };
    let Ok(permit) = state.media_streams.clone().try_acquire_owned() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let guards = MediaStreamGuards { _permit: permit, _slot: slot };
    // Audit fix: one deadline around DNS + connect + response headers; the slots held by
    // `guards` are released when it fires (the fetch future is dropped).
    let upstream = match tokio::time::timeout(
        state.media_limits.headers,
        state.media_upstream.fetch(target, kind, range.clone()),
    )
    .await
    {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(())) => return StatusCode::BAD_GATEWAY.into_response(),
        Err(_) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
    };
    if upstream.status == 416 {
        let mut response = StatusCode::RANGE_NOT_SATISFIABLE.into_response();
        if let Some(value) = upstream.content_range.as_deref().and_then(|v| HeaderValue::from_str(v).ok()) {
            response.headers_mut().insert(header::CONTENT_RANGE, value);
        }
        return response;
    }
    // A server may ignore Range (200 is fine); a 206 nobody asked for is not.
    if !matches!(upstream.status, 200 | 206) || (upstream.status == 206 && range.is_none()) {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    // Explicit MIME allowlist: an image asset must be a raster image, an MP4 asset must
    // be video/mp4. HTML, SVG, playlists and mismatches never reach the browser.
    let Some(content_type) = twitter::proxy_content_type(kind, upstream.content_type.as_deref()) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if upstream.content_length.is_some_and(|n| n > MAX_MEDIA_PROXY_BYTES) {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let mut builder = Response::builder()
        .status(if upstream.status == 206 { StatusCode::PARTIAL_CONTENT } else { StatusCode::OK })
        .header(header::CONTENT_TYPE, content_type);
    if let Some(length) = upstream.content_length {
        builder = builder.header(header::CONTENT_LENGTH, length);
    }
    for (name, value) in [
        (header::CONTENT_RANGE, &upstream.content_range),
        (header::ETAG, &upstream.etag),
        (header::LAST_MODIFIED, &upstream.last_modified),
    ] {
        if let Some(value) = value.as_deref().and_then(|v| HeaderValue::from_str(v).ok()) {
            builder = builder.header(name, value);
        }
    }
    if upstream.accept_ranges.as_deref().is_some_and(|v| v.eq_ignore_ascii_case("bytes")) {
        builder = builder.header(header::ACCEPT_RANGES, "bytes");
    }
    builder = builder
        // Audit fix: never cacheable. A cached copy would outlive an admin revocation (the
        // redemption checks run per request) and the signature's own expiry.
        .header(header::CACHE_CONTROL, "private, no-store")
        .header("cross-origin-resource-policy", "same-origin")
        .header(header::CONTENT_DISPOSITION, "inline")
        // Ask security_headers_mw for the extra `sandbox` CSP (opaque origin, no script)
        // in case the asset URL is ever opened as a document.
        .header(PASTE_SANDBOX_DOC_MARKER, "1");
    match builder.body(media_pump_body(upstream.body, guards, state.media_limits)) {
        Ok(response) => response,
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
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
            // NEW-4 / http #13: the URL came from someone's chat, and reqwest's error text
            // embeds the FULL URL (path + query). Log only the host and the error class.
            info!("[preview] fetch failed for host {}: {}", preview_log_host(&url), preview_error_class(&e));
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Preview unavailable"}))).into_response()
        }
    }
}

/// Host part of a chat URL for logging (never the path/query). "?" if unparseable.
fn preview_log_host(url: &str) -> String {
    reqwest::Url::parse(url).ok()
        .and_then(|u| u.host_str().map(|h| h.chars().take(253).collect()))
        .unwrap_or_else(|| "?".to_string())
}

/// A URL-free description of a preview failure. reqwest errors are reduced to their
/// class (their Display carries the request URL); our own errors (bail! in preview.rs)
/// never contain the URL and are kept as-is.
fn preview_error_class(e: &anyhow::Error) -> String {
    if let Some(re) = e.downcast_ref::<reqwest::Error>() {
        let class = if re.is_timeout() { "timeout" } else if re.is_connect() { "connect error" }
            else if re.is_redirect() { "redirect error" } else if re.is_body() { "body error" }
            else if re.is_decode() { "decode error" } else if re.is_request() { "request error" }
            else if let Some(s) = re.status() { return format!("HTTP {}", s.as_u16()); }
            else { "network error" };
        return class.to_string();
    }
    e.to_string()
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
    save_preview_settings(&state, body).await
}

async fn save_preview_settings(state: &AppState, body: preview::PreviewSettings) -> axum::response::Response {
    // Load existing admin settings and merge preview settings — under lock
    let _guard = state.admin_settings_lock.lock().await;
    let path = std::path::PathBuf::from(&state.data_dir).join("admin_settings.json");
    let mut existing: serde_json::Value = match tokio::fs::read_to_string(&path).await {
        Ok(json) => match serde_json::from_str(&json) {
            Ok(v) => v,
            // #17: file present but UNPARSEABLE — refuse to overwrite, or we would drop
            // registration_open/captcha/etc. and silently re-open registration on boot.
            Err(e) => {
                drop(_guard);
                tracing::error!("admin_settings.json present but unparseable; refusing to overwrite: {}", e);
                return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Failed to save settings"}))).into_response();
            }
        },
        Err(_) => serde_json::json!({}),
    };
    existing["link_preview_mode"] = serde_json::json!(body.mode);
    existing["link_preview_whitelist"] = serde_json::json!(body.whitelist);
    if let Err(e) = write_secret_json_atomic(&path, &existing).await { // #30/#112
        drop(_guard);
        tracing::error!("failed to persist admin_settings.json: {}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"message":"Failed to save settings"}))).into_response();
    }
    drop(_guard);
    // New X policy generation now: drops cached X results the new policy may forbid.
    state.preview_service.update_tweet_policy().await;
    Json(serde_json::json!({"message":"Settings saved"})).into_response()
}

// ─── GIF picker (Giphy / Tenor) ───────────────────────────────────────────────

/// Tells the client which provider is active and how keys are sourced, WITHOUT
/// exposing any server key. server_available is true only when mode=="server" and
/// the active provider's shared key is configured (so the client may use the proxy).
/// Public news feed URL (a static file on the cryptirc.com site). Fixed ⇒ no SSRF.
const NEWS_FEED_URL: &str = "https://cryptirc.com/news/news.json";
const NEWS_MAX_BYTES: usize = 256 * 1024;
const NEWS_TTL_SECS: u64 = 45;  // short so site edits show in clients within ~1 min

/// r7 (codex P1 main.rs:4422): per-account requests to /api/news per window.
const NEWS_RATE_MAX: u32 = 30;
const NEWS_RATE_WINDOW_SECS: u64 = 60;
/// After a failed refresh the origin is not asked again for this long (doubling per further
/// failure up to NEWS_BACKOFF_MAX_SECS); the stale copy is served meanwhile.
const NEWS_BACKOFF_MIN_SECS: u64 = 15;
const NEWS_BACKOFF_MAX_SECS: u64 = 300;

/// The single refresh slot: held while one request fetches the feed, plus the failure
/// backoff it leaves behind.
#[derive(Default)]
struct NewsRefresh { fail_streak: u32, retry_at: Option<std::time::Instant> }
fn news_refresh_slot() -> &'static tokio::sync::Mutex<NewsRefresh> {
    static R: std::sync::OnceLock<tokio::sync::Mutex<NewsRefresh>> = std::sync::OnceLock::new();
    R.get_or_init(Default::default)
}
fn news_rate() -> &'static DashMap<String, (std::time::Instant, u32)> {
    static M: std::sync::OnceLock<DashMap<String, (std::time::Instant, u32)>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}
fn news_rate_ok(user: &str) -> bool {
    news_rate_check(news_rate(), user, std::time::Instant::now(), std::time::Duration::from_secs(NEWS_RATE_WINDOW_SECS), NEWS_RATE_MAX)
}
/// r8 (agy P1 main.rs:4426): past this many entries the map drops every entry whose window is
/// over (such an entry would be reset on its next use anyway), so it holds roughly the accounts
/// active in the last window instead of every account that ever read the news.
const NEWS_RATE_PRUNE_ABOVE: usize = 1024;
fn news_rate_check(map: &DashMap<String, (std::time::Instant, u32)>, user: &str, now: std::time::Instant, window: std::time::Duration, max: u32) -> bool {
    if map.len() > NEWS_RATE_PRUNE_ABOVE {
        map.retain(|_, (start, _)| now.saturating_duration_since(*start) <= window);
    }
    let mut e = map.entry(user.to_string()).or_insert((now, 0));
    let (start, count) = &mut *e;
    if now.saturating_duration_since(*start) > window { *start = now; *count = 0; }
    *count += 1;
    *count <= max
}

/// The cached feed, refreshed by at most ONE fetch at a time (r7, codex P1 main.rs:4422):
/// - a fresh copy (younger than `ttl`) is served as is;
/// - otherwise the first request takes the refresh slot and fetches; requests arriving while
///   it runs get the stale copy at once, or — with nothing cached yet — wait for that one
///   fetch instead of starting their own;
/// - a failed fetch keeps the stale copy and starts a backoff (NEWS_BACKOFF_MIN_SECS,
///   doubling, at most NEWS_BACKOFF_MAX_SECS) during which the origin is not asked.
/// None = no copy at all (the caller answers 502).
async fn news_serve<F, Fut>(
    cache: &tokio::sync::Mutex<Option<(String, std::time::Instant)>>,
    slot: &tokio::sync::Mutex<NewsRefresh>,
    ttl: std::time::Duration,
    fetch: F,
) -> Option<String>
where F: FnOnce() -> Fut, Fut: std::future::Future<Output = Option<String>> {
    let cached = |c: &Option<(String, std::time::Instant)>| c.as_ref().map(|(b, at)| (b.clone(), at.elapsed() < ttl));
    let stale = match cached(&*cache.lock().await) {
        Some((b, true)) => return Some(b),
        Some((b, false)) => Some(b),
        None => None,
    };
    let mut r = match slot.try_lock() {
        Ok(g) => g,
        Err(_) if stale.is_some() => return stale,   // a refresh is under way: serve the stale copy
        Err(_) => slot.lock().await,                  // nothing cached: wait for that refresh
    };
    // Refreshed by the request we waited for (or another) meanwhile?
    let now_cached = cached(&*cache.lock().await);
    if let Some((b, true)) = now_cached { return Some(b); }
    let stale = now_cached.map(|(b, _)| b);
    if r.retry_at.is_some_and(|t| std::time::Instant::now() < t) { return stale; }
    match fetch().await {
        Some(text) => {
            *cache.lock().await = Some((text.clone(), std::time::Instant::now()));
            r.fail_streak = 0;
            r.retry_at = None;
            Some(text)
        }
        None => {
            r.fail_streak = r.fail_streak.saturating_add(1);
            let secs = (NEWS_BACKOFF_MIN_SECS << (r.fail_streak - 1).min(5)).min(NEWS_BACKOFF_MAX_SECS);
            r.retry_at = Some(std::time::Instant::now() + std::time::Duration::from_secs(secs));
            stale
        }
    }
}

/// GET /api/news — server-side proxy + cache for the public news feed. The client only
/// talks to its own origin (CSP connect-src 'self'), so the server fetches the feed here,
/// caches it for NEWS_TTL_SECS, and serves it. On a fetch/parse failure a stale cached
/// copy is served if one exists (else 502). Auth-gated like the other /api routes.
/// r7: one refresh at a time with a failure backoff (news_serve), and NEWS_RATE_MAX
/// requests per account per NEWS_RATE_WINDOW_SECS (429 beyond).
async fn route_news(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let Some(user) = extract_session_user(&state, &headers) else {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"Unauthorized"}))).into_response();
    };
    if !news_rate_ok(&user) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many news requests — slow down"}))).into_response();
    }
    let json_ct = [(axum::http::header::CONTENT_TYPE, "application/json")];
    // Fetch: size-capped, JSON-validated (must have a `posts`/`releases` array) before caching.
    let client = state.gif_client.clone();
    let fetch = || async move {
        let resp = client.get(NEWS_FEED_URL)
            .timeout(std::time::Duration::from_secs(8)).send().await.ok()?;
        if !resp.status().is_success() { return None; }
        let bytes = resp.bytes().await.ok()?;
        if bytes.len() > NEWS_MAX_BYTES { return None; }
        let text = String::from_utf8(bytes.to_vec()).ok()?;
        let v: serde_json::Value = serde_json::from_str(&text).ok()?;
        // Accept the site-mirror shape (`posts`) or the legacy `releases` shape.
        if !(v.get("posts").is_some_and(|x| x.is_array()) || v.get("releases").is_some_and(|x| x.is_array())) { return None; }
        Some(text)
    };
    match news_serve(&state.news_cache, news_refresh_slot(), std::time::Duration::from_secs(NEWS_TTL_SECS), fetch).await {
        Some(text) => (json_ct, text).into_response(),
        None => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"news feed unavailable"}))).into_response(),
    }
}

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
    // #54: validate params BEFORE spending the per-user rate budget, so a malformed/empty
    // query (which we reject anyway) doesn't burn the user's GIF allowance.
    let q = params.get("q").map(|s| s.trim()).unwrap_or("");
    if q.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error":"Missing q"}))).into_response();
    }
    let q: String = q.chars().take(100).collect();
    if !state.gif_rate_ok(&user) {
        return (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":"Too many GIF requests — slow down"}))).into_response();
    }
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
    // #99/#44: cap the upstream body (a hostile/buggy/MITM'd provider must not stream
    // unbounded bytes into RAM). 4 MiB is generous for a GIF-search JSON response.
    // Reject up front on an oversized Content-Length, then read INCREMENTALLY via the
    // shared read_capped_body helper (chunk-wise) so we never buffer more than
    // MAX_GIF_BODY+1 bytes even when Content-Length is absent or understated.
    const MAX_GIF_BODY: usize = 4 * 1024 * 1024;
    if let Some(len) = resp.content_length() {
        if len > MAX_GIF_BODY as u64 {
            info!("[gif] {} response exceeded {} bytes", provider, MAX_GIF_BODY);
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response();
        }
    }
    let bytes = match preview::read_capped_body(resp, MAX_GIF_BODY + 1).await {
        Ok(b) if b.len() <= MAX_GIF_BODY => b,
        Ok(_) => { info!("[gif] {} response exceeded {} bytes", provider, MAX_GIF_BODY);
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response(); }
        Err(_) => return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error":"GIF search failed"}))).into_response(),
    };
    // reqwest's `json` feature isn't enabled in this build, so parse the text ourselves.
    let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));
    Json(serde_json::json!({ "results": normalize_gif_results(&provider, &body) })).into_response()
}

// ─── Push notification routes ─────────────────────────────────────────────────

async fn route_push_vapid_key(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({ "publicKey": state.notifier.vapid_public_key() }))
}

async fn route_push_subscribe(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<PushSubscription>) -> impl IntoResponse {
    let token = bearer_token(&headers).unwrap_or_default();
    match state.auth.validate_session(&token) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        // r4 C1-5: the session is checked again under the notifier's lock, after the
        // endpoint's DNS lookup — a reset that revoked it meanwhile wins. r9: under the shared
        // account lock too, and uncached, so a resetpass.sh run is not overtaken either.
        Some(user) => match state.notifier.save_subscription(&user, body, || state.auth.session_valid_now(&token, &user)).await {
            Ok(_)  => (StatusCode::OK, Json(Msg { message: "Subscribed".into() })).into_response(),
            Err(e) if e.to_string() == notifications::SUBSCRIBE_SESSION_GONE =>
                (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
            // r5 (codex P1 notifications.rs:1246): per-account admission before the DNS lookup.
            Err(e) if e.to_string() == notifications::SUBSCRIBE_BUSY =>
                (StatusCode::TOO_MANY_REQUESTS, Json(Msg { message: e.to_string() })).into_response(),
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
            // client_view(): the ignore/PM-Protection mirror is write-only (see notifications.rs)
            let prefs: NotifPrefs = state.notifier.load_prefs(&user).await;
            (StatusCode::OK, Json(prefs.client_view())).into_response()
        }
    }
}

async fn route_push_put_settings(State(state): State<AppState>, headers: HeaderMap, Json(body): Json<notifications::NotifPrefsPatch>) -> impl IntoResponse {
    // Partial update: fields absent from the body keep their stored value (so one
    // device's mute sync can't revert another device's trigger/enabled), and an old
    // client's full-object PUT behaves exactly as before. Over-cap lists get a 413
    // with a readable message the client shows.
    let token = bearer_token(&headers).unwrap_or_default();
    match state.auth.validate_session(&token) {
        None => (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
        // r4 C1-5: session re-checked under the notifier's lock (see route_push_subscribe).
        Some(user) => match state.notifier.update_prefs(&user, body, || state.auth.session_valid_now(&token, &user)).await {
            Ok(_)  => (StatusCode::OK, Json(Msg { message: "Settings saved".into() })).into_response(),
            Err(e @ notifications::PrefsUpdateError::TooLarge(_)) => (StatusCode::PAYLOAD_TOO_LARGE, Json(Msg { message: e.to_string() })).into_response(),
            Err(notifications::PrefsUpdateError::SessionGone) =>
                (StatusCode::UNAUTHORIZED, Json(Msg { message: "Not authenticated".into() })).into_response(),
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

/// F3/F4 (rust-ws2) + rust-http #7: hard TRANSPORT ceiling for one inbound WebSocket
/// message AND frame, enforced by tungstenite while it reads (so nothing larger is
/// ever buffered — the old axum/tungstenite defaults were 64 MiB / 16 MiB and the
/// 64 KiB check only ran on an already-assembled message). Sized to carry the largest
/// legitimate save — SaveStats' 2 MB payload, sent as a JSON string inside the JSON
/// frame, so quotes/newlines are escaped — with room to spare. Browsers never fragment,
/// so the frame cap must equal the message cap.
const WS_MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;

/// F14: bounded per-socket reply queue (VaultUnlocked/VaultError/oversize errors).
/// A reading client drains it as fast as it reads, and commands are rate-limited to
/// WS_MAX_CMDS_PER_SEC, so a legitimate client never gets near this; a socket whose
/// queue fills is not reading at all and is closed (it reconnects normally).
const WS_SOCKET_QUEUE: usize = 256;

/// v-srv-b NEW 1: the user's big snapshot replies (LoadNotepad / LoadStats /
/// LoadPasswords / LoadPreferences and the SavePreferences fan-out, up to 1-2 MB each
/// since F4) go through this small per-user broadcast ring instead of the 128-slot one.
/// A socket that stops reading used to pin up to 128 of them (~250 MiB per account).
/// Every one of these events is a full snapshot of its kind, so a lagging socket that
/// skips older ones (RecvError::Lagged) still ends on the newest copy.
/// r3 WS-8: one small ring PER KIND (Notepad / StatsData / PasswordSafe / Preferences),
/// WS_BULK_RING slots each — the same 8 slots in all as the former single mixed ring.
/// With one mixed ring a lagging socket could skip the only snapshot of one kind (its
/// own PasswordSafe reply behind 8 Preferences broadcasts) and never get that kind; now
/// a socket that lags only skips OLDER copies of the same kind.
const WS_BULK_RING: usize = 2;
const WS_BULK_KINDS: usize = 4;

/// v-srv-b NEW 1 / F3: a socket whose single outbound frame cannot be written for this
/// long (plus WS_SEND_MIN_RATE) is not reading — close it (the client reconnects and
/// resyncs). Bounds how long a non-reading socket can pin broadcast slots.
const WS_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// ... plus 1 ms per this many bytes (16 KB/s), so a slow-but-reading link still
/// receives a 2 MB snapshot — at most WS_SEND_TIMEOUT_MAX in all.
const WS_SEND_MIN_RATE_BYTES_PER_MS: usize = 16;
const WS_SEND_TIMEOUT_MAX: std::time::Duration = std::time::Duration::from_secs(300);

/// F3 (PARTIAL in round 1): the server sends a WebSocket Ping every 30 s (browsers,
/// Electron and the TUI answer with a Pong automatically), so a healthy socket always
/// delivers SOME frame well within this window. No frame for this long = a dead link
/// or a client holding a half-sent frame (tungstenite buffers it, up to
/// WS_MAX_FRAME_BYTES) — close it. Generous so a slow uplink can still finish a 2 MB
/// save frame (the Pong queues behind it).
const WS_IDLE_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(150);

/// F9: maximum comma-separated targets in one PRIVMSG/NOTICE. Each target costs a
/// log dir + file + an IrcEcho fan-out, so an unbounded list was a disk/inode DoS.
/// 20 is at or above every common ircd's TARGMAX/MAXTARGETS (ratbox/solanum/ergo 4,
/// InspIRCd 20), so no message a real server would accept is refused.
const MAX_SEND_TARGETS: usize = 20;

/// F5: at most this many parse-error lines per socket per minute reach the log.
const WS_PARSE_ERR_LOGS_PER_MIN: u32 = 3;

/// F4: commands whose handler enforces its OWN, explicit, error-reporting size cap
/// and may therefore arrive in a frame larger than WS_MAX_MSG_BYTES (up to
/// WS_MAX_FRAME_BYTES). Every other command keeps the 64 KiB per-message cap.
fn cmd_allows_large_frame(cmd: &ClientMessage) -> bool {
    matches!(cmd,
        ClientMessage::SaveNotepad { .. } | ClientMessage::SaveStats { .. }
        | ClientMessage::SavePasswords { .. } | ClientMessage::SavePreferences { .. }
        | ClientMessage::SaveBotConfig { .. } | ClientMessage::SaveAiKey { .. }
        | ClientMessage::E2ERewrapBlob { .. })
}

/// F2: the canonical spelling of a network id — validate_uuid's lower-case copy for a
/// UUID, the input unchanged otherwise (non-UUIDs fail every ownership check anyway).
pub(crate) fn canonical_network_id(id: &str) -> String {
    validate_uuid(id).unwrap_or_else(|| id.to_string())
}

/// F2: true for a syntactically valid network UUID that is NOT in canonical
/// (lower-case) form, i.e. a re-cased duplicate of a real id. The server only ever
/// generates lower-case ids, so no legitimate connection has such an id.
pub(crate) fn is_noncanonical_network_id(id: &str) -> bool {
    validate_uuid(id).map_or(false, |c| c != id)
}

/// F2: rewrite every network/conn id a client message carries into canonical form at
/// the trust boundary, so a re-cased spelling of a user's own id can never act as a
/// second, distinct conn_id (duplicate live IRC connections past the 20-network cap,
/// history split across `logs/<Variant>/`, invisible to RemoveNetwork).
fn canonicalize_cmd_ids(mut cmd: ClientMessage) -> ClientMessage {
    match &mut cmd {
        ClientMessage::UpdateNetwork { network } => network.id = canonical_network_id(&network.id),
        ClientMessage::RemoveNetwork { id }
        | ClientMessage::Connect { id }
        | ClientMessage::Disconnect { id, .. } => *id = canonical_network_id(id),
        ClientMessage::Send { conn_id, .. }
        | ClientMessage::React { conn_id, .. }
        | ClientMessage::KeepNick { conn_id, .. }
        | ClientMessage::ListChannels { conn_id, .. }
        | ClientMessage::JoinChannel { conn_id, .. }
        | ClientMessage::PartChannel { conn_id, .. }
        | ClientMessage::GetLogs { conn_id, .. }
        | ClientMessage::SearchLogs { conn_id, .. }
        | ClientMessage::Sync { conn_id, .. }
        | ClientMessage::GenerateCert { conn_id }
        | ClientMessage::DeleteCert { conn_id }
        | ClientMessage::GetCertInfo { conn_id }
        | ClientMessage::AiDo { conn_id, .. }
        | ClientMessage::BotQuery { conn_id, .. }
        | ClientMessage::ClearTargetLogs { conn_id, .. }
        | ClientMessage::SaveChannelOrder { conn_id, .. } => *conn_id = canonical_network_id(conn_id),
        // r6 (agy P1 main.rs:4759): the optional conn_id of the E2E lookups too (a
        // re-cased id was refused as "not this account's" by owns_conn).
        ClientMessage::E2EFetchBundle { conn_id: Some(conn_id), .. }
        | ClientMessage::E2ERelayX3DH { conn_id: Some(conn_id), .. } => *conn_id = canonical_network_id(conn_id),
        _ => {}
    }
    cmd
}

/// F9: number of non-empty comma-separated targets of an outgoing PRIVMSG/NOTICE
/// line (after an optional @tags / :source prefix); 1 for every other line, so it
/// doubles as the line's cost against the per-socket command budget.
/// r4 C2-2: parsed with OutgoingLine, the SAME grammar the Send handler's log/echo loop
/// uses (params separated by RUNS of spaces). The old `splitn(3, ' ')` read
/// `PRIVMSG  #a,#b,… :x` (two spaces) as an empty target list = 1, so a single frame
/// with thousands of targets passed both the 20-recipient cap and the command budget
/// while the loop logged + echoed every one of them. Callers pass the line exactly as
/// the handler will see it (strip_crlf'd).
fn send_target_count(raw: &str) -> usize {
    let out = OutgoingLine::parse(raw);
    if out.verb != "PRIVMSG" && out.verb != "NOTICE" { return 1; }
    out.params.first()
        .map_or(0, |t| t.split(',').filter(|t| !t.is_empty()).count())
        .max(1)
}

/// F9: a target worth logging/echoing: bounded length, no spaces/control chars.
/// (The line itself still goes to the server, which is the authority on names.)
fn is_plausible_target(t: &str) -> bool {
    !t.is_empty() && t.len() <= 200 && !t.chars().any(|c| c.is_control() || c == ' ')
}

/// F5: a log-safe summary of a WS frame parse error. serde's Display embeds the
/// client's own text (an unknown `type` value verbatim, up to the frame size, with
/// raw newlines → forged log lines) and the full list of expected variants. Keep only
/// the category, position and — for an unknown type — a short sanitised name.
fn ws_parse_error_summary(e: &serde_json::Error) -> String {
    let cat = match e.classify() {
        serde_json::error::Category::Io => "io",
        serde_json::error::Category::Syntax => "syntax",
        serde_json::error::Category::Data => "data",
        serde_json::error::Category::Eof => "eof",
    };
    let msg = e.to_string();
    let detail = if let Some(rest) = msg.strip_prefix("unknown variant `") {
        let name: String = rest.split('`').next().unwrap_or("")
            .chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-').take(40).collect();
        format!(" unknown type '{}'", name)
    } else if msg.starts_with("missing field `") {
        let name: String = msg["missing field `".len()..].split('`').next().unwrap_or("")
            .chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(40).collect();
        format!(" missing field '{}'", name)
    } else {
        String::new()
    };
    format!("{}{} at {}:{}", cat, detail, e.line(), e.column())
}

/// F8: crash-safe write of a per-user file: tmp (same dir) → fsync → rename over the
/// target → fsync the dir. A failed or interrupted write leaves the previous file
/// intact (tokio::fs::write truncates in place first). Errors are returned so the
/// caller can tell the user instead of pretending it saved.
async fn write_user_file_atomic(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!("{}.tmp.{}", name, Uuid::new_v4()));
    let res = async {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.flush().await?;
        f.sync_all().await?;
        drop(f);
        tokio::fs::rename(&tmp, path).await?;
        if let Some(dir) = path.parent() {
            if let Ok(d) = tokio::fs::File::open(dir).await { let _ = d.sync_all().await; }
        }
        Ok::<(), std::io::Error>(())
    }.await;
    if res.is_err() { let _ = tokio::fs::remove_file(&tmp).await; }
    res
}

/// F8: what a Load* handler found in one encrypted per-user file.
enum UserSecretLoad {
    Missing,
    Plain(String),
    /// The file exists but does not decrypt (torn write from before F8, disk error).
    /// It has been moved aside to `<name>.corrupt.<unix-ts>` so a later save can't
    /// destroy whatever is recoverable; the message names the backup.
    Undecryptable(String),
    /// The vault was locked underneath us — nothing touched.
    Locked,
}

async fn load_user_secret(state: &AppState, username: &str, file: &str) -> UserSecretLoad {
    let path = std::path::PathBuf::from(&state.data_dir).join("users").join(safe_username(username)).join(file);
    let Ok(enc) = tokio::fs::read_to_string(&path).await else { return UserSecretLoad::Missing };
    match state.crypto.decrypt(username, enc.trim()).await {
        Ok(pt) => UserSecretLoad::Plain(String::from_utf8_lossy(&pt).to_string()),
        Err(_) => {
            // A Lock in another tab makes decrypt fail without the file being bad —
            // never quarantine a good file for that.
            if !state.crypto.is_unlocked(username).await { return UserSecretLoad::Locked; }
            let label = match file {
                "notepad.enc" => "notepad",
                "passwords.enc" => "password safe",
                "stats.enc" => "channel stats",
                "preferences.enc" => "preferences",
                other => other,
            };
            let backup = path.with_file_name(format!("{}.corrupt.{}", file, chrono::Utc::now().timestamp()));
            match tokio::fs::rename(&path, &backup).await {
                Ok(()) => {
                    warn!("{}: {} did not decrypt — moved aside to {:?}", username, file, backup.file_name().unwrap_or_default());
                    UserSecretLoad::Undecryptable(format!(
                        "Your saved {} could not be decrypted (damaged file), so it is shown empty. The damaged copy was kept on the server as {}.",
                        label, backup.file_name().and_then(|n| n.to_str()).unwrap_or("")))
                }
                Err(e) => UserSecretLoad::Undecryptable(format!("Your saved {} could not be decrypted: {}", label, e)),
            }
        }
    }
}

async fn ws_handler(State(state): State<AppState>, headers: HeaderMap, ws: WebSocketUpgrade) -> impl IntoResponse {
    // #14: enforce the global + per-IP connection caps BEFORE upgrading, so a flood is
    // shed cheaply (503) without parking a task/FD on the unauth handshake.
    let Ok(permit) = ws_sem().try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "Server at capacity").into_response();
    };
    // #15: previously the per-IP cap lived inside `if let Some(ip)`, so header-less
    // connections (direct-to-:9001, or a proxy not forwarding IP headers) skipped the
    // per-IP cap entirely and were bounded only by the 4000 global cap — one source
    // could exhaust the pool for everyone. Collapse a missing IP into a shared "noip"
    // bucket so WS_MAX_PER_IP_CONNS always applies.
    let ip = client_ip(&headers).unwrap_or_else(|| "noip".to_string());
    {
        let mut c = ws_ip_counts().entry(ip.clone()).or_insert(0);
        if *c >= WS_MAX_PER_IP_CONNS {
            return (StatusCode::SERVICE_UNAVAILABLE, "Too many connections").into_response();
        }
        *c += 1;
    }
    let guard = WsConnGuard { _permit: permit, ip: Some(ip) };
    // r2 (E2E): browsers always send Origin on a WebSocket upgrade; the TUI (and other
    // native clients) don't. Only browser sockets can be a stale cached app.js.
    let browser = headers.contains_key(header::ORIGIN);
    // F3: bound what tungstenite will buffer for one message/frame (was 64/16 MiB).
    ws.max_message_size(WS_MAX_FRAME_BYTES)
        .max_frame_size(WS_MAX_FRAME_BYTES)
        .on_upgrade(move |socket| handle_ws(socket, state, guard, browser))
}

async fn handle_ws(socket: WebSocket, state: AppState, _conn_guard: WsConnGuard, browser: bool) {
    let (mut sender, mut receiver) = socket.split();

    // Demand auth as first message
    let _ = sender.send(Message::Text(serde_json::to_string(&ServerEvent::AuthRequired {}).unwrap())).await;

    // #14: shorter unauth handshake window (was 10s) — bound how long an anonymous
    // upgrade can hold the task/FD/permit before proving a valid session.
    let auth_msg = tokio::time::timeout(
        tokio::time::Duration::from_secs(5),
        receiver.next()
    ).await;

    // #5: retain the raw handshake token so each subsequent command can cheaply
    // re-validate the session. Validating only once at handshake left a
    // revoked/expired token with full access on an already-open socket.
    let (username, session_token, client_e2e_proto) = match auth_msg {
        // S6: bound the UNAUTHENTICATED handshake frame by the same WS_MAX_MSG_BYTES cap the
        // post-auth recv loop enforces — otherwise an anonymous client could send an up-to-
        // 64-MiB Text frame and force the allocation + serde_json parse before any auth.
        Ok(Some(Ok(Message::Text(txt)))) if txt.len() <= WS_MAX_MSG_BYTES => {
            match serde_json::from_str::<ClientMessage>(&txt) {
                Ok(ClientMessage::Auth { token, e2e }) => {
                    match state.auth.validate_session(&token) {
                        Some(u) => (u, token, e2e),
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
    // r2 (codex-p3 HIGH main.rs:4697 / v-e2e NEW-1): a browser socket that did not
    // announce the current E2E protocol is an outdated cached app.js.
    let legacy_web = browser && client_e2e_proto < 3;
    // r6 (codex P1 main.rs:4989): SUBSCRIBE FIRST, then re-validate the session (and with
    // it the account generation, r4 V3S-1) immediately before EVERY account-data snapshot
    // is built and written, and once more before anything is forwarded.
    //  - An account purge only sees sockets subscribed to the account's broadcasts
    //    (release_deleted_username counts these receivers): subscribed from the start, an
    //    in-progress handshake keeps a deleted name reserved until it is gone, so the name
    //    can't be registered again under a stalled handshake (r5 subscribed only after the
    //    snapshots, so a write stalled for up to WS_SEND_TIMEOUT_MAX left the purge blind).
    //  - A purge revokes the sessions first, so the check before each snapshot fails as soon
    //    as a deletion has begun — the snapshot of the NEXT part (built after a stalled
    //    write) is never computed for, or sent from, a later same-name account.
    //  - Every write is bounded like send_task's (ws_send_bounded, r5).
    // Track this session as active (non-idle) — increment BEFORE subscribing
    // so the IRC thread never sees receiver_count>0 with active_sessions==0
    let active_counter = state.active_counter(&username);
    active_counter.fetch_add(1, Ordering::Release);
    let mut event_rx = state.user_subscribe(&username);
    let [mut bulk_rx0, mut bulk_rx1, mut bulk_rx2, mut bulk_rx3] = user_bulk_subscribe(&username);
    // Undo the registration above and close (each expansion diverges with `return`).
    macro_rules! abort_handshake {
        ($why:expr) => {{
            if let Some(why) = $why {
                info!("[WS] closing a handshake of {}: {}", username, why);
            }
            drop((event_rx, bulk_rx0, bulk_rx1, bulk_rx2, bulk_rx3));
            active_counter.fetch_sub(1, Ordering::Release);
            user_bulk_prune(&username);
            return;
        }};
    }
    macro_rules! session_still_valid {
        () => {
            if !state.auth.session_valid_for(&session_token, &username) {
                abort_handshake!(Some("the session ended during the handshake (logout, deletion or expiry)"));
            }
        };
    }
    session_still_valid!();
    if !ws_send_bounded(&mut sender, serde_json::to_string(&ServerEvent::AuthOk { username: username.clone(), assets: frontend_id().to_string() }).unwrap()).await {
        abort_handshake!(None::<&str>);
    }
    session_still_valid!();
    let vault_unlocked = state.crypto.is_unlocked(&username).await;
    let state_snapshot = serde_json::to_string(&ServerEvent::State {
        networks: state.user_network_states(&username).await,
        vault_unlocked,
    }).unwrap();
    session_still_valid!();
    if !ws_send_bounded(&mut sender, state_snapshot).await { abort_handshake!(None::<&str>); }
    // An already-unlocked vault lets the browser resume with its own cached keys.
    // The socket has not verified a passphrase and receives no migration material.
    session_still_valid!();
    if vault_unlocked {
        let ev = e2e_vault_unlocked_event(&state, &username, false).await;
        session_still_valid!();
        if !ws_send_bounded(&mut sender, serde_json::to_string(&ev).unwrap()).await { abort_handshake!(None::<&str>); }
    }

    // Seed the Uploads channel with this user's persistent upload list.
    session_still_valid!();
    {
        let records = upload::list_all_records(&state.data_dir, &username).await;
        if !records.is_empty() {
            let upload_snapshot = serde_json::to_string(&ServerEvent::UploadState { records }).unwrap();
            session_still_valid!();
            if !ws_send_bounded(&mut sender, upload_snapshot).await { abort_handshake!(None::<&str>); }
        }
    }
    // r5: and once more before anything is forwarded from the broadcasts.
    session_still_valid!();
    let session_is_active = Arc::new(std::sync::atomic::AtomicBool::new(true));

    // #60: per-socket event channel for key material that must reach ONLY the
    // originating session (not every device subscribed to the user broadcast).
    // The send_task drains both the broadcast and this per-socket channel.
    // F14: bounded (was unbounded): a client that never reads stalls send_task and
    // every queued reply used to sit in process memory for as long as the socket
    // stayed open. Producers try_send; a full queue closes the socket (see recv_task).
    let (socket_tx, mut socket_rx) = tokio::sync::mpsc::channel::<ServerEvent>(WS_SOCKET_QUEUE);

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
        // v-srv-b NEW 1: every write is bounded (see WS_SEND_TIMEOUT) — a client that
        // stopped reading used to park this task in send() forever, pinning every
        // broadcast slot it hadn't consumed.
        macro_rules! send_text {
            ($s:expr) => {{
                let s: String = $s;
                let limit = (WS_SEND_TIMEOUT + std::time::Duration::from_millis((s.len() / WS_SEND_MIN_RATE_BYTES_PER_MS) as u64))
                    .min(WS_SEND_TIMEOUT_MAX);
                match tokio::time::timeout(limit, sender.send(Message::Text(s))).await {
                    Ok(Ok(())) => true,
                    Ok(Err(_)) => false,
                    Err(_) => { warn!("[WS] closing socket for {}: a frame could not be written for {:?} (client not reading)", user_sv, limit); false }
                }
            }};
        }
        // One bulk event (see WS_BULK_RING). Older snapshots skipped on Lagged: a newer one
        // of the SAME kind follows (each kind has its own ring).
        macro_rules! on_bulk {
            ($evt:expr) => {
                match $evt {
                    Ok(evt) => match serde_json::to_string(&evt) {
                        Ok(s)  => { if !send_text!(s) { break; } }
                        Err(_) => continue,
                    },
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed)    => break,
                }
            };
        }
        loop {
            tokio::select! {
                evt = event_rx.recv() => {
                    match evt {
                        // #103: serialize gracefully — a serialization regression in a
                        // future ServerEvent variant should skip that event, not panic
                        // and drop the socket.
                        Ok(evt) => match serde_json::to_string(&evt) {
                            Ok(s)  => { if !send_text!(s) { break; } }
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
                evt = bulk_rx0.recv() => { on_bulk!(evt) }
                evt = bulk_rx1.recv() => { on_bulk!(evt) }
                evt = bulk_rx2.recv() => { on_bulk!(evt) }
                evt = bulk_rx3.recv() => { on_bulk!(evt) }
                evt = socket_rx.recv() => {
                    // None = every per-socket sender is gone (recv side finished) and the
                    // queue is drained — e.g. after an explicit "message too large" error
                    // was queued just before closing — so the socket can close now.
                    let Some(evt) = evt else { break };
                    match serde_json::to_string(&evt) {
                        Ok(s)  => { if !send_text!(s) { break; } }
                        Err(_) => continue,
                    }
                }
                _ = revalidate.tick() => {
                    if !state_sv.auth.session_valid_for(&token_sv, &user_sv) { break; }
                    // F3: keepalive probe. Clients answer with a Pong (automatic in every
                    // browser / Electron / tungstenite), which the recv side counts as
                    // activity for WS_IDLE_READ_TIMEOUT.
                    match tokio::time::timeout(WS_SEND_TIMEOUT, sender.send(Message::Ping(Vec::new()))).await {
                        Ok(Ok(())) => {}
                        _ => break,
                    }
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
        // F5: per-socket throttle for the parse-error log line.
        let mut parse_log_window = tokio::time::Instant::now();
        let mut parse_logs_in_window: u32 = 0;
        let mut parse_logs_suppressed: u64 = 0;
        // r3 WW-2: inside a "lock burst" of this socket since… (see mark_lock_burst).
        let mut lock_burst: Option<tokio::time::Instant> = None;
        loop {
            // F3: bounded wait for the next frame (see WS_IDLE_READ_TIMEOUT). Any frame
            // counts — the Pong to our 30 s Ping included — so only a dead link or a
            // client holding a half-sent frame ever hits this.
            let frame = match tokio::time::timeout(WS_IDLE_READ_TIMEOUT, receiver.next()).await {
                Ok(Some(f)) => f,
                Ok(None) => break,
                Err(_) => {
                    info!("[WS] closing socket for {}: no frame for {:?}", user2, WS_IDLE_READ_TIMEOUT);
                    break;
                }
            };
            let msg = match frame {
                Ok(m) => m,
                Err(e) => {
                    // F3/F4: tungstenite refused a message/frame over WS_MAX_FRAME_BYTES
                    // without buffering it. Tell the client explicitly (protocol's
                    // existing `error` event) before the socket closes, instead of a
                    // silent drop. Other read errors just end the session as before.
                    let es = e.to_string();
                    if es.contains("Message too long") || es.contains("Space limit exceeded") {
                        let _ = socket_tx2.try_send(ServerEvent::Error { message: format!(
                            "Message too large: the server accepts at most {} MB per message, so it was not saved.",
                            WS_MAX_FRAME_BYTES / (1024 * 1024)) });
                        // The client is typically still uploading the rest of that frame.
                        // Closing at once (unread bytes pending) makes the kernel send a
                        // RST, and the client then discards the error frame unread. Keep
                        // the socket up briefly so send_task delivers it first.
                        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
                    }
                    break;
                }
            };
            if let Message::Text(ref text) = msg {
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
                        // r5 (codex P1 main.rs:5440): canonical network ids BEFORE any guard
                        // below looks at them (handle_command canonicalised only after the
                        // outdated-tab E2E guard, which then mis-read a re-cased id of the
                        // user's own network as "not this account's" and let it through).
                        let cmd = canonicalize_cmd_ids(cmd);
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
                        // F9: a multi-target PRIVMSG/NOTICE costs one budget unit per
                        // target (it logs + echoes once per target).
                        let cost = match &cmd {
                            // r4 C2-2: counted on the line as the Send handler sees it.
                            ClientMessage::Send { raw, .. } => send_target_count(&strip_crlf(raw)).min(MAX_SEND_TARGETS + 1) as u32,
                            _ => 1,
                        };
                        cmds_in_window = cmds_in_window.saturating_add(cost);
                        if cmds_in_window > WS_MAX_CMDS_PER_SEC {
                            // Over budget — drop silently to shed the flood.
                            continue;
                        }
                        // r3 WW-2: tag the disconnects of a manual vault lock.
                        let cmd = mark_lock_burst(cmd, &mut lock_burst, tokio::time::Instant::now());
                        // S6/F4: the 64 KiB cap still applies to every command except
                        // the saves whose handlers enforce (and report) their own larger
                        // caps — but an over-size message now gets an explicit error
                        // instead of vanishing (the client used to believe it saved).
                        if text.len() > WS_MAX_MSG_BYTES && !cmd_allows_large_frame(&cmd) {
                            let _ = socket_tx2.try_send(ServerEvent::Error { message: format!(
                                "Message too large ({} KB; max {} KB) — not processed.",
                                text.len() / 1024, WS_MAX_MSG_BYTES / 1024) });
                        } else if e2e_send_blocked(&state2, &user2, &socket_tx2, &cmd, legacy_web).await {
                            // The client has been told why the encrypted target was blocked.
                        } else {
                            handle_command(cmd, &user2, &state2, &socket_tx2, false).await;
                        }
                        // F14: a full reply queue means this client is not reading its
                        // socket at all — close it rather than queue without bound.
                        if socket_tx2.capacity() == 0 {
                            warn!("[WS] closing socket for {}: reply queue full (client not reading)", user2);
                            break;
                        }
                    }
                    Err(e) => {
                        // #73: do NOT log the message body on parse error — a near-valid
                        // UnlockVault{passphrase}/DeleteAccount{password} frame would leak
                        // the leading secret characters into journald.
                        // F5: nor serde's Display (it embeds client text verbatim, newlines
                        // included); and count bad frames against the same per-socket
                        // budget as commands, with the log line itself throttled.
                        let now = tokio::time::Instant::now();
                        if now.duration_since(window_start) >= std::time::Duration::from_secs(1) {
                            window_start = now;
                            cmds_in_window = 0;
                        }
                        cmds_in_window = cmds_in_window.saturating_add(1);
                        if cmds_in_window > WS_MAX_CMDS_PER_SEC { continue; }
                        if now.duration_since(parse_log_window) >= std::time::Duration::from_secs(60) {
                            if parse_logs_suppressed > 0 {
                                info!("[WS] {} more parse error(s) for {} suppressed", parse_logs_suppressed, user2);
                            }
                            parse_log_window = now;
                            parse_logs_in_window = 0;
                            parse_logs_suppressed = 0;
                        }
                        if parse_logs_in_window < WS_PARSE_ERR_LOGS_PER_MIN {
                            parse_logs_in_window += 1;
                            info!("[WS] parse error for {}: {} ({}B)", user2, ws_parse_error_summary(&e), text.len());
                        } else {
                            parse_logs_suppressed += 1;
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        _ = &mut send_task => recv_task.abort(),
        _ = &mut recv_task => {
            // The recv side is done (client closed, read error, or an explicit close
            // after an over-size message). Drop our per-socket sender so send_task can
            // flush anything still queued for THIS socket (e.g. that error) and exit
            // on its own; don't wait long for a client that isn't reading.
            drop(socket_tx);
            if tokio::time::timeout(tokio::time::Duration::from_secs(2), &mut send_task).await.is_err() {
                send_task.abort();
            }
        }
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
    // Both tasks are finished (or aborted and dropped) here, so this socket's bulk
    // receiver is gone; drop the user's bulk sender once no socket holds one.
    user_bulk_prune(&username);
}

/// r5 (codex P1 main.rs:4991): write one handshake frame with the same bound as
/// send_task's writes (WS_SEND_TIMEOUT + size / WS_SEND_MIN_RATE, at most
/// WS_SEND_TIMEOUT_MAX). False = not written in time (or the socket failed): close.
async fn ws_send_bounded(sender: &mut futures_util::stream::SplitSink<WebSocket, Message>, s: String) -> bool {
    let limit = (WS_SEND_TIMEOUT + std::time::Duration::from_millis((s.len() / WS_SEND_MIN_RATE_BYTES_PER_MS) as u64))
        .min(WS_SEND_TIMEOUT_MAX);
    match tokio::time::timeout(limit, sender.send(Message::Text(s))).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => { warn!("[WS] closing a handshake: a frame could not be written for {:?} (client not reading)", limit); false }
    }
}

/// v-srv-b NEW 1: per-user broadcasts for the big snapshot replies (see WS_BULK_RING):
/// one small ring per kind (r3 WS-8).
type BulkSenders = [broadcast::Sender<ServerEvent>; WS_BULK_KINDS];
fn user_bulk_events() -> &'static DashMap<String, BulkSenders> {
    static M: std::sync::OnceLock<DashMap<String, BulkSenders>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}
/// r3 WS-8: the ring a snapshot kind travels on.
fn bulk_kind(evt: &ServerEvent) -> usize {
    match evt {
        ServerEvent::Notepad { .. } => 0,
        ServerEvent::StatsData { .. } => 1,
        ServerEvent::PasswordSafe { .. } => 2,
        _ => 3, // Preferences (and anything else routed here)
    }
}
fn user_bulk_subscribe(username: &str) -> [broadcast::Receiver<ServerEvent>; WS_BULK_KINDS] {
    let e = user_bulk_events().entry(username.to_string())
        .or_insert_with(|| std::array::from_fn(|_| broadcast::channel(WS_BULK_RING).0));
    std::array::from_fn(|i| e[i].subscribe())
}
/// Deliver a big snapshot reply to every socket of `username` (like send_to_user,
/// through the small ring of its kind).
fn send_bulk_to_user(username: &str, evt: ServerEvent) {
    if let Some(txs) = user_bulk_events().get(username) { let _ = txs[bulk_kind(&evt)].send(evt); }
}
fn user_bulk_prune(username: &str) {
    user_bulk_events().remove_if(username, |_, txs| txs.iter().all(|tx| tx.receiver_count() == 0));
}

/// The unlock response supplies older key material only for migration.
async fn e2e_vault_unlocked_event(state: &AppState, username: &str, proven: bool) -> ServerEvent {
    let b64 = |k: [u8; 32]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, k);
    let keyring = state.e2e_store.load_keyring(username).await;
    let migrated = match &keyring {
        Some((_, migrated)) => *migrated,
        None => state.e2e_store.identity_is_v2(username).await,
    };
    let v2_keyring = matches!(keyring, Some((ref blob, _)) if blob.starts_with("e2k2."));
    let legacy = if !migrated && proven && state.e2e_store.needs_legacy_key(username).await.unwrap_or(true) {
        state.crypto.derive_e2e_enc_key(username).await.ok().map(b64)
    } else { None };
    let e2e_pepper = if proven && v2_keyring {
        state.crypto.derive_e2e_kek_pepper(username).await.ok().map(b64)
    } else { None };
    ServerEvent::VaultUnlocked {
        e2e_enc_key: String::new(), e2e_legacy_key: legacy, e2e_pepper,
        e2e_migrated: migrated, vault_verified: proven,
    }
}

fn e2e_blob_version(blob: &str) -> u32 {
    if blob.starts_with("e2e3.") { 3 }
    else if blob.starts_with("e2e2.") { 2 }
    else { 1 }
}

/// r2: split an outgoing IRC line into (VERB, targets, text) for PRIVMSG / NOTICE —
/// skipping an IRCv3 `@tags` prefix and a `:source` prefix. None for anything else.
/// r3 (codex-p1 HIGH main.rs:5178 / agy-P1 HIGH main.rs:5127): parameters are separated
/// by RUNS of spaces, as IRC servers parse them — splitting on single spaces read
/// `PRIVMSG  #chan :x` as an empty target (and `PRIVMSG #chan  :x` as text " :x"), so
/// the outdated-tab guard let such a line through to the server in cleartext.
fn e2e_split_chat_line(raw: &str) -> Option<(String, String, String)> {
    // One space-delimited token, and the rest after the spaces that follow it.
    fn token(s: &str) -> (&str, &str) {
        let s = s.trim_start_matches(' ');
        match s.find(' ') {
            Some(i) => (&s[..i], s[i..].trim_start_matches(' ')),
            None => (s, ""),
        }
    }
    let mut rest = raw.trim_start_matches(' ');
    if rest.starts_with('@') { rest = token(rest).1; }
    if rest.starts_with(':') { rest = token(rest).1; }
    let (verb, rest) = token(rest);
    let verb = verb.to_ascii_uppercase();
    if verb != "PRIVMSG" && verb != "NOTICE" { return None; }
    let (targets, tail) = token(rest);
    if targets.is_empty() { return None; }
    let text = tail.strip_prefix(':').unwrap_or(tail).to_string();
    Some((verb, targets.to_string(), text))
}

/// r5 (codex P1 main.rs:7399): fold a nick the way a network compares nicks, never wider:
/// its CASEMAPPING (`cm`; unknown → ascii, which every mapping folds at least, so two nicks
/// the network keeps apart are never equated), and only with UTF8MAPPING=rfc8265 (Ergo's
/// precis mapping, which advertises CASEMAPPING=ascii) also NFKC + Unicode lowercase.
/// For the E2E nick → account resolution only; the outdated-tab guard deliberately uses
/// the WIDEST fold instead (e2e_fold_all: over-matching there only refuses more).
fn e2e_nick_fold(cm: Option<cryptirc::ircproto::CaseMapping>, rfc8265: bool, s: &str) -> String {
    let cm = cm.unwrap_or(cryptirc::ircproto::CaseMapping::Ascii);
    if rfc8265 {
        let n = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(s);
        cm.fold(&n.to_lowercase())
    } else {
        cm.fold(s)
    }
}

/// r3: the widest IRC case-fold. Every CASEMAPPING folds a subset of this, so comparing
/// folded names never MISSES a name the network treats as equal (it may over-match on an
/// `ascii` network, which for the outdated-tab guard below only means refusing more).
/// r4 (w3-web V3W-N2, integrator decision): fold(s) = rfc1459_specials(lowercase(NFKC(s))):
/// Unicode NFKC first, then Unicode lowercase (str::to_lowercase), then ASCII lowercase +
/// RFC1459 `[]\~` → `{}|^` (irc_lower). "Unicode lowercase + RFC1459" alone was NOT the
/// widest fold: CASEMAPPING=rfc8265 (PRECIS, e.g. Ergo) also maps fullwidth forms to their
/// ASCII letters and composes decomposed accents, so `＃ｓｅｃ` / `#se\u{301}c` named the
/// encrypted `#sec` / `#séc` there and passed the guard in cleartext. NFKC covers PRECIS's
/// width mapping and normalization. Keep identical to the client-side fold in e2e.js.
fn e2e_fold_all(s: &str) -> String {
    let nfkc = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(s);
    cryptirc::ircproto::irc_lower(&nfkc.to_lowercase())
}

/// r3 (codex-p3 HIGH e2e.js:2816 server side): the E2E names a raw PRIVMSG/NOTICE target
/// can reach: the target itself, the channel behind STATUSMSG prefixes (`@#chan`,
/// `+#chan`, `&#chan`, `~#chan`, `%#chan`, in any combination) and the nick of a
/// `nick!user@host` / `nick@server` / `nick%host` target. Folded with e2e_fold_all.
/// Returns (name as written, folded name) pairs.
fn e2e_target_names(t: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let t = t.trim();
    if t.is_empty() { return out; }
    e2e_target_names_into(t, &mut out);
    // r4 V3W-N2: the same forms read from the NFKC spelling too (a fullwidth `＠` / `＃` /
    // `！` is a STATUSMSG / channel / nick!user separator once normalized). Over-matching
    // here only makes the outdated-tab guard refuse more.
    let norm = icu_normalizer::ComposingNormalizerBorrowed::new_nfkc().normalize(t);
    if norm.as_ref() != t { e2e_target_names_into(norm.trim(), &mut out); }
    out
}

fn e2e_target_names_into(t: &str, out: &mut Vec<(String, String)>) {
    if t.is_empty() { return; }
    let mut add = |n: &str| out.push((n.to_string(), e2e_fold_all(n)));
    add(t);
    let mut s = t;
    while let Some(c) = s.chars().next() {
        if !matches!(c, '@' | '+' | '%' | '~' | '&' | '!') { break; }
        s = &s[c.len_utf8()..];
        if s.starts_with(|c: char| matches!(c, '#' | '&' | '+' | '!')) { add(s); }
    }
    if !t.starts_with(|c: char| matches!(c, '#' | '&' | '+' | '!' | '$')) {
        if let Some(i) = t.find(|c: char| matches!(c, '!' | '@' | '%')) {
            if i > 0 { add(&t[..i]); }
        }
    }
}

/// r2: is this PRIVMSG/NOTICE body cleartext a human wrote (as opposed to E2E
/// ciphertext / X3DH plumbing, or an automatic CTCP request/reply other than /me)?
fn e2e_text_is_cleartext(text: &str) -> bool {
    if text.is_empty() { return false; }
    if text.starts_with("sd8~") || text.starts_with("[e2edm") || text.starts_with("[e2ex3dh]") { return false; }
    if text.starts_with('\u{1}') && !text.starts_with("\u{1}ACTION") { return false; }
    true
}

/// Protect known encrypted targets from plaintext sends, including from clients
/// that do not implement E2E. Outdated browsers on recovery-keyring accounts
/// also need to reload before sending ciphertext from a stale ratchet.
async fn e2e_send_blocked(
    state: &AppState, username: &str,
    socket_tx: &tokio::sync::mpsc::Sender<ServerEvent>, cmd: &ClientMessage, outdated_browser: bool,
) -> bool {
    let ClientMessage::Send { conn_id, raw } = cmd else { return false };
    let Some((_verb, targets, text)) = e2e_split_chat_line(&strip_crlf(raw)) else { return false };
    let outdated_recovery = outdated_browser && !text.starts_with('\u{1}')
        && matches!(state.e2e_store.load_keyring(username).await,
            Some((blob, _)) if blob.starts_with("e2k3."));
    if !outdated_recovery && !e2e_text_is_cleartext(&text) { return false; }
    let conn_id = &canonical_network_id(conn_id);
    if !state.owns_conn(username, conn_id) { return true; }
    let protected = match state.e2e_store.protected_names(username).await {
        Ok((channels, peers)) => match_e2e_target(&targets, conn_id, channels, peers),
        Err(_) => {
            let _ = socket_tx.try_send(ServerEvent::Error { message: "Unable to verify encryption for this conversation. Message blocked.".into() });
            return true;
        }
    };
    if let Some(bare) = protected {
        let shown = if is_plausible_target(&bare) { bare } else { "status".to_string() };
        let message = if outdated_browser {
            format!("🔒 Message to {shown} blocked. Reload CryptIRC to use encrypted chat.")
        } else {
            format!("🔒 Plaintext message to {shown} blocked. Unlock encrypted chat to send.")
        };
        let _ = socket_tx.try_send(ServerEvent::IrcMessage {
            replayed: false,
            conn_id: conn_id.clone(),
            from: "*".into(),
            target: shown,
            text: message,
            ts: chrono::Utc::now().timestamp(),
            kind: MessageKind::Notice,
            msg_id: 0,
            prefix: None,
        });
        return true;
    }
    false
}

fn match_e2e_target(targets: &str, conn_id: &str, channels: Vec<String>, peers: Vec<String>) -> Option<String> {
    let channels: std::collections::HashSet<String> = channels.into_iter()
        .map(|c| e2e_fold_all(&c)).collect();
    let peers: std::collections::HashSet<String> = peers.into_iter()
        .filter(|p| !p.starts_with("__"))
        .filter_map(|p| {
            if let Some((scope, nick)) = p.strip_prefix('@').and_then(|s| s.split_once(':')) {
                if validate_uuid(scope).is_some() {
                    return (conn_id.is_empty() || scope.eq_ignore_ascii_case(conn_id)).then(|| e2e_fold_all(nick));
                }
            }
            Some(e2e_fold_all(&p))
        }).collect();
    targets.split(',').flat_map(e2e_target_names)
        .find(|(_, key)| channels.contains(key) || peers.contains(key))
        .map(|(name, _)| name)
}

// Apply edits under the same lock as joins, parts, connects, and network removal.
async fn edit_network(
    state: &AppState,
    username: &str,
    id: &str,
    require_vault: bool,
    edit: impl FnOnce(&NetworkConfig) -> Result<NetworkConfig, String>,
    send: impl Fn(ServerEvent),
) -> Result<(), String> {
    let lock = network_config_lock(username, id);
    let _guard = lock.lock().await;
    if !state.owns_network(username, id).await {
        return Err("Unknown network.".into());
    }
    let existing = state.get_network_config(id, username).await.ok_or("Unknown network.")?;
    let network = edit(&existing)?;
    let dial_changed = ipc_client::dial_settings_differ(&existing, &network);
    state.save_network_with_vault_policy(&network, username, require_vault).await.map_err(|e| e.to_string())?;
    state.avatars.forget_session(id);
    // Auto-generate client cert if SASL EXTERNAL is enabled and no cert exists
    if network.sasl_external && state.crypto.is_unlocked(username).await {
        let has_cert = state.certs.load_info(&network.id).await.is_ok();
        if !has_cert {
            let nick = network.nick.clone();
            if let Ok(info) = state.certs.generate(username, &network.id, &nick).await {
                let mut cfg = network.clone();
                cfg.client_cert_id = Some(network.id.clone());
                let _ = state.save_network_with_vault_policy(&cfg, username, require_vault).await;
                send(ServerEvent::CertInfo {
                    conn_id: network.id.clone(),
                    fingerprint: info.fingerprint,
                    cert_pem: info.cert_pem,
                });
            }
        }
    }
    // codex P2 / agy P2 (UpdateNetwork never reached the live connection): refresh
    // the running connection's cached config (push label, SASL display flags, join
    // key seeds read it). Settings that only matter when dialling — server, port,
    // TLS, nick, login, perform… — are what irc-core was given at Dial time and
    // keeps across its own reconnects, so: a connection that is not registered yet
    // (connecting, or retrying a typo'd host) is re-dialled with them right away;
    // a registered one keeps running and the user is told the change applies on the
    // next Connect. (Its E2E network identity stays the endpoint it really dials —
    // IrcConnection::dial_endpoint — whatever the config now says.)
    let live = state.connections.get(&network.id).map(|c| c.clone());
    if let Some(conn) = live {
        if let Some(fresh) = state.get_network_config(&network.id, username).await {
            let registered = { let mut c = conn.lock().await; c.cfg = fresh.clone(); c.registered };
            if dial_changed {
                let redial = !registered
                    && state.crypto.is_unlocked(username).await
                    && !state.disconnect_requested(&network.id)
                    && !user_disconnected(&network.id);
                if redial {
                    info!("[{}] connection settings changed before it registered — re-dialing with them", network.id);
                    ipc_client::dial_current(state, username, fresh).await;
                } else {
                    send(ServerEvent::IrcMessage {
                        conn_id: network.id.clone(), from: "*".into(), target: "status".into(),
                        text: "Network settings saved. The new connection settings (server, port, TLS, nick, login, perform) take effect the next time this network connects: use Disconnect, then Connect, to apply them now.".into(),
                        ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None, replayed: false,
                    });
                }
            }
        }
    }
    send(ServerEvent::State {
        networks: state.user_network_states(username).await,
        vault_unlocked: state.crypto.is_unlocked(username).await,
    });
    Ok(())
}

fn preferences_lock(username: &str) -> Arc<tokio::sync::Mutex<()>> {
    network_config_lock(username, "\u{1}preferences")
}

const PREFERENCES_VAULT_LOCKED: &str = "Unlock the vault in CryptIRC first.";

async fn save_preferences(state: &AppState, username: &str, mut prefs: String) -> Result<(), String> {
    if prefs.len() > 1_000_000 {
        return Err("Preferences too large (max 1MB) — not saved".into());
    }
    let mut incoming: serde_json::Value = serde_json::from_str(&prefs)
        .map_err(|_| "Preferences not valid JSON")?;
    if !state.crypto.is_unlocked(username).await {
        return Err(PREFERENCES_VAULT_LOCKED.into());
    }
    let dir = std::path::PathBuf::from(&state.data_dir)
        .join("users").join(safe_username(username));
    let path = dir.join("preferences.enc");
    // Callers hold the per-user preferences lock. Preserve a newer Clear when
    // an older tab saves its whole preferences snapshot after that Clear.
    if let Some(next) = incoming.as_object_mut() {
        if let Ok(stored) = tokio::fs::read_to_string(&path).await {
            if let Ok(previous) = state.crypto.decrypt(username, stored.trim()).await {
                if let Ok(mut saved) = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(&previous) {
                    let notices_version = |obj: &serde_json::Map<String, serde_json::Value>| {
                        let read = |key| obj.get(key).and_then(serde_json::Value::as_u64).unwrap_or(0);
                        (read("_mentionsClearTs"), read("_mentionsTs"))
                    };
                    if notices_version(&saved) > notices_version(next) {
                        for field in ["mentions", "_mentionsTs", "_mentionsClearTs"] {
                            if let Some(value) = saved.remove(field) { next.insert(field.into(), value); }
                        }
                        // A tab ignores its own unchanged save echo. It must see this correction.
                        next.remove("_saveTs");
                        prefs = incoming.to_string();
                        if prefs.len() > 1_000_000 { return Err("Preferences too large (max 1MB) — not saved".into()); }
                    }
                }
            }
        }
    }
    let encrypted = state.crypto.encrypt(username, prefs.as_bytes()).await
        .map_err(|e| format!("Prefs encrypt failed: {e}"))?;
    tokio::fs::create_dir_all(&dir).await
        .map_err(|e| format!("Prefs save failed: {e}"))?;
    write_user_file_atomic(&path, encrypted.as_bytes()).await
        .map_err(|e| format!("Prefs save failed: {e}"))?;
    let _ = tokio::fs::remove_file(dir.join("preferences.json")).await;
    send_bulk_to_user(username, ServerEvent::Preferences { prefs });
    Ok(())
}

// ─── Command handler ──────────────────────────────────────────────────────────

async fn handle_command(
    cmd: ClientMessage,
    username: &str,
    state: &AppState,
    socket_tx: &tokio::sync::mpsc::Sender<ServerEvent>,
    report_command_errors: bool,
) {
    let send = |evt: ServerEvent| {
        if report_command_errors && matches!(evt, ServerEvent::Error { .. }) {
            let _ = socket_tx.try_send(evt.clone());
        }
        state.send_to_user(username, evt);
    };
    // #60: send an event to ONLY the originating socket (used for vault-unlock key
    // material so it isn't broadcast to other, possibly-stale, sessions).
    // F14: bounded queue — a full queue means the client isn't reading; the recv
    // loop closes such a socket right after this command returns.
    let send_self = |evt: ServerEvent| { let _ = socket_tx.try_send(evt); };
    // F2: canonical ids from here on.
    let cmd = canonicalize_cmd_ids(cmd);

    match cmd {
        ClientMessage::Auth { .. } => {}
        // Idle/Active handled in handle_ws before reaching here
        ClientMessage::Idle {} | ClientMessage::Active {} => {}

        ClientMessage::UnlockVault { passphrase } => {
            // #13: rate-limit the KDF path per user so an authenticated client cannot
            // spam UnlockVault over one or many WebSockets to saturate worker threads
            // and exhaust RAM (each unlock pins a thread on Argon2 + allocates 64 MiB).
            // C1/F12: this now also covers the ALREADY-unlocked case. That path used to
            // short-circuit and hand the E2E key to any socket without checking the
            // passphrase; now the passphrase is verified (same Argon2 unwrap as unlock,
            // under the same per-user rate limit + process-wide KDF semaphore) before this
            // socket gets the E2E pepper. A browser does this once per device to enable
            // E2E ("enter your vault passphrase to enable E2E on this device").
            let already_unlocked = state.crypto.is_unlocked(username).await;
            // r4 C1-4: a vault lock requested after THIS unlock (another tab / device) wins:
            // the epoch taken now makes the unlock refuse to install the key if a lock lands
            // while it waits for a KDF slot or derives.
            let lock_epoch = state.crypto.lock_epoch(username);
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
                // r3 C1-5: the permit MOVES INTO the blocking closure (like run_auth_kdf).
                // Held here in the async caller, it was released when the socket's
                // recv task was aborted (socket teardown) while the already-started
                // spawn_blocking derive kept running — so the cap no longer bounded
                // live derivations.
                let crypto = state.crypto.clone();
                let uname  = username.to_string();
                let pass   = passphrase.clone();
                match run_vault_kdf(kdf_sem(), move || {
                    tokio::runtime::Handle::current().block_on(crypto.unlock_since(&uname, &pass, lock_epoch))
                }).await {
                    Some(r) => r,
                    None    => Err(anyhow::anyhow!("unlock task failed")),
                }
            };
            match unlock_res {
                Ok(_) if already_unlocked => {
                    // Passphrase re-verified on an already-unlocked vault: hand THIS socket
                    // the E2E pepper (C1). Nothing else changes server-side.
                    send_self(e2e_vault_unlocked_event(state, username, true).await);
                }
                Ok(_)  => {
                    // #60/C1: the E2E pepper + legacy key go ONLY to the unlocking socket,
                    // not to every active session (a stale device shouldn't silently
                    // receive them). Other sessions get a key-less State refresh so they
                    // observe the unlock and can prompt the user to unlock locally.
                    send_self(e2e_vault_unlocked_event(state, username, true).await);
                    send(ServerEvent::State {
                        networks: state.user_network_states(username).await,
                        vault_unlocked: true,
                    });
                    // F7: a network saved while the vault was locked holds its
                    // credentials in plaintext — encrypt them now that we can.
                    state.encrypt_plaintext_network_creds(username).await;
                    // Per-user vault: only connect THIS user's networks
                    state.reconnect_for_user(username).await;
                    // Chat lines that arrived while the vault was locked (irc.rs log_line).
                    crate::irc::flush_held_logs(&state, username).await;
                }
                // r4 C1-4: locked meanwhile → say so (the passphrase was not wrong).
                Err(e) => match e.downcast_ref::<crypto::LockedMeanwhile>() {
                    Some(lm) => send_self(ServerEvent::VaultError { message: lm.to_string() }),
                    None => send_self(ServerEvent::VaultError { message: "Incorrect passphrase".into() }),
                },
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
            // r4 C1-4: see UnlockVault — a lock requested after this change wins.
            let lock_epoch = state.crypto.lock_epoch(username);
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
                // r3 C1-5: the permit lives inside the blocking closure (see UnlockVault).
                let crypto = state.crypto.clone();
                let uname  = username.to_string();
                let (oldp, newp) = (old.clone(), new.clone());
                match run_vault_kdf(kdf_sem(), move || {
                    tokio::runtime::Handle::current().block_on(crypto.change_passphrase_since(&uname, &oldp, &newp, lock_epoch))
                }).await {
                    Some(r) => r,
                    None    => Err(anyhow::anyhow!("passphrase-change task failed")),
                }
            };
            match chpass_res {
                Ok(_)  => {
                    // Only acknowledge the passphrase change on the initiating socket.
                    send_self(e2e_vault_unlocked_event(state, username, true).await);
                }
                Err(e) => send_self(ServerEvent::VaultError { message: e.to_string() }),
            }
        }

        ClientMessage::AddNetwork { mut network } => {
            // F15 (rust-ws2, INFO) — deliberate: server/port are NOT restricted to public
            // addresses. Self-hosters routinely point CryptIRC at an ircd/bouncer on
            // localhost or the LAN, so blocking loopback/private ranges would break real
            // setups. A meaningful restriction would also have to be enforced by irc_core
            // at dial time on the RESOLVED address (a hostname can resolve to 127.0.0.1 /
            // be rebound), not by string checks here; if an operator running open
            // registration wants it, add it there as an admin opt-in setting.
            // #34: cap the number of networks per user. Each saved network spawns an
            // outbound IRC connection on unlock; an unbounded count lets one account
            // exhaust file descriptors/sockets/memory and get the server K-lined.
            // r3 C1-13/C2-6: count + create under ONE per-account lock. Each request
            // mints a different id, so the per-network locks never serialised two
            // concurrent AddNetworks: all of them saw the same count and all saved.
            // (Same lock map as network_config_lock; the key can't collide with a UUID.)
            let add_lock = network_config_lock(username, "\u{1}add-network");
            let add_guard = add_lock.lock().await;
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
            let require_vault = report_command_errors && network.has_saved_network_secrets();
            if let Err(e) = state.save_network_with_vault_policy(&network, username, require_vault).await {
                send(ServerEvent::Error { message: e.to_string() }); return;
            }
            // The new config is on disk, so the next AddNetwork's count includes it.
            drop(add_guard);
            // Auto-generate client cert if SASL EXTERNAL is enabled
            if network.sasl_external && state.crypto.is_unlocked(username).await {
                let has_cert = state.certs.load_info(&network.id).await.is_ok();
                if !has_cert {
                    let nick = network.nick.clone();
                    if let Ok(info) = state.certs.generate(username, &network.id, &nick).await {
                        let mut cfg = network.clone();
                        cfg.client_cert_id = Some(network.id.clone());
                        let _ = state.save_network_with_vault_policy(&cfg, username, require_vault).await;
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
        ClientMessage::UpdateNetwork { network } => {
            if !state.owns_network(username, &network.id).await { return; }
            let id = network.id.clone();
            if let Err(message) = edit_network(state, username, &id, false, |existing| {
                let mut network = network;
                if network.client_cert_id.is_none() {
                    network.client_cert_id = existing.client_cert_id.clone();
                }
                // Older clients omit these fields when editing a network.
                if network.channel_keys.is_empty() { network.channel_keys.clone_from(&existing.channel_keys); }
                if network.channel_order.is_empty() { network.channel_order.clone_from(&existing.channel_order); }
                network.keep_nick.clone_from(&existing.keep_nick);
                network.keep_nick_managed = existing.keep_nick_managed;
                Ok(network)
            }, &send).await {
                send(ServerEvent::Error { message });
            }
        }
        ClientMessage::KeepNick { conn_id, nick, stop, import } => {
            if let Err(message) = keepnick::set(state, username, &conn_id, nick, stop, import).await {
                send_self(ServerEvent::Error { message: format!("KeepNick: {message}") });
            }
        }
        ClientMessage::React { conn_id, target, request_id, reaction } => {
            if !reactions::valid_request_id(&request_id) { return; }
            let result = if state.auth.check_ws_kdf_rate_limit(username, "reactions").is_ok() {
                reactions::send(state, username, &conn_id, &target, reaction).await
            } else {
                Err("Too many reactions. Try again in a minute.")
            };
            send_self(ServerEvent::ReactionResult { request_id, error: result.err().map(str::to_owned) });
        }
        ClientMessage::RemoveNetwork { id } => {
            if !state.owns_network(username, &id).await { return; }
            state.avatars.forget_session(&id);
            // #20: resolve the reason before any await elsewhere.
            let reason = match state.get_network_config(&id, username).await {
                Some(cfg) => strip_crlf(quit_reason_for(&cfg)),
                None => DEFAULT_QUIT_MESSAGE.to_string(),
            };
            // #4 + C-1: hold the per-config lock across the file DELETE **and** the in-memory
            // map removals **and** the Drop send — one critical section. #4 (the file half):
            // without the lock a concurrent Join/Part/Update/Send/GenerateCert for this id
            // could interleave get_network_config→delete→save_network and RESURRECT the
            // <id>.json on disk. C-1 (the map half, the round-3 finding): the eager map
            // removals used to sit OUTSIDE this lock, so a two-tab Connect could resolve its
            // get_network_config (file still present) and then, after our delete+removal,
            // re-insert conn_owners + Dial a live socket for a network with no config — an
            // invisible, un-reapable, credential-bearing orphan. Connect now takes the same
            // lock and re-reads the config inside it, so it sees None. send_drop is inside
            // the lock and AFTER the delete, so a Connect that won the lock first (and
            // already sent its Dial) is followed by our Drop → daemon ends disconnected.
            // r3 C2-1: the lock is also held across the fresh ownership check below AND the
            // destructive work it gates (config, session, logs/<id>/).
            {
                let _cfg_lock = network_config_lock(username, &id);
                let _cfg_guard = _cfg_lock.lock().await;
                let ownership = network_id_ownership(&state, username, &id).await;
                let holds_session = state.owns_conn(username, &id);
                if ownership == IdOwnership::Sole || holds_session {
                    state.request_disconnect(&id);
                    state.abort_connect_task(&id);
                    state.clear_pending_dial(&id);
                }
                if ownership != IdOwnership::NotListed {
                    state.remove_network(&id, username).await;
                }
                // The daemon session + the global per-id maps/flags: only when this account
                // is the sole owner of the id or is the one holding its session.
                if ownership == IdOwnership::Sole || holds_session {
                    ipc_client::send_drop(&state, &id, reason).await;
                    state.connections.remove(&id);
                    state.conn_owners.remove(&id);
                    state.clear_disconnect_request(&id);
                }
                // The explicit-Disconnect mark is global per id: only its sole owner clears it.
                if ownership == IdOwnership::Sole { set_user_disconnected(&id, false); }
                match ownership {
                    IdOwnership::Sole => {
                        // F16: the network's chat history goes with it. Nothing can reach
                        // `logs/<id>/` once the config is gone (a re-added server gets a new
                        // id), and "Clear All Data" walked only live configs, so it stayed on
                        // disk forever. Also removes legacy re-cased variant dirs (F2).
                        let removed_dirs = state.logger.delete_conn_logs(&id).await;
                        if removed_dirs > 0 { info!("Removed {} log dir(s) of deleted network {} for {}", removed_dirs, id, username); }
                    }
                    IdOwnership::Shared => {
                        // r3 C2-1: a legacy id another account's config also names: only THIS
                        // account's config went; logs/<id>/ holds both accounts' history (each
                        // line under its writer's vault key) and stays, like certs/<id>/.
                        warn!("[{}] removed {}'s copy of a network id shared with another account; its logs/cert are kept", id, username);
                    }
                    IdOwnership::Unverified => {
                        // r4: owners unreadable (storage error) — fail closed like Shared.
                        warn!("[{}] removed {}'s network config; the id's owners could not be verified, so its logs/cert are kept", id, username);
                    }
                    IdOwnership::NotListed => {}
                }
            }
            send(ServerEvent::State {
                networks: state.user_network_states(username).await,
                vault_unlocked: state.crypto.is_unlocked(username).await,
            });
        }
        ClientMessage::Connect { id } => {
            if !state.owns_network(username, &id).await { return; }
            // (I3) An already-live network no-ops here PURELY because of the web-side
            // `connections.contains_key` guard below — NOT because the daemon rejects a
            // duplicate Dial. A Dial for an already-owned conn_id actually REPLACES it
            // daemon-side (drops the live socket + redials — that's the cert-renewal
            // path), so this guard is what prevents bouncing a healthy connection. It
            // also supersedes the old force-kill-and-restart dance against ghost/
            // duplicate connections, which spawn_connection's check-and-insert prevents.
            if state.connections.contains_key(&id) { return; }
            // C-1/I-1: serialize this Connect's map mutations + Dial under the per-config
            // lock so they're atomic vs a concurrent two-tab RemoveNetwork (delete + map
            // removal) or Disconnect (disconnect-flag set + Drop). Re-read the config INSIDE
            // the lock — a RemoveNetwork that won the lock first deleted it → we see None →
            // bail (no in-memory resurrection of a removed network). Whichever of
            // Connect/Disconnect/RemoveNetwork acquires the lock LAST wins deterministically
            // (no partial interleave), and the daemon receives their Dial/Drop in that order.
            let _cfg_lock = network_config_lock(username, &id);
            let _cfg_guard = _cfg_lock.lock().await;
            if state.connections.contains_key(&id) { return; }
            // r4 C1-2 / C2-1: re-check after the lock wait — another account's session may
            // have claimed this (legacy, shared) id meanwhile (claim_and_dial re-checks it
            // again under the id-wide claim lock).
            if !state.owns_network(username, &id).await { return; }
            if let Some(cfg) = state.get_network_config(&id, username).await {
                // r3 A2-3: with the vault locked, a network whose saved credentials (or
                // client-cert key) are encrypted would be dialled WITHOUT them — an
                // unauthenticated session that reconnect_for_user then skips after the
                // unlock (it is already "live"). Don't dial; the user asked for it to be
                // online, so drop any explicit-Disconnect mark and let the next unlock
                // connect it. Credential-less networks still connect while locked.
                if state.dial_deferred_for_locked_vault(username, &cfg).await {
                    // r4: the per-id flags are global — never clear another account's
                    // (re-checked after the await above, nothing awaits in between).
                    if !state.conn_owners.get(&id).map_or(false, |o| o.as_str() != username) {
                        set_user_disconnected(&id, false);
                        state.clear_disconnect_request(&id);
                        state.clear_pending_dial(&id);
                    }
                    send(ServerEvent::Disconnected { conn_id: id.clone(), reason: VAULT_LOCKED_CONNECT_REASON.into() });
                    return;
                }
                // r4: the disconnect flags are cleared by claim_and_dial once the claim
                // is ours (they are per id, shared with any other account naming it).
                if claim_and_dial(&state, username, cfg, true).await == ClaimOutcome::HeldByOther {
                    send(ServerEvent::Disconnected { conn_id: id.clone(), reason: NETWORK_ID_HELD_MSG.into() });
                }
            }
        }
        ClientMessage::Disconnect { id, reason: user_reason, from_lock } => {
            if !state.owns_network(username, &id).await { return; }
            // A reason supplied by `/quit <msg>` wins; blank/absent falls back to the
            // network's configured Quit Message (else the default advert), so a bare
            // /quit and the Disconnect button behave identically. strip_crlf on the
            // user path too — it is untrusted input, and an embedded CRLF would
            // otherwise ride into the daemon's QUIT line.
            let user_reason = user_reason
                .map(|r| strip_crlf(&r).trim().to_string())
                .filter(|r| !r.is_empty());
            let reason = match user_reason {
                Some(r) => r,
                None => match state.get_network_config(&id, username).await {
                    Some(cfg) => strip_crlf(quit_reason_for(&cfg)),
                    None => DEFAULT_QUIT_MESSAGE.to_string(),
                },
            };
            // I-1: serialize under the same per-config lock so the disconnect-flag set +
            // Drop are atomic vs a concurrent two-tab Connect (which clears the flag + Dials)
            // — otherwise the flag-clear and flag-set race and the daemon can be left holding
            // a socket the web thinks is disconnected (or vice versa).
            let _cfg_lock = network_config_lock(username, &id);
            let _cfg_guard = _cfg_lock.lock().await;
            // r3 C2-1: the daemon session and the per-id flags below are global. Only the
            // account holding the session, or the id's sole owner (fresh check, under the
            // lock), may drop / set them — never one of two accounts naming a legacy id.
            let ownership = network_id_ownership(&state, username, &id).await;
            if !state.owns_conn(username, &id) && ownership != IdOwnership::Sole { return; }
            state.request_disconnect(&id);
            state.abort_connect_task(&id);
            state.clear_pending_dial(&id);
            // r3 WW-2 (integrator decision): a disconnect that is part of a vault lock is
            // NOT the user's explicit Disconnect — unlock must bring the network back, as in
            // 7ee4ccb. It neither sets nor clears the mark, so a network the user had
            // explicitly disconnected BEFORE the lock stays disconnected after the unlock.
            // (r3 C2-1: the mark is global per id, so only the id's sole owner sets it.)
            if !from_lock && ownership == IdOwnership::Sole { set_user_disconnected(&id, true); }
            ipc_client::send_drop(&state, &id, reason).await;
        }
        ClientMessage::ListChannels { conn_id, request_id, pattern } => {
            if request_id.len() != 32 || !request_id.bytes().all(|c| c.is_ascii_hexdigit()) { return; }
            let result = async {
                anyhow::ensure!(pattern.len() <= 400 && !pattern.chars().any(|c| c.is_whitespace() || c.is_control()),
                    "Invalid IRC channel list pattern.");
                anyhow::ensure!(state.owns_conn(username, &conn_id), "This network is offline.");
                let conn = state.connections.get(&conn_id).map(|entry| entry.clone())
                    .ok_or_else(|| anyhow::anyhow!("This network is offline."))?;
                let line = if pattern.is_empty() { "LIST\r\n".into() } else { format!("LIST {}\r\n", pattern) };
                let result = conn.lock().await.send_list(&line, Some(request_id.clone())).await;
                result
            }.await;
            if let Err(error) = result {
                send_self(ServerEvent::IrcListError { conn_id, request_id, message: error.to_string() });
            }
        }

        ClientMessage::Send { conn_id, raw } => {
            if !state.owns_conn(username, &conn_id) {
                if report_command_errors {
                    send_self(ServerEvent::Error { message: "This network is offline.".into() });
                }
                return;
            }
            // #20: clone the Arc out and DROP the DashMap Ref immediately so we never
            // hold a shard read-guard across send_raw / logger.append / save_network
            // awaits (which would block synchronous insert/remove on the same shard).
            let conn = state.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
                let safe = strip_crlf(&raw);
                if safe.is_empty() { return; }
                // F9: one Send used to log + echo once per comma-separated target with
                // no limit (thousands of new log dirs/inodes from one frame). Refuse an
                // over-long target list outright — nothing is sent — with a clear error.
                let n_targets = send_target_count(&safe);
                if n_targets > MAX_SEND_TARGETS {
                    send_self(ServerEvent::Error { message: format!(
                        "Too many recipients in one message ({}; max {}). Nothing was sent.", n_targets, MAX_SEND_TARGETS) });
                    return;
                }
                // Skip TAGMSG from logging (typing indicators etc). #F23: detect TAGMSG by the
                // actual command VERB, not a substring of the whole line — a PRIVMSG whose BODY
                // contains "TAGMSG" must not be misclassified (and then dropped / not logged).
                // Typing indicators arrive as `@+typing=active TAGMSG <target>`, so skip an
                // optional IRCv3 @message-tags prefix (and a source prefix) before the verb.
                // r3 A1-4: ONE parse of the outgoing line (IRC grammar: optional @tags and
                // :source, then the verb, params separated by runs of spaces, `:` trailing)
                // drives every classification below, like send_target_count /
                // redact_for_log already do — the PRIVMSG/NOTICE echo + log + self-bot
                // hook and the JOIN/PART auto_join persistence used to test the raw line's
                // first bytes, so a tagged / prefixed / double-spaced line went to IRC
                // but skipped all of them.
                let out = OutgoingLine::parse(&safe);
                let is_tagmsg = out.verb == "TAGMSG";
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
                // Our own user@host, learned from the self-JOIN prefix / CHGHOST. Used to
                // build the owner's full mask for the bot-trigger hook below. It can be
                // empty (it resets on a web reattach until relearned) — harmless here,
                // since the owner bypasses host-based access lists anyway.
                let self_userhost = c.self_userhost.clone();
                // r4 C1-9 (codex P1 main.rs:5882): the exact lines that go out — a long
                // PRIVMSG/NOTICE text split into pieces that reach the recipients whole, a
                // line IRC cannot carry refused (nothing sent). Each line that went out is
                // logged and echoed below as its own message, never more than the wire got.
                let mut wire = match crate::irc::fit_outgoing_line(&safe, &nick, &self_userhost) {
                    Ok(w) => w,
                    Err(why) => { drop(c); send_self(ServerEvent::Error { message: why }); return; }
                };
                // Remote avatars: an opted-in user's PRIVMSG / NOTICE (not a CTCP other than
                // ACTION) carries the announce tag on its first line — the first time to a
                // target, then on a URL change or every 30 min. Dropped (never the message)
                // when the tag would not fit; only with message-tags, unless CLIENTTAGDENY
                // refuses it.
                if (out.verb == "PRIVMSG" || out.verb == "NOTICE") && out.params.len() >= 2 && c.message_tags && c.avx.tags_allowed() {
                    let text = &out.params[1];
                    let plain_ctcp = text.starts_with('\u{1}') && !text.starts_with("\u{1}ACTION ");
                    if !plain_ctcp {
                        if let Some(url) = avatar::remote::share_url(&state, username) {
                            // Account status from disk (codex astra L remote.rs:1056), only when due.
                            if state.avatar_remote.announce_due(&conn_id, &out.params[0], &url) && avatar::remote::owner_active(&state.auth, username).await {
                                if let Some(first) = wire.first_mut() {
                                    if let Some(tagged) = avatar::remote::with_tag(first, &url) { *first = tagged; }
                                }
                            }
                        }
                    }
                }
                // F2: capture the connection's live state under the same lock as the send.
                // If it isn't registered/connected, the daemon drops this RawSend (it's in
                // reconnect/backoff), so we must NOT log + IrcEcho the message as sent — that
                // false confirmation is the one direction with no ring recovery.
                //
                // r5 (codex P2 main.rs:5984): decide by the SAME state that is reported. A
                // line used to be handed to irc-core first and the state checked after, so a
                // message reported "not sent" (and never logged/echoed) could still reach IRC
                // when the flags lagged a re-registration. Not connected/registered → nothing
                // is handed over, except a JOIN/PART: irc-core applies those at the next
                // registration (or sends them if it is in fact registered), and the notice
                // says so instead of claiming "not sent".
                let live = c.connected && c.registered;
                let deferred_join_part = !live && matches!(out.verb.as_str(), "JOIN" | "PART");
                let mut handed_off = live || deferred_join_part;
                if handed_off {
                    for l in &wire {
                        if c.send_raw(&format!("{}\r\n", l)).await.is_err() { handed_off = false; break; }
                    }
                }
                // codex P2 irc.rs:102: no IPC link = not sent, even though the flags above
                // still say connected (they only change when the daemon tells us).
                let connected = live && handed_off;
                drop(c);
                // (Not for TAGMSG typing indicators: one per keystroke burst would flood
                // the status buffer while the link is down.)
                if !connected && !is_tagmsg {
                    if report_command_errors {
                        send_self(ServerEvent::Error { message: "Connection lost during send. Check history before retrying.".into() });
                    }
                    // Tell the user (once, to status) instead of silently pretending it sent.
                    let text = if deferred_join_part && handed_off {
                        "⚠ Not connected (reconnecting…) — this /join or /part takes effect when the network is back"
                    } else {
                        "⚠ Not connected — your message was not sent (reconnecting…)"
                    };
                    state.send_to_user(username, ServerEvent::IrcMessage {
                        replayed: false,
                        conn_id: conn_id.clone(),
                        from: "*".into(),
                        target: "status".into(),
                        text: text.into(),
                        ts: chrono::Utc::now().timestamp(),
                        kind: MessageKind::Notice,
                        msg_id: 0,
                        prefix: None,
                    });
                }
                // Broadcast PRIVMSG/NOTICE to all user sessions so other devices see them —
                // ONLY when the line actually went to IRC (see F2 above).
                if !is_tagmsg && connected {
                    // r4 C1-9: one log line + echo per line that went out (see `wire`).
                    for out in wire.iter().map(|l| OutgoingLine::parse(l)) {
                    let is_privmsg = out.verb == "PRIVMSG";
                    let is_notice_out = out.verb == "NOTICE";
                    if is_privmsg || is_notice_out {
                        if out.params.len() >= 2 {
                            let targets = out.params[0].to_string();
                            let text = out.params[1].to_string();
                            let is_action = text.contains("\x01ACTION ");
                            let ts = chrono::Utc::now().timestamp();
                            let (kind, clean) = if is_action && text.starts_with("\x01ACTION ") && text.ends_with('\x01') {
                                (MessageKind::Action, text[8..text.len()-1].to_string())
                            } else if is_notice_out {
                                (MessageKind::Notice, text)
                            } else {
                                (MessageKind::Privmsg, text)
                            };
                            // #55: PRIVMSG/NOTICE may carry a comma-separated target list
                            // (`#a,#b`); echo + log to EACH target, not the whole list as one.
                            // (Removed the dead channel-vs-PM if/else whose branches were identical
                            // — the display target is simply the recipient string in both cases.)
                            // (r4 C2-2: send_target_count now counts exactly these targets, so
                            // n_targets <= MAX_SEND_TARGETS bounds this loop; `take` is a backstop.)
                            for display_target in targets.split(',').filter(|t| is_plausible_target(t)).take(MAX_SEND_TARGETS) {
                                let display_target = display_target.to_string();
                                // r5 (agy P2 main.rs:6036): through the hold path (held while
                                // the vault is locked, never written ahead of held lines).
                                let msg_id = crate::irc::log_own_line(&state, username, &conn_id, &display_target, ts, &nick, &clean, match &kind {
                                    MessageKind::Privmsg => "privmsg",
                                    MessageKind::Notice => "notice",
                                    MessageKind::Action => "action",
                                }).await;
                                // Server-side bot triggers on the owner's OWN line.
                                // irc.rs can never see these (our own PRIVMSG is either
                                // echo-suppressed or never echoed at all), so without
                                // this hook the owner's own `$ai`/`!w` silently did
                                // nothing. Channel targets only, and NOTICE is excluded
                                // to match irc.rs. ACTION (/me) IS included, because
                                // irc.rs dispatches on the cleaned text without checking
                                // kind — so `/me !w london` fires the bot for everyone
                                // else, and excluding it here would make the owner's own
                                // /me the one case that silently didn't work.
                                // No loop is possible — bot replies go out via
                                // bot_send → send_raw, never back through this handler.
                                if !matches!(kind, MessageKind::Notice)
                                    && display_target.starts_with(['#', '&', '+', '!'])
                                {
                                    let own_mask = format!("{}!{}", nick, self_userhost);
                                    bots::maybe_trigger_self(
                                        &state, username, &conn_id, &conn,
                                        &display_target, &nick, &own_mask, &clean,
                                    );
                                }
                                state.send_to_user(username, ServerEvent::IrcEcho {
                                    conn_id: conn_id.clone(),
                                    from: nick.clone(),
                                    target: display_target.clone(),
                                    text: clean.clone(),
                                    ts,
                                    kind: kind.clone(),
                                    msg_id,
                                });
                                if is_privmsg {
                                    let reference = reactions::own_local(&mut *conn.lock().await, &display_target, &clean, msg_id);
                                    if let Some(event) = reference.and_then(|r| reactions::anchor_event(&conn_id, &display_target, msg_id, &r)) {
                                        state.send_to_user(username, event);
                                    }
                                }
                            }
                        }
                    }
                    } // for out in wire
                }
                // Persist JOIN/PART in auto_join (with channel key if provided)
                let is_join = out.verb == "JOIN";
                if is_join || out.verb == "PART" {
                    // r4 F1-2: EVERY channel of a list (`JOIN #a,#b ka,kb`, `PART #a,#b`), each
                    // JOIN channel with the key at the same list position — only the first
                    // one used to be saved/forgotten, so `/part #a,#b` rejoined #b on the
                    // next connect and `/join #a,#b` never auto-joined #b.
                    let pairs = join_part_channels(&out.params, is_join);
                    if !pairs.is_empty() {
                        // Serialize this auto_join/channel_keys RMW behind the same
                        // per-config lock the JoinChannel/PartChannel handlers use — the
                        // raw `/join`/`/part` SEND path does the identical mutation and
                        // would otherwise race them (last-writer-wins + shared .tmp).
                        // send_raw already happened above, so the lock isn't held across
                        // the IRC round-trip. One read-modify-write for the whole list.
                        let _cfg_lock = network_config_lock(username, &conn_id);
                        let _cfg_guard = _cfg_lock.lock().await;
                        if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                            let mut changed = false;
                            let cm = if is_join { None } else { crate::irc::known_casemapping(&conn_id) };
                            for (ch, key) in pairs {
                                if is_join {
                                    let lc = ch.to_lowercase();
                                    if !cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) && cfg.auto_join.len() < 100 {
                                        cfg.auto_join.push(ch.to_string());
                                        changed = true;
                                    }
                                    // Save channel key if provided (JOIN #chan key)
                                    if !key.is_empty() {
                                        cfg.channel_keys.insert(lc, key.to_string());
                                        changed = true;
                                    }
                                } else {
                                    forget_parted_channel(&mut cfg, ch, cm);
                                    changed = true;
                                }
                            }
                            if changed { let _ = state.save_network(&cfg, username).await; }
                        }
                    }
                }
            } else {
                if report_command_errors {
                    send_self(ServerEvent::Error { message: "This network is offline.".into() });
                }
                info!("[{}] SEND failed: no connection found", conn_id);
            }
        }
        ClientMessage::JoinChannel { conn_id, channel, key } => {
            // r6 (agy P1 main.rs:6225): a join on a network that is not connected used to be
            // dropped silently (owns_conn is false without a live connection) — neither sent
            // nor saved. Now (like PartChannel and a typed /join) it is saved to the
            // network's auto-join list and the user is told it joins when the network
            // connects: the next Dial carries the saved auto-join list, so it is joined
            // exactly once. With a live connection (connected, or still connecting /
            // backing off) the JOIN goes to irc-core as before, which joins it now or —
            // r5 628eaf5 — records it for its own registration-time joins.
            let live_conn = if state.owns_conn(username, &conn_id) {
                state.connections.get(&conn_id).map(|c| c.clone())
            } else { None };
            if live_conn.is_none() && !state.owns_network(username, &conn_id).await { return; }
            let safe_ch = strip_crlf(&channel);
            if safe_ch.is_empty() || !is_valid_channel(&safe_ch) { return; }
            if live_conn.is_none() {
                send_self(ServerEvent::IrcMessage {
                    conn_id: conn_id.clone(), from: "*".into(), target: "status".into(),
                    text: format!("Not connected — {} was added to this network's auto-join list and is joined when the network connects.", safe_ch),
                    ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None, replayed: false,
                });
            }
            {
                if let Some(conn) = &live_conn {
                    let cmd = match key.as_deref() {
                        Some(k) if !k.is_empty() => format!("JOIN {} {}\r\n", safe_ch, strip_crlf(k)),
                        _ => format!("JOIN {}\r\n", safe_ch),
                    };
                    let _ = conn.lock().await.send_raw(&cmd).await;
                }
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
            // codex P2 irc.rs:206 / w-srv #14: which saved key/auto-join spelling is "this
            // channel" depends on the SERVER's CASEMAPPING (unknown = exact spelling only).
            let mut server_cm = crate::irc::known_casemapping(&conn_id);
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                server_cm = c.server_casemapping.or(server_cm);
                let _ = c.send_raw(&format!("PART {}\r\n", safe)).await;
            }
            // Always strip from auto_join so reconnect doesn't re-join it.
            let mut user_nick = String::new();
            {
                // #4: serialize the read-modify-write behind the per-config lock.
                let cfg_lock = network_config_lock(username, &conn_id);
                let _cfg_guard = cfg_lock.lock().await;
                if let Some(mut cfg) = state.get_network_config(&conn_id, username).await {
                    user_nick = cfg.nick.clone();
                    forget_parted_channel(&mut cfg, &safe, server_cm);
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
        ClientMessage::GetLogs { conn_id, target, limit, before, before_id, status_view } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let view = status_view_for(&target, status_view.as_deref());
            let lim = limit.unwrap_or(200).min(500);
            let lines = if let Some(ts) = before {
                // Paging / jump-to-message: scan the FULL history so we can reach
                // any depth (read_logs would cap the look-back to the last 10k and
                // hide older messages — the bug behind "message no longer in
                // history" when search finds something far back).
                state.logger.read_logs_before_view(username, &conn_id, &target, ts, before_id, lim, view).await.unwrap_or_default()
            } else {
                // Initial load: just the most-recent `lim` messages. r3 C1-3: ask the
                // tail read for exactly those (it reads newest-first and stops) instead of
                // materialising the newest 10,000 decrypted lines to keep the last `lim`.
                state.logger.read_logs_view(username, &conn_id, &target, lim, view).await.unwrap_or_default()
            };
            send(ServerEvent::LogLines { conn_id, target, lines });
        }
        ClientMessage::SearchLogs { conn_id, target, query, limit } => {
            if !state.owns_network(username, &conn_id).await { return; }
            // #13: default to a sane cap and clamp the client value (was 0 = unbounded,
            // which let a 1-char query stream the whole history through the broadcast).
            // search_logs additionally enforces a min query length + scan ceiling.
            let lim = limit.unwrap_or(500).clamp(1, 1000);
            let lines = state.logger.search_logs(username, &conn_id, &target, &query, lim).await.unwrap_or_default();
            send(ServerEvent::SearchResults { conn_id, target, query, lines });
        }
        ClientMessage::Sync { conn_id, target, after_id, status_view } => {
            if !state.owns_network(username, &conn_id).await { return; }
            let view = status_view_for(&target, status_view.as_deref());
            let lines = state.logger.read_logs_since_view(username, &conn_id, &target, after_id, view).await.unwrap_or_default();
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
            // r3 C2-1: the per-config lock is held from the fresh ownership check through
            // the regeneration and the config RMW (it also serialises the RMW against the
            // JoinChannel/PartChannel/UpdateNetwork/SEND config writers, as before).
            // certs/<id>/ is keyed by the id alone: unless THIS account is the id's sole
            // owner, regenerating would replace another account's certificate and key.
            let _cfg_lock = network_config_lock(username, &conn_id);
            let _cfg_guard = _cfg_lock.lock().await;
            match network_id_ownership(&state, username, &conn_id).await {
                IdOwnership::Sole => {}
                o @ (IdOwnership::Shared | IdOwnership::Unverified) => {
                    send(ServerEvent::Error { message: o.refusal().unwrap_or(CONTESTED_NETWORK_MSG).into() }); return;
                }
                IdOwnership::NotListed => return,
            }
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
                    // (still under the per-config lock taken above; re-read inside it).
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
            // r3 C2-1: check + delete under the per-config lock; only the id's sole owner.
            let _cfg_lock = network_config_lock(username, &conn_id);
            let _cfg_guard = _cfg_lock.lock().await;
            match network_id_ownership(&state, username, &conn_id).await {
                IdOwnership::Sole => {}
                o @ (IdOwnership::Shared | IdOwnership::Unverified) => {
                    send(ServerEvent::Error { message: o.refusal().unwrap_or(CONTESTED_NETWORK_MSG).into() }); return;
                }
                IdOwnership::NotListed => return,
            }
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
            // r3 C2-1: certs/<id>/ may be another account's — show it to the sole owner only.
            let _cfg_lock = network_config_lock(username, &conn_id);
            let _cfg_guard = _cfg_lock.lock().await;
            match network_id_ownership(&state, username, &conn_id).await {
                IdOwnership::Sole => {}
                o @ (IdOwnership::Shared | IdOwnership::Unverified) => {
                    send(ServerEvent::Error { message: o.refusal().unwrap_or(CONTESTED_NETWORK_MSG).into() }); return;
                }
                IdOwnership::NotListed => return,
            }
            match state.certs.load_info(&conn_id).await {
                Ok(info) => send(ServerEvent::CertInfo {
                    conn_id, fingerprint: info.fingerprint, cert_pem: info.cert_pem,
                }),
                Err(_) => send(ServerEvent::Error { message: "No certificate found for this network".into() }),
            }
        }

        // ── E2E: identity key blob (browser-encrypted private keys) ───────────
        ClientMessage::E2EStoreIdentity { blob, expect } => {
            // F17: no INFO-level per-user E2E activity logging (who uses E2E / when).
            tracing::debug!("[E2E] store_identity ({} bytes)", blob.len());
            // #14: E2E blobs are only producible by an UNLOCKED vault. Refuse writes while
            // locked, and refuse an empty/oversized blob, so a locked/stale/XSS'd client
            // can't wipe identity.enc.
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to store E2E identity".into() }); return;
            }
            if blob.is_empty() || blob.len() > WS_MAX_MSG_BYTES {
                send(ServerEvent::Error { message: "E2E identity blob rejected (empty or too large)".into() }); return;
            }
            // C1: after migration only client-held-key blobs may be written, so a stale
            // cached app.js (which can't read the upgraded identity and would "helpfully"
            // regenerate one) can never overwrite it. r3: checked atomically with the
            // write (the permit is held until the write is done).
            let Some(_permit) = state.e2e_store.write_permit(username, e2e_blob_version(&blob)).await else {
                send_self(ServerEvent::Error { message: "E2E: this app version is out of date — reload the page".into() }); return;
            };
            // r3: create-if-absent for a first unlock (`expect`). A conflict writes
            // nothing and is silent: the client reads the identity back right after
            // (same socket, in order) and adopts the stored one.
            match state.e2e_store.store_identity_enc_cas(username, &blob, expect.as_deref()).await {
                Ok(None) => {}
                Ok(Some(_)) => tracing::debug!("[E2E] identity store skipped: another device stored one first"),
                Err(e) => {
                    warn!("[E2E] identity store failed: {}", e);
                    send(ServerEvent::Error { message: format!("E2E store identity: {}", e) });
                }
            }
        }
        ClientMessage::E2ELoadIdentity {} => {
            // Reply ONLY to the requesting socket (was a broadcast to every session of the
            // user, which handed other tabs an identity blob they never asked for — and an
            // older app.js reacted to an unreadable one by generating a new identity).
            match state.e2e_store.load_identity_enc(username).await {
                Some(blob) => send_self(ServerEvent::E2EIdentityBlob { blob }),
                None       => send_self(ServerEvent::E2EIdentityBlob { blob: String::new() }),
            }
        }

        // ── E2E: public key bundle + one-time prekeys ─────────────────────────
        ClientMessage::E2EPublishBundle { mut bundle, v, id_hash } => {
            tracing::debug!("[E2E] publish_bundle");
            // #14: only an unlocked vault can produce a valid bundle — reject while locked so
            // a locked/stale/XSS'd client can't overwrite the live published bundle.
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to publish E2E bundle".into() }); return;
            }
            // C1: a stale app.js (no `v`) can't store the private halves any more once the
            // user is migrated, so its bundle would advertise keys nobody holds.
            // r3: checked atomically with the write (permit held until it is done).
            let Some(_permit) = state.e2e_store.write_permit(username, v.max(1)).await else {
                send_self(ServerEvent::Error { message: "E2E: this app version is out of date — reload the page".into() }); return;
            };
            // r3 (codex-p3 MED e2e.js:1129): a bundle names the identity blob it was made
            // for; one for an identity that is not (or no longer) the stored one — a
            // device that lost the first-unlock race, a stale page after a reset — is
            // refused instead of replacing the live bundle with keys nobody can use.
            if let Some(h) = id_hash.as_deref() {
                if state.e2e_store.identity_blob_hash(username).await.as_deref() != Some(h) {
                    warn!("[E2E] refusing a key bundle for an identity that is not the stored one");
                    send_self(ServerEvent::Error { message: "E2E: key bundle not published — your E2E identity was changed on another device; reload the page".into() });
                    return;
                }
            }
            // HIGH: cap OTPKs carried in a bundle so one publish can't exhaust
            // inodes/disk (one file per key). Real clients publish a small bounded
            // batch; 256 matches the client refill batch size.
            if bundle.one_time_prekeys.len() > 256 {
                warn!("[E2E] publish_bundle carried {} OTPKs — truncating to 256",
                    bundle.one_time_prekeys.len());
                bundle.one_time_prekeys.truncate(256);
            }
            match state.e2e_store.store_bundle(username, &bundle).await {
                Ok(_) => {
                    // L5: use same threshold as client OTPK_REFILL_BELOW = 10
                    let remaining = state.e2e_store.otpk_count(username).await;
                    if remaining < 10 {
                        send(ServerEvent::E2EOTPKLow { remaining });
                    }
                }
                Err(e) => send(ServerEvent::Error { message: format!("E2E publish bundle: {}", e) }),
            }
        }
        ClientMessage::E2EAddOTPKs { mut keys, v } => {
            // #14: reject OTPK writes while the vault is locked (private halves are only
            // producible by an unlocked vault).
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to add E2E prekeys".into() }); return;
            }
            // C1: same stale-client guard as E2EPublishBundle (r3: atomic with the write).
            let Some(_permit) = state.e2e_store.write_permit(username, v.max(1)).await else {
                send_self(ServerEvent::Error { message: "E2E: this app version is out of date — reload the page".into() }); return;
            };
            // HIGH: cap per-call OTPK count so a single add can't exhaust
            // inodes/disk (one file per key). 256 matches the client refill batch.
            if keys.len() > 256 {
                warn!("[E2E] add_otpks carried {} keys — truncating to 256", keys.len());
                keys.truncate(256);
            }
            match state.e2e_store.add_one_time_prekeys(username, keys).await {
                Ok(_)  => {}
                Err(e) => send(ServerEvent::Error { message: format!("E2E add OTPKs: {}", e) }),
            }
        }
        ClientMessage::E2EFetchBundle { username: target_user, conn_id, req } => {
            // The IRC nick as typed (used only for an in-memory comparison against live
            // connection nicks, and echoed back so the client keys the session by the
            // same nick it is talking to — `[bob]` must not come back as `bob`).
            let nick: String = target_user.chars().filter(|c| !c.is_control()).take(64).collect();
            // Sanitized form for the on-disk username lookup (#22: ASCII-only, matching
            // the on-disk sanitizer).
            let safe: String = nick.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                .take(64).collect();
            // F11: the account that actually HOLDS this nick (preferring the caller's own
            // network) wins over a CryptIRC account whose USERNAME merely equals the nick —
            // otherwise anyone could register username == a peer's nick and have their
            // bundle served for every fetch. Username lookup is only the fallback when no
            // live connection on this server holds the nick.
            if let Some(id) = &req {
                if !e2e_bridge::valid_id(id) || !conn_id.as_deref().is_some_and(|cid| state.owns_conn(username, cid)) { return; }
            }
            let resolved = match conn_id.as_deref() {
                // Current clients: strictly the holder of the nick on the caller's network.
                Some(cid) => match state.resolve_e2e_peer(&nick, username, cid).await {
                    Ok(resolved) => resolved,
                    Err(()) => {
                        if let Some(req) = req {
                            send_self(ServerEvent::E2EBundleMissing { conn_id: cid.to_owned(), req, reason: "ambiguous" });
                        } else {
                            send_self(ServerEvent::Error { message: format!("No E2E key bundle for {} (nick is ambiguous on this network)", nick) });
                        }
                        return;
                    }
                },
                // Older cached app.js (no conn_id): previous behaviour kept for
                // compatibility, minus the username-first preference: the live holder of
                // the nick (any network, ambiguity refused), else a username match.
                None => match state.resolve_nick_to_username(&nick).await {
                    Some(real_user) => Some(real_user),
                    None if state.e2e_nick_is_held(&nick).await => {
                        send_self(ServerEvent::Error { message: format!("No E2E key bundle for {} (nick is ambiguous on this server)", nick) });
                        return;
                    }
                    None => Some(safe),
                },
            };
            // F17: no INFO log of who fetches whose bundle (E2E contact metadata).
            tracing::debug!("[E2E] fetch_bundle resolved");
            let local_peer = resolved.is_some();
            if let Some(resolved) = resolved {
                // Charge actual bundle lookups, which can consume a prekey. Ordinary
                // IRC DMs on a network without discovery never use this quota.
                if state.auth.check_ws_kdf_rate_limit(username, "e2e_bundle").is_err() {
                    if let (Some(conn_id), Some(req)) = (conn_id, req) {
                        send_self(ServerEvent::E2EBundleMissing { conn_id, req, reason: "rate-limited" });
                    } else {
                        send_self(ServerEvent::Error { message: "Too many key-bundle requests — slow down".into() });
                    }
                    return;
                }
                if let Some(bundle) = state.e2e_store.fetch_bundle(&resolved, username).await {
                    send_self(ServerEvent::E2EBundle { username: nick.clone(), bundle, conn_id, req, bridge: false });
                    // Check if the target user's prekeys are running low and notify them.
                    // #58: debounce so a fetch flood can't spam the victim's channel.
                    let remaining = state.e2e_store.otpk_count(&resolved).await;
                    if remaining < 10 && otpk_low_should_notify(&resolved) {
                        state.send_to_user(&resolved, ServerEvent::E2EOTPKLow { remaining });
                    }
                    return;
                }
            }
            if let (Some(cid), Some(id)) = (conn_id, req) {
                let reason = if local_peer { "peer-setup" }
                    else if let Some(conn) = state.connections.get(&cid).map(|c| c.clone()) {
                        match e2e_bridge::request(state, username, conn, &nick, &id).await {
                            Ok(true) => return,
                            Ok(false) => "unsupported",
                            Err(reason) => reason,
                        }
                    } else { "unavailable" };
                send_self(ServerEvent::E2EBundleMissing { conn_id: cid, req: id, reason });
                return;
            }
            send_self(ServerEvent::Error { message: format!("No E2E key bundle for {} on this network", nick) });
        }

        // ── E2E: ratchet session state ────────────────────────────────────────
        ClientMessage::E2EStoreSession { partner, blob, dv, snd } => {
            // #14: session blobs are only producible by an unlocked vault — reject writes
            // while locked, and reject empty/oversized blobs, to prevent self-DoS/corruption.
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to store E2E session".into() }); return;
            }
            if blob.is_empty() || blob.len() > WS_MAX_MSG_BYTES {
                send(ServerEvent::Error { message: "E2E session blob rejected (empty or too large)".into() }); return;
            }
            // C1: no legacy-format writes after migration (stale app.js). r3: checked
            // atomically with the write (permit held until it is done).
            let Some(_permit) = state.e2e_store.write_permit(username, e2e_blob_version(&blob)).await else {
                send_self(ServerEvent::Error { message: "E2E: this app version is out of date — reload the page".into() }); return;
            };
            // #13: pass the RAW partner through; the single canonical injective sanitizer
            // lives in e2e::safe_partner (applied inside store_session), so client cache,
            // on-disk stem, and other devices never diverge for non-ASCII/bracket nicks.
            match state.e2e_store.store_session(username, &partner, &blob).await {
                Ok(_)  => {
                    // r2 (NEW-7): tell this user's other devices that the ratchet for
                    // this peer moved on because THIS device sent, so a second device
                    // re-syncs before it sends on a stale chain. Peer sessions only
                    // (never the reserved __spk__/__otpk__/__state__ slots).
                    if snd && !partner.starts_with("__") {
                        let dv: String = dv.unwrap_or_default().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_').take(32).collect();
                        if !dv.is_empty() {
                            state.send_to_user(username, ServerEvent::E2ESessionMoved { partner, dv });
                        }
                    }
                }
                Err(e) => send(ServerEvent::Error { message: format!("E2E store session: {}", e) }),
            }
        }
        ClientMessage::E2ELoadSession { partner } => {
            // #13: pass/echo the RAW partner (client keys dmSessions by the raw nick);
            // e2e::safe_partner does the sole, injective filename derivation.
            // Reply only to the requesting socket (it is a request/response; broadcasting
            // it pushed other tabs session state they never asked for).
            match state.e2e_store.load_session(username, &partner).await {
                Some(blob) => send_self(ServerEvent::E2ESession { partner, blob }),
                None       => send_self(ServerEvent::E2ESession { partner, blob: String::new() }),
            }
        }
        ClientMessage::E2EDeleteSession { partner, v, req } => {
            let permit = if state.crypto.is_unlocked(username).await {
                state.e2e_store.write_permit(username, v.max(1)).await
            } else { None };
            let ok = permit.is_some() && state.e2e_store.delete_session(username, &partner).await.is_ok();
            if let Some(req) = req { send_self(ServerEvent::E2EKeyDeleted { req, ok }); }
            else if !ok { send_self(ServerEvent::Error { message: "E2E: could not remove session; unlock the vault and reload if needed".into() }); }
        }

        // ── E2E: channel pre-shared keys ──────────────────────────────────────
        ClientMessage::E2EStoreChannelKey { channel, blob } => {
            // #14: channel-key blobs are only producible by an unlocked vault — reject writes
            // while locked, and reject empty/oversized blobs (self-DoS/corruption).
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Vault must be unlocked to store E2E channel key".into() }); return;
            }
            if blob.is_empty() || blob.len() > WS_MAX_MSG_BYTES {
                send(ServerEvent::Error { message: "E2E channel key blob rejected (empty or too large)".into() }); return;
            }
            // C1: no legacy-format writes after migration (stale app.js). r3: checked
            // atomically with the write (permit held until it is done).
            let Some(_permit) = state.e2e_store.write_permit(username, e2e_blob_version(&blob)).await else {
                send_self(ServerEvent::Error { message: "E2E: this app version is out of date — reload the page".into() }); return;
            };
            // #13/#36: one canonical, injective sanitizer lives in e2e::safe_channel
            // (applied inside store_channel_key). Pass the raw channel through and echo
            // the same name so client, disk stem, and other devices never diverge;
            // non-canonical names are rejected as an Err below.
            match state.e2e_store.store_channel_key(username, &channel, &blob).await {
                Ok(_)  => {
                    // Notify ALL sessions so other devices load the new key
                    state.send_to_user(username, ServerEvent::E2EChannelKey {
                        channel, blob, req: None,
                    });
                }
                Err(e) => send(ServerEvent::Error { message: format!("E2E store channel key: {}", e) }),
            }
        }
        ClientMessage::E2ELoadChannelKey { channel, req } => {
            let blob = state.e2e_store.load_channel_key(username, &channel).await;
            if blob.is_some() || req.is_some() {
                send_self(ServerEvent::E2EChannelKey { channel, blob: blob.unwrap_or_default(), req });
            }
        }
        ClientMessage::E2EDeleteChannelKey { channel, v, req } => {
            let permit = if state.crypto.is_unlocked(username).await {
                state.e2e_store.write_permit(username, v.max(1)).await
            } else { None };
            let ok = permit.is_some() && state.e2e_store.delete_channel_key(username, &channel).await.is_ok();
            if let Some(req) = req { send_self(ServerEvent::E2EKeyDeleted { req, ok }); }
            else if !ok { send_self(ServerEvent::Error { message: "E2E: could not remove shared key; unlock the vault and reload if needed".into() }); }
            if !ok { return; }
            let channels = state.e2e_store.list_channel_keys(username).await;
            // r2 (v-e2e NEW-1): the upgraded client re-stores a mixed-case legacy PSK
            // (#MixCase) under its lowercased name and then deletes the original. The
            // channel still HAS a key, so this is not a key removal: broadcasting the list
            // made a still-open older tab (case-sensitive list handling) drop #MixCase
            // from memory and send that channel in cleartext. Only a real removal (no
            // case-insensitive copy left) is announced to the other sessions.
            let still_keyed = channels.iter().any(|c| c.to_lowercase() == channel.to_lowercase());
            if still_keyed {
                send_self(ServerEvent::E2EChannelList { channels });
            } else {
                // Notify ALL sessions of this user so other devices update the lock icon
                state.send_to_user(username, ServerEvent::E2EChannelList { channels });
            }
        }
        ClientMessage::E2EListChannelKeys {} => {
            let channels = state.e2e_store.list_channel_keys(username).await;
            send_self(ServerEvent::E2EChannelList { channels });
        }

        // Stale tabs can still send these. Confirmed pins sync in encrypted state.
        ClientMessage::E2ELegacyTrust {} => {}
        ClientMessage::E2ERelayX3DH { target_nick, header, conn_id } => {
            // Per-caller rate limit (mirrors E2EFetchBundle #27): this is the only
            // unthrottled high-volume, large-payload (<=64KiB) cross-user WRITE primitive.
            // Without a cap, an authenticated caller can flood a victim's 128-slot
            // broadcast faster than send_task drains it; a broadcast Lagged is treated as
            // fatal (Err(_) => break), force-closing the victim's WebSocket. 10/60s per
            // caller is ample — a real X3DH relay fires once per newly-initiated conversation.
            if state.auth.check_ws_kdf_rate_limit(username, "e2e_relay").is_err() {
                send_self(ServerEvent::Error { message: "Too many relay requests — slow down".into() });
                return;
            }
            // #49 + F10: bind the relayed X3DH header to the sender's OWN published bundle,
            // and REQUIRE one: a sender with no bundle could otherwise relay a header with
            // arbitrary identity keys and get them pinned on first contact. A legitimate
            // initiator always has a bundle (the responder needs it) and always builds the
            // header from the identity it published, so this only rejects forgeries.
            match state.e2e_store.bundle_identity_keys(username).await {
                Some((dh, sign)) => {
                    let hdr_ik   = header.get("sender_ik").and_then(|v| v.as_str()).unwrap_or("");
                    let hdr_sign = header.get("sender_sign_ik").and_then(|v| v.as_str()).unwrap_or("");
                    if hdr_ik != dh.as_str() || hdr_sign != sign.as_str() {
                        warn!("[E2E] refusing X3DH relay: header identity != published bundle");
                        send_self(ServerEvent::Error { message: "E2E relay refused: identity mismatch".into() });
                        return;
                    }
                }
                None => {
                    send_self(ServerEvent::Error { message: "E2E relay refused: no published key bundle".into() });
                    return;
                }
            }
            // Bound the header: a real X3DH header is ~500 bytes of JSON.
            if serde_json::to_string(&header).map(|s| s.len()).unwrap_or(usize::MAX) > 4096 {
                send_self(ServerEvent::Error { message: "E2E relay refused: header too large".into() });
                return;
            }
            let target: String = target_nick.chars().filter(|c| !c.is_control() && *c != ' ').take(64).collect();
            // F10: take from_nick from the connection the client says it is talking on (it
            // must own it), so a user on several networks is labelled with the right nick,
            // and scope the target lookup to that same network. Old clients send no conn_id:
            // fall back to the previous behaviour (first live connection of the sender).
            let asked_conn = conn_id.is_some();
            let sender_conn = conn_id.filter(|c| state.owns_conn(username, c));
            if asked_conn && sender_conn.is_none() {
                send_self(ServerEvent::Error { message: "E2E relay refused: unknown connection".into() });
                return;
            }
            // r6 (codex P2 main.rs:6796): from_nick is the nick the IRC server CONFIRMED on a
            // connected + registered connection. ensure_connection_entry seeds `nick` from
            // the saved config, so a connection still registering (or backing off after a
            // failed login) carried whatever nick its config named — anyone could relay a
            // first-contact header labelled with another person's nick.
            let registered_nick = |c: &irc::IrcConnection| {
                (c.connected && c.registered && !c.nick.is_empty()).then(|| c.nick.clone())
            };
            // r7 (codex P1/P2 main.rs:6914): the sender's nick and the recipient are ALWAYS
            // taken from the same network. Without a conn_id (an older cached app.js, or
            // e2e.js with no active network — it also sends the header inline over IRC),
            // the old path took a registered nick from ANY of the sender's connections and
            // resolved the recipient globally: a nick registered on the sender's own server
            // could be presented to someone on another network (misleading first contact,
            // or a key-change block on an existing pin). Now each of the sender's registered
            // connections is tried with resolve_nick_on_network (the recipient must hold the
            // nick on THAT connection's network); the relay goes out only if exactly one
            // recipient account results, labelled with the sender's nick on such a network.
            let (sender_nick, target_user) = match &sender_conn {
                Some(cid) => {
                    let conn = state.connections.get(cid).map(|c| c.clone());
                    let nick = match conn { Some(conn) => registered_nick(&*conn.lock().await), None => None };
                    let Some(nick) = nick else {
                        send_self(ServerEvent::Error { message: "E2E relay refused: that connection is not registered on IRC yet".into() });
                        return;
                    };
                    (nick, state.resolve_nick_on_network(&target, username, cid).await)
                }
                None => {
                    let mut conn_ids: Vec<String> = state.conn_owners.iter()
                        .filter(|e| e.value() == username)
                        .map(|e| e.key().clone()).collect();
                    conn_ids.sort();
                    let mut any_registered = false;
                    let mut hits: Vec<(String, String)> = Vec::new();   // (sender nick, recipient)
                    for cid in conn_ids {
                        // #20: clone the Arc out and drop the DashMap Ref before awaiting.
                        let conn = state.connections.get(&cid).map(|c| c.clone());
                        let Some(conn) = conn else { continue };
                        let Some(nick) = registered_nick(&*conn.lock().await) else { continue };
                        any_registered = true;
                        if let Some(t) = state.resolve_nick_on_network(&target, username, &cid).await {
                            hits.push((nick, t));
                        }
                    }
                    if !any_registered {
                        send_self(ServerEvent::Error { message: "E2E relay refused: that connection is not registered on IRC yet".into() });
                        return;
                    }
                    let mut recipients: Vec<&str> = hits.iter().map(|(_, t)| t.as_str()).collect();
                    recipients.sort();
                    recipients.dedup();
                    if recipients.len() > 1 {
                        send_self(ServerEvent::Error { message: "E2E relay refused: that nick belongs to different users on your networks — reload the page to update CryptIRC".into() });
                        return;
                    }
                    match hits.into_iter().next() {
                        Some((nick, t)) => (nick, Some(t)),
                        None => (String::new(), None),
                    }
                }
            };
            if let Some(target_user) = target_user {
                // F17: no INFO log of who relays to whom.
                tracing::debug!("[E2E] relaying x3dh header");
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
                send_self(ServerEvent::E2EOTPKLow { remaining });
            }
        }
        // ── C1: client-held keyring ───────────────────────────────────────────
        ClientMessage::E2ELoadKeyring {} => {
            let (blob, migrated) = state.e2e_store.load_keyring(username).await.unwrap_or_default();
            let has_identity = state.e2e_store.load_identity_enc(username).await.map(|b| !b.is_empty()).unwrap_or(false);
            // Which DM peers / channels have stored E2E state. A browser that can't unlock
            // E2E yet uses this to BLOCK sends to them instead of sending cleartext. (The
            // server already knows these names: they are its own file names.)
            let peers: Vec<String> = state.e2e_store.list_sessions(username).await
                .into_iter().filter(|p| !p.starts_with("__")).collect();
            let channels = state.e2e_store.list_channel_keys(username).await;
            let needs_legacy = !migrated && state.e2e_store.needs_legacy_key(username).await.unwrap_or(true);
            send_self(ServerEvent::E2EKeyring { blob, migrated, has_identity, needs_legacy, peers, channels });
        }
        ClientMessage::E2EStoreKeyring { blob, migrated, expect } => {
            if !blob.starts_with("e2k3.") {
                send_self(ServerEvent::Error { message: "E2E: reload the app to set up a recovery keyring".into() }); return;
            }
            if !state.crypto.is_unlocked(username).await {
                send_self(ServerEvent::Error { message: "Vault must be unlocked to store the E2E keyring".into() }); return;
            }
            // r2: compare-and-swap (see E2EStore::store_keyring). On a conflict nothing is
            // written and the current keyring comes back for the client to adopt.
            match state.e2e_store.store_keyring(username, &blob, migrated, expect.as_deref()).await {
                Ok((eff, None)) => send_self(ServerEvent::E2EKeyringStored { migrated: eff, conflict: false, blob: None }),
                Ok((eff, Some(cur))) => send_self(ServerEvent::E2EKeyringStored { migrated: eff, conflict: true, blob: Some(cur) }),
                Err(e)  => send_self(ServerEvent::Error { message: format!("E2E store keyring: {}", e) }),
            }
        }
        ClientMessage::E2ERewrapBlob { slot, name, expect, blob } => {
            let ok = expect.len() <= WS_MAX_MSG_BYTES && blob.len() <= WS_MAX_MSG_BYTES
                && state.crypto.is_unlocked(username).await &&
                state.e2e_store.rewrap_v2_blob(username, &slot, &name, &expect, &blob).await.unwrap_or(false);
            send_self(ServerEvent::E2EBlobRewrapped { slot, name, ok });
        }
        ClientMessage::E2EListSessions {} => {
            let partners = state.e2e_store.list_sessions(username).await;
            send_self(ServerEvent::E2ESessionList { partners });
        }
        ClientMessage::SaveAppearance { settings } => {
            // Limit to 4KB to prevent abuse; require well-formed JSON that is also an
            // object AND passes a structural safety check (#51) before we persist it and
            // fan it out to every one of this user's sessions — this closes the untrusted-
            // data channel into the client theme sink without enumerating individual keys
            // (so custom themes + future settings keep syncing).
            let parsed = if settings.len() <= 4096 {
                serde_json::from_str::<serde_json::Value>(&settings).ok()
            } else {
                None
            };
            if parsed.as_ref().map_or(false, |v| v.is_object() && appearance_json_is_safe(v, 0)) {
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
            let lock = preferences_lock(username);
            let _guard = lock.lock().await;
            if let Err(message) = save_preferences(state, username, prefs).await {
                if message != PREFERENCES_VAULT_LOCKED { send(ServerEvent::Error { message }); }
            }
        }
        ClientMessage::LoadPreferences {} => {
            let lock = preferences_lock(username);
            let _guard = lock.lock().await;
            if state.crypto.is_unlocked(username).await {
                let dir = std::path::PathBuf::from(&state.data_dir)
                    .join("users").join(&safe_username(username));
                let enc_path = dir.join("preferences.enc");
                // Prefer the encrypted file if present
                if tokio::fs::metadata(&enc_path).await.is_ok() {
                    match load_user_secret(state, username, "preferences.enc").await {
                        UserSecretLoad::Plain(p) => send_bulk_to_user(username, ServerEvent::Preferences { prefs: p }),
                        // F8: an undecryptable file is moved aside (not silently replaced
                        // by the client's next save) and the user is told; the empty
                        // payload keeps every client's load flow unchanged.
                        UserSecretLoad::Undecryptable(msg) => {
                            send(ServerEvent::Error { message: msg });
                            send_bulk_to_user(username, ServerEvent::Preferences { prefs: String::new() });
                        }
                        UserSecretLoad::Missing | UserSecretLoad::Locked => send_bulk_to_user(username, ServerEvent::Preferences { prefs: String::new() }),
                    }
                } else {
                    // Legacy plaintext migration: if an old preferences.json exists
                    // from before prefs-encryption was added, read it, send it to
                    // the client, and re-encrypt it on disk. The client will also
                    // trigger a save on next prefs change which re-writes .enc too.
                    let legacy = dir.join("preferences.json");
                    if let Ok(data) = tokio::fs::read_to_string(&legacy).await {
                        send_bulk_to_user(username, ServerEvent::Preferences { prefs: data.clone() });
                        if let Ok(enc) = state.crypto.encrypt(username, data.as_bytes()).await {
                            // F8: delete the plaintext only once the encrypted copy is
                            // durably on disk (a failed write used to lose both).
                            if write_user_file_atomic(&enc_path, enc.as_bytes()).await.is_ok() {
                                let _ = tokio::fs::remove_file(&legacy).await;
                            }
                        }
                    }
                }
            } else {
                // Vault locked — return empty so client can proceed with defaults.
                send_bulk_to_user(username, ServerEvent::Preferences { prefs: String::new() });
            }
        }
        ClientMessage::SaveBotConfig { config } => {
            // Bot config is deliberately NOT vault-encrypted (server-readable so the
            // bots run 24/7 while the vault is locked). Validate + size-cap, persist
            // to disk, and refresh the in-memory cache the trigger dispatch reads.
            if config.len() > 65536 {
                send(ServerEvent::Error { message: "Bot config too large".into() });
            } else {
                info!("bots: save request from {} ({} bytes)", username, config.len());
                match serde_json::from_str::<bots::BotConfig>(&config) {
                    Err(e) => {
                        // A rejected save used to be near-invisible: the panel showed
                        // its own optimistic "Bots saved" toast while the server threw
                        // the config away, so every toggle silently reverted on reload.
                        warn!("bots: save REJECTED for {} — malformed config: {}", username, e);
                        send(ServerEvent::Error { message: format!("Bot config rejected: {}", e) });
                    }
                    Ok(cfg) => {
                        match bots::save(&state.data_dir, username, &cfg).await {
                            Ok(()) => {
                                info!("bots: saved for {} (master={})", username, cfg.enabled);
                                // r7: config + its generation installed in one step; enforcement
                                // queued under the previous config is discarded (bots::install_config).
                                bots::install_config(&state.bots, username, cfg);
                                // Echo the canonical stored form back to all of this
                                // user's sessions so every device stays in sync.
                                if let Some(c) = state.bots.get(username) {
                                    if let Ok(js) = serde_json::to_string(&*c) {
                                        state.send_to_user(username, ServerEvent::BotConfig { config: js });
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("bots: DISK WRITE failed for {}: {}", username, e);
                                send(ServerEvent::Error { message: format!("Bot config save failed: {}", e) });
                            }
                        }
                    }
                }
            }
        }
        ClientMessage::LoadBotConfig {} => {
            let js = state.bots.get(username)
                .and_then(|c| serde_json::to_string(&*c).ok())
                .unwrap_or_else(|| "{}".to_string());
            send(ServerEvent::BotConfig { config: js });
            // Tell the UI which AI providers already have a key (masked; no key value).
            let providers = bots::ai_providers_with_keys(&state, username).await;
            send(ServerEvent::AiKeysSet { providers });
        }
        ClientMessage::AiDo { conn_id, target, query } => {
            // IDOR guard: this account must OWN the connection it's driving. Without
            // this, a user could pass another user's conn_id and run the AI (op/kick/
            // ban/PRIVMSG) through the victim's connection. Matches the Send handler.
            if !state.owns_conn(username, &conn_id) { return; }
            let q = query.trim();
            // Sanitize the target before it reaches any raw IRC line (a WS string can
            // carry a decoded \r/\n).
            let target = cryptirc::ircproto::strip_crlf(&target);
            if target.is_empty() || target.contains(' ') {
                send(ServerEvent::BotResult { bot: "ai".into(), text: "invalid channel".into() });
            } else if !target.starts_with(['#','&','+','!']) {
                send(ServerEvent::BotResult { bot: "ai".into(), text: "/aido must be used in a channel".into() });
            } else if q.is_empty() {
                send(ServerEvent::BotResult { bot: "ai".into(), text: "usage: /aido <what to do>".into() });
            } else if q.len() > 4000 {
                send(ServerEvent::BotResult { bot: "ai".into(), text: "AI: message too long".into() });
            } else if let Some(conn) = state.connections.get(&conn_id).map(|c| c.clone()) {
                // The owner is inherently trusted, so actions are allowed whenever the
                // commands toggle is on. YOLO (unrestricted raw commands) is ONLY
                // honored here, on the owner's own /aido input — never channel/DM.
                let (allow, yolo) = state.bots.get(username)
                    .map(|c| (c.ai.commands_enabled, c.ai.commands_enabled && c.ai.commands_yolo))
                    .unwrap_or((false, false));
                let st = state.clone();
                // r4 C1-1: the reply belongs to the account as it is now (see AcctTicket).
                let acct = bots::AcctTicket::take(state, username);
                let (cid, tgt, query) = (conn_id.clone(), target.clone(), q.to_string());
                tokio::spawn(async move {
                    // r7 (codex P1 bots.rs:1735): bound to THIS connection — if it is closed or
                    // replaced (network edited, Disconnect + Connect) before the AI answers, the
                    // actions and the reply are not sent; the owner sees the reply privately.
                    let ct = bots::ConnTicket::take(&cid, &conn).await;
                    // /aido shares the owner's private AI conversation ("__owner__").
                    let reply = bots::run_ai_channel(&st, &acct, bots::OWNER_CONV, &ct, &tgt, allow, yolo, &query).await;
                    if reply.is_empty() || !acct.live(&st) { return; }
                    // r4 C1-3 (integrator decision): the AI's reply is never posted in plaintext
                    // to a channel with E2E state. /aido's actions still ran; the reply is shown
                    // to the owner only, with the reason, instead of being posted.
                    if let Some(name) = bots::e2e_protected_target(&st, acct.user(), &tgt).await {
                        acct.deliver(&st, ServerEvent::BotResult { bot: "ai".into(), text: format!(
                            "⛔ /aido reply NOT posted to {}: end-to-end encryption is on there, and AI output \
                             can't be encrypted, so it would have gone out in plaintext. The reply (only you see \
                             this): {}", name, reply) });
                        return;
                    }
                    // Argon P1 (main.rs:6460): bot_say, not bot_send — a raw send is never
                    // echoed back to the owner's own sessions nor logged, so the owner saw
                    // nothing of the reply everyone else in the channel saw. (bot_say re-checks
                    // E2E state right before sending.)
                    bots::bot_say_owner(&st, &acct, &ct, &tgt, &reply).await;   // r6: the owner chose the target
                });
            } else {
                send(ServerEvent::BotResult { bot: "ai".into(), text: "AI: not connected to that network".into() });
            }
        }
        ClientMessage::ClearAiHistory {} => {
            bots::ai_history_clear(username, None);
        }
        ClientMessage::SaveAiKey { provider, key } => {
            // 32 KB: a plain key is tiny, but the Codex "openai-codex" bundle is a JSON
            // blob with two JWTs (access + id token), so allow more headroom.
            if key.len() > 32768 {
                send(ServerEvent::Error { message: "AI key/token too long".into() });
            } else {
                match bots::save_ai_key(&state, username, &provider, &key).await {
                    Ok(()) => {
                        let providers = bots::ai_providers_with_keys(&state, username).await;
                        state.send_to_user(username, ServerEvent::AiKeysSet { providers });
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("AI key: {}", e) }),
                }
            }
        }
        ClientMessage::BotQuery { bot, query, conn_id, channel } => {
            // Owner's private lookup (/w, /ud). Bounded query; result returns to the
            // owner's UI only, never a channel. Works regardless of bot enabled state.
            let q = query.trim();
            if matches!(bot.as_str(), "quotedb" | "seen" | "tell" | "note") {
                // Stateful bots the owner drives privately. `channel` is the owner's
                // active channel (needed by quotedb/tell); the reply returns to their UI.
                if q.len() > 400 { send(ServerEvent::BotResult { bot, text: "too long".into() }); }
                else {
                    let cid = if !conn_id.is_empty() && state.owns_conn(username, &conn_id) { conn_id } else { String::new() };
                    bots::run_private_stateful(&state, username, &bot, &cid, &channel, q);
                }
            } else if bot == "ai" {
                // AI prompts can be long; allow a bigger cap than the keyless bots.
                if q.is_empty() {
                    send(ServerEvent::BotResult { bot, text: "usage: /ai <message>".into() });
                } else if q.len() > 4000 {
                    send(ServerEvent::BotResult { bot, text: "AI: message too long".into() });
                } else {
                    // Only honor a conn_id the owner actually owns (IDOR guard); else
                    // fall back to no-awareness chat.
                    let cid = if !conn_id.is_empty() && state.owns_conn(username, &conn_id) { conn_id } else { String::new() };
                    bots::run_private_ai(&state, username, q, &cid);
                }
            } else {
                // These bots work with no argument (joke/quote/fact/coin/8ball/roll).
                let no_arg = matches!(bot.as_str(), "joke" | "quote" | "fact" | "coin" | "eightball" | "roll");
                if q.len() > 200 || (q.is_empty() && !no_arg) {
                    send(ServerEvent::BotResult { bot: bot.clone(), text: "usage: give a location/term".into() });
                } else if matches!(bot.as_str(),
                    "weather" | "ud" | "wiki" | "define" | "crypto"
                    | "time" | "cc" | "joke" | "quote" | "fact" | "eightball" | "roll" | "coin") {
                    bots::run_private_query(&state, username, &bot, q);
                } else {
                    send(ServerEvent::BotResult { bot, text: "unknown bot".into() });
                }
            }
        }
        ClientMessage::SaveNotepad { content } => {
            if content.len() > 1_000_000 { send(ServerEvent::Error { message: "Notepad too large (max 1MB)".into() }); }
            else if state.crypto.is_unlocked(username).await {
                match state.crypto.encrypt(username, content.as_bytes()).await {
                    Ok(enc) => {
                        let dir = std::path::PathBuf::from(&state.data_dir).join("users").join(&safe_username(username));
                        let _ = tokio::fs::create_dir_all(&dir).await;
                        // F8: crash-safe tmp+fsync+rename (a failed in-place write used to
                        // truncate the only copy) and the failure is reported, not dropped.
                        if let Err(e) = write_user_file_atomic(&dir.join("notepad.enc"), enc.as_bytes()).await {
                            warn!("{}: notepad.enc save failed: {}", username, e);
                            send(ServerEvent::Error { message: format!("Notepad save failed: {} — your previous copy is unchanged", e) });
                        }
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadNotepad {} => {
            if state.crypto.is_unlocked(username).await {
                match load_user_secret(state, username, "notepad.enc").await {
                    UserSecretLoad::Plain(pt) => send_bulk_to_user(username, ServerEvent::Notepad { content: pt }),
                    // F8: tell the user (and keep the damaged file aside) instead of
                    // presenting it as empty; the empty payload keeps old clients' flow.
                    UserSecretLoad::Undecryptable(msg) => {
                        send(ServerEvent::Error { message: msg });
                        send_bulk_to_user(username, ServerEvent::Notepad { content: String::new() });
                    }
                    UserSecretLoad::Locked => send(ServerEvent::Error { message: "Vault locked".into() }),
                    UserSecretLoad::Missing => send_bulk_to_user(username, ServerEvent::Notepad { content: String::new() }),
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
                        // F8: crash-safe tmp+fsync+rename (a failed in-place write used to
                        // truncate the only copy) and the failure is reported, not dropped.
                        if let Err(e) = write_user_file_atomic(&dir.join("stats.enc"), enc.as_bytes()).await {
                            warn!("{}: stats.enc save failed: {}", username, e);
                            send(ServerEvent::Error { message: format!("Stats save failed: {} — your previous copy is unchanged", e) });
                        }
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadStats {} => {
            if state.crypto.is_unlocked(username).await {
                match load_user_secret(state, username, "stats.enc").await {
                    UserSecretLoad::Plain(pt) => send_bulk_to_user(username, ServerEvent::StatsData { data: pt }),
                    // F8: tell the user (and keep the damaged file aside) instead of
                    // presenting it as empty; the empty payload keeps old clients' flow.
                    UserSecretLoad::Undecryptable(msg) => {
                        send(ServerEvent::Error { message: msg });
                        send_bulk_to_user(username, ServerEvent::StatsData { data: String::new() });
                    }
                    UserSecretLoad::Locked => send(ServerEvent::Error { message: "Vault locked".into() }),
                    UserSecretLoad::Missing => send_bulk_to_user(username, ServerEvent::StatsData { data: String::new() }),
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
                        // F8: crash-safe tmp+fsync+rename (a failed in-place write used to
                        // truncate the only copy) and the failure is reported, not dropped.
                        if let Err(e) = write_user_file_atomic(&dir.join("passwords.enc"), enc.as_bytes()).await {
                            warn!("{}: passwords.enc save failed: {}", username, e);
                            send(ServerEvent::Error { message: format!("Password safe save failed: {} — your previous copy is unchanged", e) });
                        }
                    }
                    Err(e) => send(ServerEvent::Error { message: format!("Save failed: {}", e) }),
                }
            } else { send(ServerEvent::Error { message: "Vault locked".into() }); }
        }
        ClientMessage::LoadPasswords {} => {
            if state.crypto.is_unlocked(username).await {
                match load_user_secret(state, username, "passwords.enc").await {
                    UserSecretLoad::Plain(pt) => send_bulk_to_user(username, ServerEvent::PasswordSafe { data: pt }),
                    // F8: tell the user (and keep the damaged file aside) instead of
                    // presenting it as empty; the empty payload keeps old clients' flow.
                    UserSecretLoad::Undecryptable(msg) => {
                        send(ServerEvent::Error { message: msg });
                        send_bulk_to_user(username, ServerEvent::PasswordSafe { data: String::new() });
                    }
                    UserSecretLoad::Locked => send(ServerEvent::Error { message: "Vault locked".into() }),
                    UserSecretLoad::Missing => send_bulk_to_user(username, ServerEvent::PasswordSafe { data: String::new() }),
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
            crate::irc::discard_held_logs(username, None, None).await;
            // Delete logs for all this user's connections (F16: by config-file id, so a
            // config that fails to parse still has its logs cleared, plus F2 variants).
            for id in state.user_network_ids(username).await {
                // r3 C2-1: logs/<id>/ is keyed by the id alone — delete it only while this
                // account is the id's sole owner (fresh check + delete under the per-config
                // lock); a legacy id another account's config also names keeps its logs.
                let _cfg_lock = network_config_lock(username, &id);
                let _cfg_guard = _cfg_lock.lock().await;
                match network_id_ownership(&state, username, &id).await {
                    IdOwnership::Sole => { state.logger.delete_conn_logs(&id).await; }
                    IdOwnership::Shared => warn!("[{}] Clear All Data for {}: network id shared with another account — its logs are kept", id, username),
                    IdOwnership::Unverified => warn!("[{}] Clear All Data for {}: could not verify the network id's owners — its logs are kept", id, username),
                    IdOwnership::NotListed => {}
                }
            }
            // F16: ...and the history of networks REMOVED earlier (no config names
            // them any more). Ownership is proven by decrypting with this user's key.
            if state.crypto.is_unlocked(username).await {
                let keep = state.all_configured_network_ids().await;
                let n = state.logger.delete_unowned_user_logs(username, &keep).await;
                if n > 0 { info!("Cleared {} orphaned log dir(s) of removed networks for {}", n, username); }
            } else {
                info!("Vault locked during Clear All Data for {} — logs of removed networks need an unlocked vault to identify", username);
            }
            // Delete notepad
            let notepad_path = std::path::PathBuf::from(&state.data_dir)
                .join("users").join(&safe_username(username)).join("notepad.enc");
            let _ = tokio::fs::remove_file(&notepad_path).await;
            // ...and any damaged copies F8 moved aside (notepad.enc.corrupt.<ts>).
            if let Ok(mut rd) = tokio::fs::read_dir(std::path::PathBuf::from(&state.data_dir)
                .join("users").join(&safe_username(username))).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    if e.file_name().to_str().map_or(false, |n| n.starts_with("notepad.enc.corrupt.")) {
                        let _ = tokio::fs::remove_file(e.path()).await;
                    }
                }
            }
            // Delete pastes by this user. r6 (codex P1 main.rs:7284): through the store, so its
            // index and the per-account paste quota are updated at once — removing the files
            // directly left the quota charged until the hourly reconciliation, so a user told
            // to "Clear All Data" to free paste space stayed blocked. Same match as before
            // (the paste's `author` field equals the account name).
            let n = state.paste_store.delete_by_author(username).await;
            if n > 0 { info!("Clear All Data: {} paste(s) of {} deleted", n, username); }
            // r3 A1-14: the AI bot's in-memory conversation memory is chat history too.
            // What "Clear All Data" means (the confirm dialog lists it): chat history &
            // logs, the notepad and the user's paste posts. Kept on purpose: the account,
            // networks, Password Safe, uploads (My Uploads), preferences/appearance,
            // channel stats, AI keys and bot data — the dialog now says so.
            bots::ai_history_clear(username, None);
            info!("All data cleared for user: {}", username);
            // Broadcast to all user's sessions so other devices clear too
            state.send_to_user(username, ServerEvent::DataCleared {});
        }
        ClientMessage::ClearTargetLogs { conn_id, target } => {
            if !state.owns_network(username, &conn_id).await { return; }
            // r3 C2-1: logs/<id>/ is keyed by the id alone — only its sole owner may clear
            // it (check + delete under the per-config lock).
            let _cfg_lock = network_config_lock(username, &conn_id);
            let _cfg_guard = _cfg_lock.lock().await;
            match network_id_ownership(&state, username, &conn_id).await {
                IdOwnership::Sole => {}
                o @ (IdOwnership::Shared | IdOwnership::Unverified) => {
                    send(ServerEvent::Error { message: o.refusal().unwrap_or(CONTESTED_NETWORK_MSG).into() }); return;
                }
                IdOwnership::NotListed => return,
            }
            // r8 (agy P1 main.rs:7506): delete_target refuses while the vault is locked — then
            // nothing is cleared, so the lines held for this conversation must stay too.
            if !state.crypto.is_unlocked(username).await {
                send(ServerEvent::Error { message: "Clear failed: Vault locked".into() });
                return;
            }
            crate::irc::discard_held_logs(username, Some(&conn_id), Some(&target)).await;
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
            // rust-http #3: the Argon2 verify inside login() ran directly on the async
            // worker with no concurrency cap — run it on the blocking pool behind the
            // process-wide KDF cap. Busy → an `error` event (NOT auth_failed: the client
            // treats auth_failed as "session invalid" and logs the user out).
            let login_res = {
                let auth = state.auth.clone();
                let (uname, pw) = (username.to_string(), password.clone());
                crate::run_auth_kdf(move || async move { auth.login(&uname, &pw, Some(&uname)).await }).await
            };
            let Some(login_res) = login_res else {
                send(ServerEvent::Error { message: "Server busy — please try again in a moment.".into() });
                return;
            };
            match login_res {
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
        // F2: only a canonical id can be driven, so a re-cased duplicate that is
        // somehow still in conn_owners can never be used as a second connection.
        if is_noncanonical_network_id(conn_id) { return false; }
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
        // #1: the connection map is GLOBAL and carries no proof that a nick belongs to
        // any particular account, so a nick held by two or more DISTINCT accounts is
        // ambiguous — an attacker who nick-grabs a peer would otherwise be arbitrarily
        // picked and serve their own bundle/relay. Accumulate the single distinct owner;
        // a second distinct owner must refuse (None), not be arbitrarily selected.
        let mut owner: Option<String> = None;
        for conn_id in conn_ids {
            // Clone the Arc out and DROP the DashMap Ref before awaiting the Mutex —
            // holding a shard read-guard across .await blocks same-shard insert/remove
            // (connect/disconnect) and risks deadlock. Matches every other call site.
            let conn = self.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
                // r2 (codex-p2): only a connected + registered connection holds a nick.
                let (conn_nick, live) = {
                    let c = conn.lock().await;
                    (c.nick.clone(), c.connected && c.registered)
                };
                if live && conn_nick.to_lowercase() == nick_lower {
                    if let Some(o) = self.conn_owners.get(&conn_id) {
                        match &owner {
                            None => owner = Some(o.clone()),
                            Some(existing) if existing.as_str() == o.as_str() => {}
                            Some(_) => {
                                // r2 (v-e2e INFO-1): no nick in the log (contact metadata).
                                warn!("[E2E] refusing ambiguous nick resolution — multiple accounts hold it");
                                return None;
                            }
                        }
                    }
                }
            }
        }
        owner
    }

    /// F11: does any live connection on this server currently use IRC nick `nick`?
    async fn e2e_nick_is_held(&self, nick: &str) -> bool {
        let nick_lower = nick.to_lowercase();
        let conn_ids: Vec<String> = self.connections.iter().map(|e| e.key().clone()).collect();
        for conn_id in conn_ids {
            let conn = self.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
                let c = conn.lock().await;
                if c.connected && c.registered && c.nick.to_lowercase() == nick_lower { return true; }
            }
        }
        false
    }

    /// F10/F11: network identity of a connection: ISUPPORT NETWORK= name if seen, and
    /// the configured server host (lowercased) + port. Taken from the live connection's
    /// cached config when there is one, else from the owner's config file (no secret
    /// decryption needed).
    async fn e2e_conn_ident(&self, conn_id: &str, owner: &str) -> Option<e2e::NetIdent> {
        let safe_id = validate_uuid(conn_id)?;
        let live = self.connections.get(&safe_id).map(|c| c.clone());
        if let Some(conn) = live {
            let c = conn.lock().await;
            // codex P2 main.rs:6834 / agy P2: the endpoint the connection really dials
            // (irc.rs IrcConnection::dial_endpoint), not the editable saved config.
            let (host, port) = c.dial_endpoint.clone().unwrap_or_else(|| (c.cfg.server.clone(), c.cfg.port));
            if !host.trim().is_empty() {
                return Some(e2e::NetIdent::new(e2e::network_name(&safe_id), &host, port));
            }
        }
        let path = format!("{}/networks/{}/{}.json", self.data_dir, owner, safe_id);
        let json = tokio::fs::read_to_string(path).await.ok()?;
        let v: serde_json::Value = serde_json::from_str(&json).ok()?;
        let host = v.get("server")?.as_str()?.to_string();
        let port = v.get("port").and_then(|p| p.as_u64()).unwrap_or(0) as u16;
        Some(e2e::NetIdent::new(e2e::network_name(&safe_id), &host, port))
    }

    /// F10/F11: the CryptIRC account holding IRC nick `nick` ON THE CALLER'S NETWORK
    /// (`caller_conn`, which `caller` must own). Strict: no global fallback and no
    /// username==nick fallback — a holder of that nick on another network, or an account
    /// that merely registered that username, never matches.
    /// r2 (codex-p2 MED main.rs:6321, NEW-4, NEW-5):
    ///  - only a connection that is connected AND registered (the IRC server actually
    ///    assigned it that nick) counts — a config that merely names the nick, stuck
    ///    reconnecting to an unreachable port, proves nothing;
    ///  - candidates are ranked by how strongly they share the caller's network
    ///    (e2e::network_match_tier: same host+port > same host on another port with the
    ///    same NETWORK= name, or a host under the same allowlisted network domain). A
    ///    NETWORK= name alone never links two hosts and nothing is inferred from DNS
    ///    suffixes. Only the best tier that has any holder is used, so a look-alike ircd
    ///    can neither be preferred over nor make ambiguous the real holder on the
    ///    caller's own server. Within that tier: exactly one distinct owner, or None.
    async fn resolve_nick_on_network(&self, nick: &str, caller: &str, caller_conn: &str) -> Option<String> {
        self.resolve_e2e_peer(nick, caller, caller_conn).await.ok().flatten()
    }

    async fn resolve_e2e_peer(&self, nick: &str, caller: &str, caller_conn: &str) -> Result<Option<String>, ()> {
        if nick.is_empty() || !self.owns_conn(caller, caller_conn) { return Err(()); }
        let scope = self.e2e_conn_ident(caller_conn, caller).await.ok_or(())?;
        // r5 (codex P1 main.rs:7399): nicks compared the way the caller's network compares
        // them (its CASEMAPPING, + NFKC with UTF8MAPPING=rfc8265), never wider — Unicode
        // lowercase failed `Bob{Work}` vs the holder's `Bob[Work]` on an rfc1459 network
        // (bundle fetch / X3DH relay refused) and equated `É…`/`é…`, two different nicks on
        // an ascii one. Candidates are on the same network (network_match_tier below).
        let caller_cm = {
            let live = self.connections.get(caller_conn).map(|c| c.clone());
            let scm = match live { Some(c) => c.lock().await.server_casemapping, None => None };
            scm.or_else(|| crate::irc::known_casemapping(caller_conn))
        };
        let rfc8265 = e2e::utf8mapping_is_rfc8265(caller_conn);
        let fold = |n: &str| e2e_nick_fold(caller_cm, rfc8265, n);
        let nick_lower = fold(nick);
        let conn_ids: Vec<String> = self.connections.iter().map(|e| e.key().clone()).collect();
        // best tier seen so far, its single owner, and whether that tier is ambiguous
        let mut best: (u8, Option<String>, bool) = (0, None, false);
        for conn_id in conn_ids {
            if conn_id == caller_conn { continue; }
            let conn = self.connections.get(&conn_id).map(|c| c.clone());
            let Some(conn) = conn else { continue };
            let (conn_nick, live) = { let c = conn.lock().await; (c.nick.clone(), c.connected && c.registered) };
            if !live || fold(&conn_nick) != nick_lower { continue; }
            let Some(o) = self.conn_owners.get(&conn_id).map(|o| o.clone()) else { continue };
            let Some(ident) = self.e2e_conn_ident(&conn_id, &o).await else { continue };
            let tier = e2e::network_match_tier(&scope, &ident);
            if tier == 0 || tier < best.0 { continue; }
            if tier > best.0 { best = (tier, Some(o), false); continue; }
            if best.1.as_deref() != Some(o.as_str()) { best.2 = true; }
        }
        if best.2 {
            warn!("[E2E] refusing ambiguous nick resolution — multiple accounts hold it on one network");
            return Err(());
        }
        Ok(best.1)
    }

    async fn owns_network(&self, username: &str, id: &str) -> bool {
        // F2: the old get_network_config fallback lower-cased the id to find the
        // file, so ANY re-casing of the caller's own id counted as owned and then
        // became a brand-new conn_id. Only the canonical spelling is accepted now
        // (handle_command canonicalises every id before it gets here).
        match validate_uuid(id) {
            Some(c) if c == id => {}
            _ => return false,
        }
        if let Some(owner) = self.conn_owners.get(id) {
            return owner.as_str() == username;
        }
        self.get_network_config(id, username).await.is_some()
    }

    pub async fn user_network_states(&self, username: &str) -> Vec<NetworkState> {
        let mut out = Vec::new();
        for cfg in self.load_user_configs(username).await {
            // r4 C2-3: the live connection (nick, channels, topics, member lists) and the
            // id-keyed cert are shown only when they are THIS account's: `connections` /
            // certs/<id>/ are keyed by the network id alone, and a legacy (pre-#23) config
            // may name an id another account's session holds — the snapshot used to hand
            // that account's channel state (private-channel membership included) to
            // anyone whose config named the id. A session is this account's when
            // conn_owners says so (every claim sets it before dialing, see claim_and_dial).
            let held_by_other = self.conn_owners.get(&cfg.id).map_or(false, |o| o.as_str() != username);
            // #20: clone the Arc out and drop the DashMap Ref before awaiting the
            // connection Mutex, so we never hold a shard read-guard across the await.
            let conn = if self.owns_conn(username, &cfg.id) {
                self.connections.get(&cfg.id).map(|c| c.clone())
            } else { None };
            let (connected, nick, channels, lag_ms, (reactions, reaction_dislike)) = if let Some(conn) = conn {
                let c   = conn.lock().await;
                // The channel's display spelling (as the server announced it), not the
                // map key: that is a case FOLD (#92), which for `#Foo[Bar]` is
                // `#foo{bar}` — a different log target and browser buffer than the
                // `#foo[bar]` every JOIN/PRIVMSG event uses, so after a reload such a
                // channel came back as a second, history-less row.
                let chs = c.channels.values().map(|cs| ChannelState {
                    name: cs.name.clone(), topic: cs.topic.clone(), names: cs.names.clone()
                }).collect();
                (c.connected, c.nick.clone(), chs, c.lag_ms, reactions::support(&c))
            } else { (false, cfg.nick.clone(), vec![], None, (false, false)) };

            // Include cert info (r4 C2-3: not another account's, see above)
            let has_cert = !held_by_other && self.certs.exists(&cfg.id).await;
            let cert_fingerprint = if has_cert {
                self.certs.load_info(&cfg.id).await.ok().map(|i| i.fingerprint)
            } else { None };

            let casemapping = crate::irc::known_casemapping(&cfg.id).map(|m| m.token().to_string());
            out.push(NetworkState { config: cfg, connected, reactions, reaction_dislike, nick, channels, lag_ms, has_cert, cert_fingerprint, casemapping });
        }
        out
    }

    pub async fn reconnect_for_user(&self, username: &str) {
        for cfg in self.load_user_configs(username).await {
            let id = cfg.id.clone();
            // Already live — most likely reattached from a daemon that was
            // still running across a web-process restart (see ipc_client's
            // Attach/AttachComplete reconciliation, which runs once at process
            // startup, independent of any user's login timing). Nothing to do;
            // unlike the old per-process model, "connected" can now already be
            // true the very first time a freshly-logged-in session checks.
            if self.connections.contains_key(&id) || self.disconnect_requested(&id) { continue; }
            // C-1 completion: this is the FOURTH mutator of conn_owners + Dial (after
            // Connect/Disconnect/RemoveNetwork). Take the SAME per-config lock and re-read
            // the config INSIDE it, so a two-tab UnlockVault(this) + RemoveNetwork(id) race
            // can't re-insert conn_owners + Dial a live socket for a network whose config
            // was just deleted — the exact orphan C-1 prevents, reached via the reconnect
            // path instead of Connect. A RemoveNetwork that won the lock first → the fresh
            // get_network_config returns None → we skip. (Sole caller holds no lock across
            // this; dial_current never re-acquires the config lock → no deadlock.)
            let _cfg_lock = network_config_lock(username, &id);
            let _cfg_guard = _cfg_lock.lock().await;
            if self.connections.contains_key(&id) || self.disconnect_requested(&id) { continue; }
            let Some(fresh) = self.get_network_config(&id, username).await else { continue };
            // agy P2 main.rs:6378: an explicitly disconnected network (Disconnect button /
            // /quit) earlier in this web process, not reconnected since, must not be undone
            // by a vault lock+unlock. NOTE (integrator decision): Auto-Reconnect = No is
            // deliberately NOT a reason to skip here — the setting is labelled "Auto-
            // Reconnect: Yes (exponential backoff)" and governs reconnecting after a DROP
            // (the daemon + Attach reconciliation apply it). Connecting a user's networks
            // when they log in / unlock has always included those networks; changing that
            // would leave them offline on every login.
            if user_disconnected(&id) {
                info!("[{}] not reconnecting on unlock for {}: the user disconnected it", id, username);
                continue;
            }
            // r3 C2-1: never take over a (legacy, colliding) network id that another
            // account's live session holds. (r4: claim_and_dial re-checks this under the
            // id-wide claim lock, after every await.)
            if self.conn_owners.get(&id).map_or(false, |o| o.as_str() != username) {
                warn!("[{}] not reconnecting on unlock for {}: the id is held by another account's session", id, username);
                continue;
            }
            // r3 A2-3: a Lock that raced this unlock — don't dial without the credentials.
            if self.dial_deferred_for_locked_vault(username, &fresh).await { continue; }
            if claim_and_dial(self, username, fresh, false).await == ClaimOutcome::HeldByOther {
                warn!("[{}] not reconnecting on unlock for {}: the id is held by another account's session", id, username);
            }
        }
    }

    /// r3 A2-3: true when `username`'s vault is locked AND `cfg` (as get_network_config
    /// returned it, i.e. still holding the at-rest values) needs the vault to dial
    /// correctly: an encrypted server/SASL/oper/NickServ password, channel key or
    /// perform command, or a client certificate (its key is vault-encrypted).
    /// build_dial_params would silently drop all of those and connect unauthenticated.
    pub(crate) async fn dial_deferred_for_locked_vault(&self, username: &str, cfg: &NetworkConfig) -> bool {
        if self.crypto.is_unlocked(username).await { return false; }
        let enc = |v: &Option<String>| v.as_deref().map_or(false, Self::is_enc_blob);
        let needs = enc(&cfg.password)
            || enc(&cfg.oper_pass)
            || enc(&cfg.nickserv_pass)
            || cfg.sasl_plain.as_ref().map_or(false, |s| Self::is_enc_blob(&s.password))
            || cfg.channel_keys.values().any(|v| Self::is_enc_blob(v))
            || cfg.perform_commands.iter().any(|c| Self::is_enc_blob(c));
        if needs { return true; }
        match &cfg.client_cert_id {
            Some(cert_id) => self.certs.exists(cert_id).await,
            None => false,
        }
    }

    /// #F31: compute the at-rest value for one credential field, hardened against a vault
    /// Lock/Unlock that races between the get_network_config (read/decrypt) and save_network
    /// (re-encrypt) of the same read-modify-write:
    ///   • an already-"enc:" `incoming` (e.g. a value read back while the vault was locked, so
    ///     get_network_config never decrypted it) is persisted verbatim — never re-encrypted
    ///     into enc:<E(enc:…)>, which would irrecoverably corrupt the credential;
    ///   • when the vault is unlocked, plaintext is encrypted the normal way;
    ///   • when the vault is locked we cannot encrypt, so rather than write the plaintext a
    ///     prior unlocked read handed us (leaking the credential at rest) we keep the prior
    ///     on-disk "enc:" blob if one exists.
    /// The "enc:" sentinel matches how the credentials are wrapped below (crypto::encrypt
    /// returns bare base64; this module prefixes it with "enc:").
    async fn encrypt_cred_field(&self, username: &str, unlocked: bool, incoming: &str, on_disk: Option<&str>) -> anyhow::Result<String> {
        if Self::is_enc_blob(incoming) {
            return Ok(incoming.to_string()); // already an encrypted blob — persist verbatim
        }
        if unlocked {
            let enc = self.crypto.encrypt(username, incoming.as_bytes()).await?;
            return Ok(format!("enc:{}", enc));
        }
        match on_disk {
            Some(d) if Self::is_enc_blob(d) => Ok(d.to_string()), // never overwrite enc: with plaintext
            _ => Ok(incoming.to_string()),
        }
    }

    /// True only for values that are genuinely our "enc:"-wrapped AEAD blobs: "enc:" followed by
    /// base64 that decodes to at least NONCE(12)+TAG(16)=28 bytes (crypto::encrypt's minimum
    /// output). #F31-regression: the bare `starts_with("enc:")` check treated a *plaintext*
    /// credential that merely begins with the literal "enc:" (e.g. "enc:hunter2") as an already-
    /// encrypted blob and stored it verbatim in cleartext at rest. Validating the base64 length
    /// disambiguates a real blob from such a plaintext, while still catching a genuine blob read
    /// back undecrypted (locked vault) so it is never double-encrypted.
    pub(crate) fn is_enc_blob(s: &str) -> bool {
        let Some(rest) = s.strip_prefix("enc:") else { return false };
        matches!(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, rest), Ok(b) if b.len() >= 28)
    }

    pub async fn save_network(&self, cfg: &NetworkConfig, username: &str) -> anyhow::Result<()> {
        self.save_network_with_vault_policy(cfg, username, false).await
    }

    async fn save_network_with_vault_policy(&self, cfg: &NetworkConfig, username: &str, require_vault: bool) -> anyhow::Result<()> {
        let safe_id = validate_uuid(&cfg.id).ok_or_else(|| anyhow::anyhow!("Invalid network id"))?;
        let dir     = format!("{}/networks/{}", self.data_dir, username);
        tokio::fs::create_dir_all(&dir).await?;

        // S2: If vault is unlocked, encrypt sensitive fields before persisting.
        // We store an encrypted variant so server-password and SASL credentials
        // are never written to disk in plaintext.
        let mut persisted = cfg.clone();
        // F2: the stored id is always the canonical one (= the file stem).
        persisted.id = safe_id.clone();

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
        // #F31: capture the vault-unlock state ONCE for this read-modify-write, and load the
        // currently-persisted (raw, un-decrypted) config so a vault Lock/Unlock racing between
        // the get_network_config that produced `cfg` and this save can't corrupt the at-rest
        // credentials. encrypt_cred_field never double-encrypts an already-"enc:" blob and never
        // overwrites an on-disk "enc:" value with plaintext while the vault is locked.
        let unlocked  = self.crypto.is_unlocked(username).await;
        if require_vault && !unlocked {
            anyhow::bail!("Unlock the vault in CryptIRC first.");
        }
        let existing: Option<NetworkConfig> = tokio::fs::read_to_string(format!("{}/{}.json", dir, safe_id))
            .await.ok()
            .and_then(|j| serde_json::from_str(&j).ok());
        if let Some(ref p) = cfg.password {
            persisted.password = Some(self.encrypt_cred_field(username, unlocked, p,
                existing.as_ref().and_then(|e| e.password.as_deref())).await?);
        }
        if let Some(ref sc) = cfg.sasl_plain {
            persisted.sasl_plain = Some(crate::SaslConfig {
                account:  sc.account.clone(),
                password: self.encrypt_cred_field(username, unlocked, &sc.password,
                    existing.as_ref().and_then(|e| e.sasl_plain.as_ref()).map(|s| s.password.as_str())).await?,
            });
        }
        if let Some(ref p) = cfg.oper_pass {
            if !p.is_empty() {
                persisted.oper_pass = Some(self.encrypt_cred_field(username, unlocked, p,
                    existing.as_ref().and_then(|e| e.oper_pass.as_deref())).await?);
            }
        }
        if let Some(ref p) = cfg.nickserv_pass {
            if !p.is_empty() {
                persisted.nickserv_pass = Some(self.encrypt_cred_field(username, unlocked, p,
                    existing.as_ref().and_then(|e| e.nickserv_pass.as_deref())).await?);
            }
        }
        // codex P1 main.rs:6462: channel keys are channel passwords and perform commands
        // routinely carry `/msg NickServ IDENTIFY <pw>` — credentials like the fields
        // above, so each VALUE is wrapped the same way ("enc:" + AEAD blob, decrypted by
        // get_network_config, verbatim when already a blob, plaintext only while the
        // vault is locked until the next unlock re-encrypts it — F7). Channel NAMES (the
        // map keys) stay plaintext, like auto_join. Old plaintext files stay readable.
        let mut keys_at_rest = std::collections::HashMap::with_capacity(persisted.channel_keys.len());
        for (k, v) in &persisted.channel_keys {
            let on_disk = existing.as_ref().and_then(|e| e.channel_keys.get(k)).map(|s| s.as_str());
            let at_rest = if v.is_empty() { String::new() } else { self.encrypt_cred_field(username, unlocked, v, on_disk).await? };
            keys_at_rest.insert(k.clone(), at_rest);
        }
        persisted.channel_keys = keys_at_rest;
        // r3 C1-7: the perform list is ONE credential field for the locked-vault rule
        // encrypt_cred_field applies to the scalar fields (never overwrite an on-disk
        // "enc:" value with plaintext). Entries have no stable key to pair an incoming
        // command with its on-disk blob, so: if the vault is locked, the stored list holds
        // encrypted commands, and the incoming list holds plaintext but no "enc:" blob at
        // all, the incoming list came from a read made while the vault was still unlocked
        // (a Lock raced this read-modify-write) — keep the stored list verbatim instead of
        // writing the decrypted commands in plaintext. A list read while locked carries the
        // blobs themselves; its blobs stay verbatim and any NEW plaintext entry is saved
        // as before (plaintext until the next unlock re-encrypts it, F7).
        let disk_perform_enc = existing.as_ref()
            .map_or(false, |e| e.perform_commands.iter().any(|c| Self::is_enc_blob(c)));
        let incoming_has_blob = persisted.perform_commands.iter().any(|c| Self::is_enc_blob(c));
        let incoming_has_plain = persisted.perform_commands.iter().any(|c| !c.is_empty() && !Self::is_enc_blob(c));
        if !unlocked && disk_perform_enc && incoming_has_plain && !incoming_has_blob {
            if let Some(e) = existing.as_ref() {
                warn!("[{}] vault locked during a config save: keeping the stored (encrypted) perform commands", safe_id);
                persisted.perform_commands = e.perform_commands.clone();
                // r4 (w3-srv INFO 9): don't leave it silent — the edit to the perform list
                // was not applied.
                self.send_to_user(username, ServerEvent::Error { message: PERFORM_KEPT_WHILE_LOCKED_MSG.into() });
            }
        } else {
            let mut perform_at_rest = Vec::with_capacity(persisted.perform_commands.len());
            for c in &persisted.perform_commands {
                perform_at_rest.push(if c.is_empty() { String::new() } else { self.encrypt_cred_field(username, unlocked, c, None).await? });
            }
            persisted.perform_commands = perform_at_rest;
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
        // F2: a re-cased id saved before canonicalisation (cfg.id "13DAc991-…" in
        // 13dac991-….json) is reported, dialled and logged under the canonical id.
        cfg.id = safe_id.clone();

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
            // Channel keys / perform commands (see save_network). A plaintext value from
            // an older file simply has no "enc:" prefix and is returned as-is.
            for v in cfg.channel_keys.values_mut() {
                if let Some(enc) = v.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        *v = String::from_utf8_lossy(&plain).into_owned();
                    }
                }
            }
            for c in cfg.perform_commands.iter_mut() {
                if let Some(enc) = c.strip_prefix("enc:") {
                    if let Ok(plain) = self.crypto.decrypt(username, enc).await {
                        *c = String::from_utf8_lossy(&plain).into_owned();
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

    /// F7: re-save (encrypting) every network config of `username` that still holds a
    /// credential in plaintext — written while the vault was locked (AddNetwork/
    /// UpdateNetwork had nothing to encrypt with) or by a pre-S2 version. Runs right
    /// after an unlock. Idempotent (an all-`enc:` config is skipped untouched) and
    /// crash-safe (save_network is tmp+rename; a lock racing in makes save_network keep
    /// the on-disk value). Serialised with every other config writer by the per-config
    /// lock, and re-reads the config inside it so a concurrent RemoveNetwork wins.
    pub async fn encrypt_plaintext_network_creds(&self, username: &str) {
        let has_plain = |v: Option<&str>| v.map_or(false, |p| !p.is_empty() && !Self::is_enc_blob(p));
        for id in self.user_network_ids(username).await {
            let path = format!("{}/networks/{}/{}.json", self.data_dir, username, id);
            let Ok(raw) = tokio::fs::read_to_string(&path).await else { continue };
            let Ok(cfg) = serde_json::from_str::<NetworkConfig>(&raw) else { continue };
            let needs = has_plain(cfg.password.as_deref())
                || has_plain(cfg.sasl_plain.as_ref().map(|s| s.password.as_str()))
                || has_plain(cfg.oper_pass.as_deref())
                || has_plain(cfg.nickserv_pass.as_deref())
                // codex P1: channel keys and perform commands are encrypted too now;
                // this is also the migration for every pre-existing plaintext file.
                || cfg.channel_keys.values().any(|v| has_plain(Some(v.as_str())))
                || cfg.perform_commands.iter().any(|c| has_plain(Some(c.as_str())));
            if !needs { continue; }
            let cfg_lock = network_config_lock(username, &id);
            let _cfg_guard = cfg_lock.lock().await;
            if !self.crypto.is_unlocked(username).await { return; }
            let Some(fresh) = self.get_network_config(&id, username).await else { continue };
            match self.save_network(&fresh, username).await {
                Ok(()) => info!("Encrypted plaintext credentials of network {} for {}", id, username),
                Err(e) => warn!("Could not encrypt plaintext credentials of network {} for {}: {}", id, username, e),
            }
        }
    }

    /// F16/F7: canonical ids of every network config file `username` has on disk
    /// (from the file names alone — no parse, no decrypt).
    pub async fn user_network_ids(&self, username: &str) -> Vec<String> {
        let dir = format!("{}/networks/{}", self.data_dir, username);
        let mut out = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let p = e.path();
                if !p.extension().map(|x| x == "json").unwrap_or(false) { continue; }
                if let Some(id) = p.file_stem().and_then(|s| s.to_str()).and_then(validate_uuid) {
                    if !out.contains(&id) { out.push(id); }
                }
            }
        }
        out
    }

    /// F16: lower-cased ids of every network that still has a config, for ANY user,
    /// plus every live conn_id — log dirs named by these are never treated as orphans.
    pub async fn all_configured_network_ids(&self) -> std::collections::HashSet<String> {
        let mut keep: std::collections::HashSet<String> = self.conn_owners.iter()
            .map(|e| e.key().to_ascii_lowercase()).collect();
        keep.extend(self.connections.iter().map(|e| e.key().to_ascii_lowercase()));
        let root = format!("{}/networks", self.data_dir);
        if let Ok(mut users) = tokio::fs::read_dir(&root).await {
            while let Ok(Some(u)) = users.next_entry().await {
                let Ok(mut confs) = tokio::fs::read_dir(u.path()).await else { continue };
                while let Ok(Some(c)) = confs.next_entry().await {
                    let p = c.path();
                    // Any stem counts (incl. `.json.tmp` leftovers) — over-keeping is safe.
                    if let Some(stem) = p.file_name().and_then(|s| s.to_str()) {
                        let id = stem.split('.').next().unwrap_or("");
                        if !id.is_empty() { keep.insert(id.to_ascii_lowercase()); }
                    }
                }
            }
        }
        keep
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

/// Structural safety gate for the synced appearance blob (#51). This blob is persisted
/// and broadcast to every one of a user's sessions and is consumed by the client theme
/// sink, so a hijacked session must not be able to push markup / CSS-injection
/// metacharacters or pathological structure through it. We validate STRUCTURE (bounded
/// nesting, bounded member counts, no '<' / '>' / control chars in any string or key)
/// rather than enumerating individual keys, so custom themes and future appearance
/// settings keep syncing unchanged. Numeric ranges are clamped by the client at apply time.
fn appearance_json_is_safe(v: &serde_json::Value, depth: u32) -> bool {
    if depth > 12 {
        return false;
    }
    fn str_ok(s: &str) -> bool {
        !s.chars().any(|c| c == '<' || c == '>' || c.is_control())
    }
    match v {
        serde_json::Value::String(s) => str_ok(s),
        serde_json::Value::Array(a) => {
            a.len() <= 1024 && a.iter().all(|e| appearance_json_is_safe(e, depth + 1))
        }
        serde_json::Value::Object(m) => {
            m.len() <= 1024
                && m.iter().all(|(k, val)| str_ok(k) && appearance_json_is_safe(val, depth + 1))
        }
        // Numbers / bools / null are inert once JSON-parsed.
        _ => true,
    }
}

/// Sanitize a username for safe filesystem path usage (defense-in-depth)
pub fn safe_username(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').take(64).collect()
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

/// #45: re-harden an existing secret directory TREE at startup so per-user vault/e2e
/// subdirs (and their secret files) created before the 0700/0600 hardening — or on an
/// upgraded install where `unlock()`/`create_dir_secure` returns early before re-chmod —
/// are brought to 0700 dirs / 0600 files. Best-effort, bounded to startup, skips symlinks
/// (a swapped symlink must not redirect the chmod). Depth-capped as a runaway guard.
fn harden_secret_tree(path: &std::path::Path, depth: u32) {
    use std::os::unix::fs::PermissionsExt;
    if depth > 6 { return; }
    let meta = match std::fs::symlink_metadata(path) { Ok(m) => m, Err(_) => return };
    if meta.file_type().is_symlink() { return; }
    if meta.is_dir() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
        if let Ok(rd) = std::fs::read_dir(path) {
            for ent in rd.flatten() { harden_secret_tree(&ent.path(), depth + 1); }
        }
    } else if meta.is_file() {
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
}

/// #58: debounce unsolicited `E2EOTPKLow` pushes to a target. A third party fetching a
/// victim's bundle drains an OTPK and would otherwise fire one E2EOTPKLow per fetch into
/// the victim's broadcast channel; rate-limit those to at most one per minute per target.
/// Returns true if the caller should send the event now.
fn otpk_low_should_notify(target: &str) -> bool {
    use std::time::Instant;
    static LAST: std::sync::OnceLock<dashmap::DashMap<String, Instant>> = std::sync::OnceLock::new();
    let map = LAST.get_or_init(dashmap::DashMap::new);
    if map.len() > 8192 { map.retain(|_, t: &mut Instant| t.elapsed() < std::time::Duration::from_secs(120)); }
    let now = Instant::now();
    match map.get(target).map(|t| t.elapsed()) {
        Some(elapsed) if elapsed < std::time::Duration::from_secs(60) => false,
        _ => { map.insert(target.to_string(), now); true }
    }
}

/// #30/#112: atomically persist a secret JSON file (admin_settings.json holds plaintext
/// API keys + the registration_code) via tmp+rename, chmod 0600 so the data dir being
/// world-readable can't leak the secrets. Returns Err on serialize/write/rename failure
/// so callers can surface a real error instead of silently writing an empty/partial file.
async fn write_secret_json_atomic(path: &std::path::Path, value: &serde_json::Value) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    let result = async {
        let mut file = tokio::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).await?;
        file.write_all(body.as_bytes()).await?;
        file.flush().await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&tmp, path).await?;
        if let Some(dir) = path.parent() {
            if let Ok(file) = tokio::fs::File::open(dir).await { let _ = file.sync_all().await; }
        }
        Ok(())
    }.await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    Ok(())
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
/// Every `networks/<user>/<stem>.json` on disk as (user, stem), and whether the scan
/// read every directory without error. Used by the startup conn_owners seeding and the
/// account-purge ownership guard (v-srv-a NEW-1).
async fn scan_network_configs(data_dir: &str) -> (Vec<(String, String)>, bool) {
    let root = std::path::PathBuf::from(data_dir).join("networks");
    let mut out = Vec::new();
    let mut users = match tokio::fs::read_dir(&root).await {
        Ok(rd) => rd,
        Err(e) => return (out, e.kind() == std::io::ErrorKind::NotFound),
    };
    let mut complete = true;
    loop {
        let entry = match users.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(_) => { complete = false; break; }
        };
        let Some(user) = entry.file_name().to_str().map(str::to_string) else { complete = false; continue };
        match entry.file_type().await {
            Ok(t) if t.is_dir() => {}
            Ok(_) => continue,
            Err(_) => { complete = false; continue; }
        }
        let mut confs = match tokio::fs::read_dir(entry.path()).await {
            Ok(rd) => rd,
            Err(_) => { complete = false; continue; }
        };
        loop {
            match confs.next_entry().await {
                Ok(Some(c)) => {
                    let p = c.path();
                    if p.extension().map_or(false, |x| x == "json") {
                        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
                            out.push((user.clone(), stem.to_string()));
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => { complete = false; break; }
            }
        }
    }
    (out, complete)
}

/// The optional `status_view` of GetLogs / Sync applies to the shared "status" log only.
fn status_view_for(target: &str, v: Option<&str>) -> Option<logs::StatusView> {
    if !target.eq_ignore_ascii_case("status") { return None; }
    v.and_then(logs::StatusView::parse)
}

/// agy P2 main.rs:5264: drop a parted channel's auto-join entry and saved key under the
/// spelling they were STORED with. Keys are stored by to_lowercase() of whatever
/// spelling the user or the server used (persist_channel_key may reuse an RFC1459-fold
/// slot such as `#chan{x}` for `#chan[x]`), so a plain to_lowercase() remove left that
/// key on disk forever. Exact spelling first; then the same channel under the server's
/// CASEMAPPING `cm` — codex P2 irc.rs:206 / w-srv #14: this folded rfc1459 regardless,
/// so on an ascii server (ergo, UnrealIRCd 6, InspIRCd 4) parting keyless `#x{y}` deleted
/// the key (and auto-join entry) of the different channel `#x[y]`. With the mapping
/// unknown (`None`), only the exact spelling.
fn forget_parted_channel(cfg: &mut NetworkConfig, channel: &str, cm: Option<cryptirc::ircproto::CaseMapping>) {
    let slot = crate::irc::existing_key_slot(&cfg.channel_keys, channel, cm);
    cfg.channel_keys.remove(&slot);
    let lc = channel.to_lowercase();
    if cfg.auto_join.iter().any(|c| c.to_lowercase() == lc) {
        cfg.auto_join.retain(|c| c.to_lowercase() != lc);
    } else if let Some(cm) = cm {
        let folded = cm.fold(channel);
        cfg.auto_join.retain(|c| cm.fold(c) != folded);
    }
}

#[cfg(test)]
mod part_slot_tests {
    use super::*;
    use cryptirc::ircproto::CaseMapping;

    fn cfg_with(keys: &[(&str, &str)], auto: &[&str]) -> NetworkConfig {
        NetworkConfig {
            channel_keys: keys.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            auto_join: auto.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    /// w-srv #14 FIX-INTRODUCES-BUG / codex P2 irc.rs:206: parting keyless `#x{y}` on an
    /// ascii-casemapping server must not delete the key (or auto-join) of `#x[y]`.
    #[test]
    fn part_on_ascii_server_keeps_the_other_channels_key() {
        let mut c = cfg_with(&[("#x[y]", "sekrit1")], &["#x[y]"]);
        forget_parted_channel(&mut c, "#x{y}", Some(CaseMapping::Ascii));
        assert_eq!(c.channel_keys.get("#x[y]").map(String::as_str), Some("sekrit1"));
        assert_eq!(c.auto_join, vec!["#x[y]".to_string()]);
        // Unknown mapping: exact only, same result.
        forget_parted_channel(&mut c, "#x{y}", None);
        assert_eq!(c.channel_keys.len(), 1);
        assert_eq!(c.auto_join.len(), 1);
        // Its own exact spelling is removed.
        forget_parted_channel(&mut c, "#X[Y]", Some(CaseMapping::Ascii));
        assert!(c.channel_keys.is_empty() && c.auto_join.is_empty());
    }

    /// The round-2 case it fixed still works where the server folds: on rfc1459 the
    /// server-spelled `#Chan[X]` finds the key stored as `#chan{x}`.
    #[test]
    fn part_on_rfc1459_server_finds_the_folded_slot() {
        let mut c = cfg_with(&[("#chan{x}", "k")], &["#chan{x}"]);
        forget_parted_channel(&mut c, "#Chan[X]", Some(CaseMapping::Rfc1459));
        assert!(c.channel_keys.is_empty() && c.auto_join.is_empty());
    }
}

/// agy P2 (reconnect_for_user): networks the user explicitly disconnected in this web
/// process (Disconnect / `/quit`), until they Connect it again or remove it.
fn user_disconnected_set() -> &'static DashMap<String, ()> {
    static S: std::sync::OnceLock<DashMap<String, ()>> = std::sync::OnceLock::new();
    S.get_or_init(DashMap::new)
}
pub(crate) fn user_disconnected(conn_id: &str) -> bool { user_disconnected_set().contains_key(conn_id) }
fn set_user_disconnected(conn_id: &str, on: bool) {
    if on { user_disconnected_set().insert(conn_id.to_string(), ()); }
    else { user_disconnected_set().remove(conn_id); }
}

/// r3 WW-2: a manual "Lock vault" is sent by every app.js version as `lock_vault`
/// immediately followed by one `disconnect` per network, from the same socket, in one
/// synchronous burst (_lockVaultNow). Those disconnects are part of the lock, not the
/// user's explicit Disconnect, so they are tagged `from_lock` and the Disconnect handler
/// does not record them (unlock then reconnects the networks, like 7ee4ccb). The burst
/// starts at `lock_vault` and ends at the first other command dispatched on the socket,
/// so a later Disconnect click / `/quit` / TUI `/disconnect` is explicit as before.
/// (Idle/Active presence frames never reach this point.)
/// r4 (w3-srv INFO 5): the burst also ends LOCK_BURST_WINDOW after the `lock_vault` was
/// dispatched, so a Disconnect sent later from the same socket with no other command in
/// between is explicit too, whatever the UI does. The burst's frames are queued back to
/// back; the window only has to cover the handling of up to 20 disconnects.
const LOCK_BURST_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
fn mark_lock_burst(cmd: ClientMessage, lock_burst: &mut Option<tokio::time::Instant>, now: tokio::time::Instant) -> ClientMessage {
    match cmd {
        ClientMessage::LockVault {} => { *lock_burst = Some(now); ClientMessage::LockVault {} }
        ClientMessage::Disconnect { id, reason, .. }
            if lock_burst.map_or(false, |t| now.saturating_duration_since(t) <= LOCK_BURST_WINDOW) =>
        {
            ClientMessage::Disconnect { id, reason, from_lock: true }
        }
        other => { *lock_burst = None; other }
    }
}

/// r4 (w3-srv INFO 9): save_network kept the stored (encrypted) perform commands because
/// the vault was locked while an edit that would have written them in plaintext was saved.
const PERFORM_KEPT_WHILE_LOCKED_MSG: &str = "The vault was locked while this network's settings were being saved, \
so its perform commands were left as they were (they are stored encrypted). The other settings were saved. Unlock \
the vault and edit the perform commands again.";

/// r3 C2-1: shown when a cert / history operation is refused for a network id that
/// several accounts' configs name (only possible for legacy, pre-#23 configs).
const CONTESTED_NETWORK_MSG: &str = "This network's id is also used by another account's saved network \
(left over from an older CryptIRC version), so its client certificate and server-side history are shared \
and can't be changed from here. Remove the network and add it again to give it its own id.";

/// r3 C2-1: the accounts whose `networks/<user>/` holds `<id>.json` RIGHT NOW (by file
/// name, ASCII-case-insensitively like purge_account's guard, so a legacy re-cased file
/// name counts too; a config that fails to parse still counts). None = this id's owners
/// could not be verified (callers then fail closed, with ID_OWNERS_UNVERIFIED_MSG).
/// r4 (w3-srv INFO 4): narrowed. It used to return None for ANY unreadable entry under
/// networks/, so one bad entry made every account's cert / history actions fail with the
/// misleading "shared with another account" text. Now:
///  - an entry whose name is not UTF-8 is skipped (never an account: usernames are
///    validated ASCII, and only an account can act on an id);
///  - each account dir is first checked for the exact `<id>.json` (a stat, which works
///    even when the dir can't be listed); only when that is absent is the dir listed for a
///    legacy re-cased spelling — a dir that can't be listed then counts as not naming the
///    id (re-cased spellings predate F2 and need a pre-#23 collision as well), and only an
///    error on the stat itself (or on listing networks/) leaves this id unverified.
async fn network_id_owners(data_dir: &str, id: &str) -> Option<Vec<String>> {
    let root = std::path::PathBuf::from(data_dir).join("networks");
    let mut users = match tokio::fs::read_dir(&root).await {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(Vec::new()),
        Err(e) => { warn!("network id owners: cannot list {}: {}", root.display(), e); return None; }
    };
    let file = format!("{}.json", id);
    let mut out = Vec::new();
    loop {
        let entry = match users.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => { warn!("network id owners: listing {} failed: {}", root.display(), e); return None; }
        };
        let Some(user) = entry.file_name().to_str().map(str::to_string) else {
            warn!("network id owners: skipping a non-UTF-8 entry under {}", root.display());
            continue;
        };
        match entry.file_type().await {
            Ok(t) if t.is_dir() => {}
            Ok(_) => continue,
            Err(e) => { warn!("[{}] network id owners: cannot stat networks/{}: {}", id, user, e); return None; }
        }
        match tokio::fs::symlink_metadata(entry.path().join(&file)).await {
            Ok(_) => { out.push(user); continue; }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => { warn!("[{}] network id owners: cannot check networks/{}: {}", id, user, e); return None; }
        }
        // Not under its canonical name: look for a legacy re-cased spelling.
        let Ok(mut confs) = tokio::fs::read_dir(entry.path()).await else { continue };
        loop {
            match confs.next_entry().await {
                Ok(Some(c)) => {
                    if c.file_name().to_str().map_or(false, |n| n.eq_ignore_ascii_case(&file)) {
                        out.push(user.clone());
                        break;
                    }
                }
                Ok(None) | Err(_) => break,
            }
        }
    }
    out.sort();
    out.dedup();
    Some(out)
}

/// r3 C2-1: one account's standing on a network id, decided from a FRESH owner list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdOwnership {
    /// Exactly this account names the id: it may act on the id-keyed shared state.
    Sole,
    /// This account and at least one other (a legacy collision): only this account's own
    /// config may be touched.
    Shared,
    /// r4 (w3-srv INFO 4): the owners could not be verified (a storage error): treated
    /// like Shared (fail closed), but reported as what it is (ID_OWNERS_UNVERIFIED_MSG).
    Unverified,
    /// This account's config does not name the id (any more).
    NotListed,
}

impl IdOwnership {
    /// Shared or Unverified: someone else may hold a stake — never act on the shared state.
    fn maybe_shared(self) -> bool { matches!(self, IdOwnership::Shared | IdOwnership::Unverified) }
    /// The refusal text for a cert / history operation (None for Sole / NotListed).
    fn refusal(self) -> Option<&'static str> {
        match self {
            IdOwnership::Shared => Some(CONTESTED_NETWORK_MSG),
            IdOwnership::Unverified => Some(ID_OWNERS_UNVERIFIED_MSG),
            IdOwnership::Sole | IdOwnership::NotListed => None,
        }
    }
}

/// r4 (w3-srv INFO 4): shown instead of CONTESTED_NETWORK_MSG when the owners of an id
/// could not be read.
const ID_OWNERS_UNVERIFIED_MSG: &str = "The server could not verify which account this network belongs to \
(a storage error while reading the saved networks), so nothing was changed. Try again in a moment; if it keeps \
happening, the server operator should check the data directory.";

/// `owners` = network_id_owners' list (None = unverified).
fn classify_id_owners(owners: Option<&[String]>, username: &str) -> IdOwnership {
    match owners {
        None => IdOwnership::Unverified,
        Some(o) if o.len() == 1 && o[0] == username => IdOwnership::Sole,
        Some(o) if o.iter().any(|u| u == username) => IdOwnership::Shared,
        Some(_) => IdOwnership::NotListed,
    }
}

/// r3 C2-1 (security-review follow-up to 153eddc): `username`'s standing on `id` from a
/// fresh read of the disk — Sole ONLY when the owner list is exactly [username]; the old
/// "is it still shared?" re-check also said "no" when the one remaining owner was the
/// OTHER account. Every caller holds network_config_lock(username, id) across this check
/// AND the operation it gates: this account's own config can't change meanwhile (each
/// writer/remover of it takes that lock), and another account's copy of an id can only
/// disappear (ids are server-minted; nothing creates a copy under another account), which
/// can turn Shared into Sole for the account that still has its copy, never the reverse.
async fn network_id_ownership(state: &AppState, username: &str, id: &str) -> IdOwnership {
    let owners = network_id_owners(&state.data_dir, id).await;
    classify_id_owners(owners.as_deref(), username)
}

/// r4 C1-2 / C2-1 / F2-5: one async mutex per network id, NOT per account, taken by every
/// claim of that id (claim_and_dial). network_config_lock is keyed user+id, so two accounts
/// whose legacy configs name the same id never contended: both passed the "unowned" check,
/// both overwrote conn_owners and both sent a Dial, and the account conn_owners routed the
/// session's events to could differ from the account whose credentials the daemon dialed.
/// Lock order: network_config_lock(user, id) → network_claim_lock(id), never the reverse
/// (nothing that holds a claim lock waits for a config lock).
fn network_claim_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static LOCKS: std::sync::OnceLock<DashMap<String, Arc<Mutex<()>>>> = std::sync::OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}
fn network_claim_lock(id: &str) -> Arc<Mutex<()>> {
    network_claim_locks()
        .entry(id.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// r4: shown when a Connect is refused because another account's session holds the id.
const NETWORK_ID_HELD_MSG: &str = "Not connected: this network's id is also used by another account's saved \
network (left over from an older CryptIRC version), and that account's connection is using it. Remove the \
network and add it again to give it its own id.";

/// What claim_and_dial did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimOutcome {
    /// The id is this account's; a Dial was sent (or queued while the daemon link is down).
    Dialed,
    /// The id is this account's and its session is already live: nothing was sent.
    AlreadyLive,
    /// Another account's session holds the id: nothing was changed.
    HeldByOther,
}

/// r3 C2-1 (security-review follow-up 2 / integrator decision) + r4 C1-2 / C2-1: take
/// ownership of a network id and dial it — used by Connect (`user_connect`: also clears
/// the per-id disconnect flags, once the claim is ours) and reconnect_for_user, with the
/// caller's per-config lock held.
///
/// Concurrency (r4): the whole claim runs under network_claim_lock(id), so claims of one id
/// are serialized ACROSS accounts, and every decision is re-checked after each await:
///  - an id whose conn_owners entry is another account's is never taken over
///    (HeldByOther); the owner is inserted with an atomic check-and-insert, so even a path
///    that bypassed the lock could not overwrite another account's entry;
///  - the conn_owners insert and the Dial happen inside the same critical section, so the
///    account events are routed to is always the account whose config was dialed last.
///
/// A live daemon session of a legacy id that SEVERAL accounts' configs name is NEVER
/// adopted: such an ownerless session survives a web restart (v-srv-a NEW-1) and nobody can
/// tell whose it is. For a shared unowned id the claim (1) quarantines the id, (2) Drops
/// whatever session the daemon holds, (3) sets the owner and dials fresh. r4: EVERY claim
/// of an unowned id quarantines it, bound to the claiming account — ipc_client drops all
/// events for the id until a ConnStatus::Connecting arrives while conn_owners names that
/// account (the fresh session's first event). An id becomes unowned only when its session
/// ends or is dropped (Disconnect/RemoveNetwork/purge/terminal Disconnected), so a sole
/// owner claiming it right after another account released it (a formerly shared id) can't
/// receive the released session's in-flight lines either; no Drop is sent in the sole case
/// (there is normally no session, and a Dial replaces one daemon-side anyway). The daemon
/// forwards nothing from a dropped/replaced session once the new one exists (generation
/// token, also in the prod b8e1ede daemon). An id this account already owns is claimed
/// exactly as before (no quarantine).
async fn claim_and_dial(state: &AppState, username: &str, cfg: NetworkConfig, user_connect: bool) -> ClaimOutcome {
    let id = cfg.id.clone();
    let claim_lock = network_claim_lock(&id);
    let _claim_guard = claim_lock.lock().await;
    // Re-checked under the id lock (the caller's checks ran before it).
    match state.conn_owners.get(&id).map(|o| o.clone()) {
        Some(o) if o != username => return ClaimOutcome::HeldByOther,
        Some(_) if state.connections.contains_key(&id) => return ClaimOutcome::AlreadyLive,
        _ => {}
    }
    let unowned = !state.conn_owners.contains_key(&id);
    if unowned {
        // (Unverified owners fail closed: treated like a shared id — never adopted.)
        let shared = network_id_ownership(state, username, &id).await.maybe_shared();
        // Re-check after the await: every claim of this id holds the lock we hold, so the
        // id can at most have been released meanwhile — but never take it over.
        if state.conn_owners.get(&id).map_or(false, |o| o.as_str() != username) {
            return ClaimOutcome::HeldByOther;
        }
        fresh_claim_quarantine().insert(id.clone(), username.to_string());
        if shared {
            info!("[{}] {} claims a network id shared with another account: dropping any live session and dialing fresh", id, username);
            ipc_client::send_drop(state, &id, DEFAULT_QUIT_MESSAGE.to_string()).await;
            state.connections.remove(&id);
        }
    }
    // Atomic check-and-insert: never overwrite another account's entry.
    let ours = {
        let entry = state.conn_owners.entry(id.clone()).or_insert_with(|| username.to_string());
        entry.value() == username
    };
    if !ours {
        fresh_claim_quarantine().remove_if(&id, |_, c| c == username);
        return ClaimOutcome::HeldByOther;
    }
    if user_connect {
        state.clear_disconnect_request(&id);
        state.clear_pending_dial(&id);
        set_user_disconnected(&id, false);
    }
    ipc_client::dial_current(state, username, cfg).await;
    // Re-check after the dial's awaits. Nothing should have released the id (our own
    // release paths wait for the config lock our caller holds), but if the entry is gone
    // or not ours, the session we just dialed must not run on with nobody routing it.
    if state.conn_owners.get(&id).map_or(true, |o| o.as_str() != username) {
        warn!("[{}] ownership changed while {} was dialing it — dropping that dial", id, username);
        state.clear_pending_dial(&id);
        ipc_client::send_drop(state, &id, DEFAULT_QUIT_MESSAGE.to_string()).await;
    }
    ClaimOutcome::Dialed
}

/// r5 (codex P2 main.rs:8428): called by ipc_client at AttachComplete, before the
/// pending-dial drain. A fresh-claim quarantine lifts only on the claimed session's first
/// ConnStatus::Connecting, which an Attach replay never contains. If the daemon link
/// dropped after the claim's Dial left this process but before the web handled that
/// Connecting, the id stayed quarantined — its SessionSync and lines dropped (and acked)
/// — until some later Dial. The replay can't tell whether the daemon's current session for
/// the id is the claim's own (its Dial was processed) or the one it replaced (the Dial was
/// lost with the link): adopting the latter is exactly what the quarantine exists to
/// prevent. So every id still quarantined here is dialed AGAIN for its claimant, with the
/// claim's locks taken and everything re-checked: a Dial replaces whatever session the
/// daemon holds for the id, and the fresh session's Connecting lifts the quarantine. Ids
/// with a queued dial are left to the pending-dial drain; a stale entry (the claimant no
/// longer owns the id) is left alone (events of an ownerless id are dropped anyway, and the
/// next claim re-binds it).
pub(crate) async fn redial_quarantined_claims(
    state: &AppState,
    out_tx: &tokio::sync::mpsc::UnboundedSender<cryptirc::ipc::IpcMessage>,
) {
    let ids: Vec<(String, String)> = fresh_claim_quarantine().iter()
        .map(|e| (e.key().clone(), e.value().clone())).collect();
    for (id, claimant) in ids {
        if state.pending_dials.contains(&id) || state.disconnect_requested(&id) { continue; }
        // Same locks, same order, as a claim (config lock → claim lock).
        let cfg_lock = network_config_lock(&claimant, &id);
        let _cfg_guard = cfg_lock.lock().await;
        let claim_lock = network_claim_lock(&id);
        let _claim_guard = claim_lock.lock().await;
        if fresh_claim_quarantine().get(&id).map_or(true, |c| *c != claimant) { continue; }
        if state.conn_owners.get(&id).map_or(true, |o| o.as_str() != claimant) { continue; }
        if state.pending_dials.contains(&id) || state.disconnect_requested(&id)
            || user_disconnected(&id) || state.connections.contains_key(&id) { continue; }
        let Some(cfg) = state.get_network_config(&id, &claimant).await else { continue };
        // Without its encrypted credentials it would dial unauthenticated: leave it to the
        // next unlock (reconnect_for_user claims it again, which dials it).
        if state.dial_deferred_for_locked_vault(&claimant, &cfg).await { continue; }
        info!("[{}] fresh claim by {} was not confirmed before the daemon link dropped — dialing it again", id, claimant);
        ipc_client::dial(state, &claimant, cfg, out_tx).await;
    }
}

/// r3 C2-1 / r4: ids under a fresh-claim quarantine → the claiming account (see
/// claim_and_dial).
fn fresh_claim_quarantine() -> &'static DashMap<String, String> {
    static Q: std::sync::OnceLock<DashMap<String, String>> = std::sync::OnceLock::new();
    Q.get_or_init(DashMap::new)
}

/// r3 C2-1: ipc_client's gate for daemon events. False = drop this event: its conn_id is
/// under a fresh-claim quarantine and it is not the fresh session's first
/// ConnStatus::Connecting (which lifts the quarantine and is processed normally).
/// r4 C1-2 / C2-1: bound to the claiming account — a Connecting lifts the quarantine only
/// while conn_owners names the account that claimed (before the claim's owner insert, or
/// after the id changed hands, it is dropped like every other event of the id).
pub(crate) fn fresh_claim_admits(state: &AppState, msg: &cryptirc::ipc::IpcMessage) -> bool {
    fresh_claim_admits_with(msg, |id| state.conn_owners.get(id).map(|o| o.clone()))
}

fn fresh_claim_admits_with(msg: &cryptirc::ipc::IpcMessage, owner_of: impl Fn(&str) -> Option<String>) -> bool {
    use cryptirc::ipc::{ConnLifecycle, IpcMessage};
    let q = fresh_claim_quarantine();
    if q.is_empty() { return true; }
    let conn_id = match msg {
        IpcMessage::RawLine { conn_id, .. } | IpcMessage::ConnStatus { conn_id, .. }
        | IpcMessage::SessionSync { conn_id, .. } => conn_id,
        _ => return true,
    };
    let Some(claimant) = q.get(conn_id).map(|c| c.value().clone()) else { return true };
    if matches!(msg, IpcMessage::ConnStatus { state: ConnLifecycle::Connecting, .. })
        && owner_of(conn_id.as_str()).as_deref() == Some(claimant.as_str())
    {
        q.remove_if(conn_id, |_, c| *c == claimant);
        return true;
    }
    false
}

/// r3 A1-4: an outgoing raw IRC line split the way IRC servers read it: an optional
/// IRCv3 `@tags` prefix and `:source` prefix are skipped, the verb is upper-cased, and
/// the params are separated by one OR MORE spaces, a param starting with `:` being the
/// trailing one (rest of the line). Missing verb = "".
struct OutgoingLine<'a> {
    verb: String,
    params: Vec<&'a str>,
}

impl<'a> OutgoingLine<'a> {
    fn parse(raw: &'a str) -> Self {
        let mut rest = raw.trim_start_matches(' ');
        if let Some(r) = rest.strip_prefix('@') { rest = r.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
        if let Some(r) = rest.strip_prefix(':') { rest = r.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
        let (verb, mut rest) = match rest.split_once(' ') {
            Some((v, t)) => (v, t),
            None => (rest, ""),
        };
        let mut params = Vec::new();
        loop {
            rest = rest.trim_start_matches(' ');
            if rest.is_empty() { break; }
            if let Some(trailing) = rest.strip_prefix(':') { params.push(trailing); break; }
            match rest.split_once(' ') {
                Some((p, t)) => { params.push(p); rest = t; }
                None => { params.push(rest); break; }
            }
        }
        OutgoingLine { verb: verb.to_ascii_uppercase(), params }
    }
}

/// r4 F1-2: the channels of an outgoing JOIN / PART (`params` = OutgoingLine params) to
/// persist, each JOIN channel paired with the key at the same position of the key list
/// (RFC 1459/2812: `JOIN #a,#b,#c ka,kb` = #a→ka, #b→kb, #c no key; "" = no key). PART
/// never pairs keys (its second param is the reason). Only syntactically valid channel
/// names, at most MAX_JOIN_PART_PERSIST of them (a server refuses longer lists anyway —
/// CHANLIMIT/TARGMAX — and the auto-join list holds 100), duplicates dropped.
const MAX_JOIN_PART_PERSIST: usize = 100;
fn join_part_channels<'a>(params: &[&'a str], is_join: bool) -> Vec<(&'a str, &'a str)> {
    let Some(chans) = params.first().copied() else { return Vec::new() };
    let keys: Vec<&'a str> = if is_join { params.get(1).copied().map_or(Vec::new(), |k| k.split(',').collect()) } else { Vec::new() };
    let mut out: Vec<(&'a str, &'a str)> = Vec::new();
    for (i, ch) in chans.split(',').enumerate() {
        if out.len() >= MAX_JOIN_PART_PERSIST { break; }
        if ch.is_empty() || !is_valid_channel(ch) { continue; }
        if out.iter().any(|(c, _)| c.eq_ignore_ascii_case(ch)) { continue; }
        out.push((ch, keys.get(i).copied().unwrap_or("")));
    }
    out
}

/// r3 A2-3: Disconnected reason when a Connect / queued dial is deferred until the vault
/// is unlocked (the network's saved credentials are encrypted).
pub(crate) const VAULT_LOCKED_CONNECT_REASON: &str =
    "Vault locked — this network's saved credentials are encrypted; it connects when you unlock the vault";

fn prune_network_config_locks() {
    network_config_locks().retain(|_, v| Arc::strong_count(v) > 1);
    network_claim_locks().retain(|_, v| Arc::strong_count(v) > 1);
}

pub fn redact_for_log(line: &str) -> String {
    // F6: match on the real command VERB. The old plain `starts_with` on the raw line
    // was defeated by an IRCv3 `@tags ` prefix, a `:source ` prefix or leading spaces
    // (all of which servers accept), and then the default branch logged 80 chars
    // verbatim — including the password of `OPER`/`REGISTER`/services lines and the
    // channel key the channel-modes dialog sends as `MODE #chan +k <key>`.
    let mut line = line.trim_start();
    if let Some(r) = line.strip_prefix('@') { line = r.splitn(2, ' ').nth(1).unwrap_or("").trim_start(); }
    if let Some(r) = line.strip_prefix(':') { line = r.splitn(2, ' ').nth(1).unwrap_or("").trim_start(); }
    let (verb_raw, params) = match line.split_once(' ') {
        Some((v, p)) => (v, p.trim_start()),
        None => (line, ""),
    };
    let verb = log_escape(verb_raw, 32);
    let upper = verb_raw.to_ascii_uppercase();
    let first = |p: &str| -> String { log_escape(p.split(' ').next().unwrap_or(""), 64) };
    // OPER <login> <pass> / PASS <pass> / AUTHENTICATE <b64 SASL> / WEBIRC <pass> ...
    if matches!(upper.as_str(), "OPER" | "PASS" | "AUTHENTICATE" | "WEBIRC") {
        return format!("{} <redacted>", upper);
    }
    // JOIN #chan <key> — the channel key is a shared secret; keep only the channels.
    if upper == "JOIN" {
        let mut it = params.splitn(2, ' ');
        let chans = log_escape(it.next().unwrap_or(""), 120);
        return if it.next().map_or(false, |k| !k.trim().is_empty()) {
            format!("{} {} <key redacted>", verb, chans)
        } else {
            format!("{} {}", verb, chans)
        };
    }
    // MODE <target> <modes> [params…] — params can be a +k channel key; never log them.
    if upper == "MODE" {
        let mut it = params.split(' ').filter(|x| !x.is_empty());
        let target = log_escape(it.next().unwrap_or(""), 64);
        let modes  = log_escape(it.next().unwrap_or(""), 32);
        let n = it.count();
        return if n > 0 {
            format!("{} {} {} <{} param(s) redacted>", verb, target, modes, n)
        } else {
            format!("{} {} {}", verb, target, modes).trim_end().to_string()
        };
    }
    // SQUERY <service> :<text> — RFC-2812 "server query"; only ever addressed to a
    // service (ratbox-services), so the tail may carry account credentials. Mirrors the
    // client-side redactSensitive rule (E). Keep verb + service token, drop the rest.
    if upper == "SQUERY" {
        return format!("{} {} <redacted>", verb, first(params));
    }
    const SERVICES: &[&str] = &["NICKSERV", "NS", "USERSERV", "US", "CHANSERV", "CS", "MEMOSERV", "MS",
        "OPERSERV", "OS", "HOSTSERV", "HS", "BOTSERV", "BS"];
    // PRIVMSG/NOTICE: never log a body (it may be non-E2E plaintext); a message to a
    // service may carry a credential in any subcommand, so mask everything after it.
    if upper == "PRIVMSG" || upper == "NOTICE" {
        let mut it = params.splitn(2, ' ');
        let target_raw = it.next().unwrap_or("");
        let body_len = it.next().map(|b| b.len()).unwrap_or(0);
        let target = log_escape(target_raw, 64);
        // Strip an optional @server suffix (NickServ@services.net) before matching.
        let tgt_base = target_raw.split('@').next().unwrap_or("").to_ascii_uppercase();
        if SERVICES.contains(&tgt_base.as_str()) {
            return format!("{} {} :<redacted>", verb, target);
        }
        return format!("{} {} :<{}B body redacted>", verb, target, body_len);
    }
    // Bare service pseudo-commands: `NICKSERV IDENTIFY <pw>`, `NS@services GHOST …`.
    let verb_base = upper.split('@').next().unwrap_or("");
    if SERVICES.contains(&verb_base) {
        return if params.trim().is_empty() { verb } else { format!("{} <redacted>", verb) };
    }
    // Commands whose FIRST parameter is a target/mask/subcommand, never a secret: keep
    // it for diagnostics. Anything else — including REGISTER/VERIFY/IDENTIFY/LOGIN and
    // every verb we don't know — logs only its verb and byte count (convergent: a new
    // credential-bearing command is redacted by default instead of leaked).
    const TARGET_FIRST: &[&str] = &["PART", "TOPIC", "KICK", "INVITE", "WHO", "WHOIS", "WHOWAS", "NAMES",
        "LIST", "NICK", "MONITOR", "CHATHISTORY", "TAGMSG", "KNOCK", "ISON", "USERHOST", "CAP", "PING",
        "PONG", "AWAY", "QUIT", "MOTD", "LUSERS", "VERSION", "TIME", "ADMIN", "INFO", "STATS", "LINKS"];
    if params.is_empty() {
        return verb;
    }
    if TARGET_FIRST.contains(&upper.as_str()) {
        let f = first(params);
        let rest = params.len().saturating_sub(params.split(' ').next().unwrap_or("").len());
        // AWAY/QUIT's first word is free text, not a target — size only.
        if matches!(upper.as_str(), "AWAY" | "QUIT") { return format!("{} <{}B>", verb, params.len()); }
        return if rest > 0 { format!("{} {} <+{}B>", verb, f, rest) } else { format!("{} {}", verb, f) };
    }
    format!("{} <{}B redacted>", verb, params.len())
}

/// F5/F6: char-safe truncation + control-character escaping for any client-supplied
/// text that reaches the log, so it can't forge extra log lines or terminal escapes.
fn log_escape(s: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i >= max_chars { out.push('…'); break; }
        if c.is_control() { out.push_str(&format!("\\x{:02x}", c as u32 & 0xff)); } else { out.push(c); }
    }
    out
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

/// Template the served `app.js`: rewrite the `/cryptirc` base path, and substitute the
/// r10: id of the frontend this binary serves: a hash of every embedded static file
/// (build.rs CRYPTIRC_STATIC_HASH: the include_str!/include_bytes! paths into static/ in
/// src/) plus the version, computed once. It is rendered into the served
/// app.js (`__CRYPTIRC_ASSETS__` → CRYPTIRC_ASSETS) and sent in every AuthOk, so a page
/// (tab, PWA, detached window) that stayed open across a redeploy — its WebSocket simply
/// reconnects and nothing reloads it — sees that the server now serves a different
/// frontend and offers a reload. Same-version redeploys with changed assets count too; a
/// rebuild that leaves the frontend byte-identical does not (nothing to reload).
static FRONTEND_ID: std::sync::OnceLock<String> = std::sync::OnceLock::new();
fn frontend_id() -> &'static str {
    FRONTEND_ID.get_or_init(|| frontend_asset_id(&[
        option_env!("CRYPTIRC_STATIC_HASH").unwrap_or("no-static-hash"), env!("CARGO_PKG_VERSION"),
    ]))
}
/// 12 hex chars of SHA-256 over the length-prefixed parts.
fn frontend_asset_id(parts: &[&str]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for p in parts { h.update((p.len() as u64).to_le_bytes()); h.update(p.as_bytes()); }
    h.finalize().iter().take(6).map(|b| format!("{:02x}", b)).collect()
}

/// `__CRYPTIRC_BUILD__` / `__CRYPTIRC_VERSION__` placeholders. `version` is always
/// `env!("CARGO_PKG_VERSION")` at the one real call site — Cargo.toml's `[package].version`
/// is the sole human-edited version number in the project; the served JS never hardcodes
/// its own copy. Pulled out of `main()` so this substitution logic is unit-testable.
fn render_app_js(raw: &str, base_path_trimmed: &str, build: &str, version: &str) -> String {
    rewrite_base_path(raw, base_path_trimmed)
        .replace("__CRYPTIRC_BUILD__", build)
        .replace("__CRYPTIRC_VERSION__", version)
}

/// Rewrite every `/cryptirc` PATH occurrence to the configured base path, leaving URL
/// authorities alone. F18: the old blanket `replace("/cryptirc", base)` also hit the
/// `//cryptirc` of `https://cryptirc.com/…` (app.js's built-in news links), turning it
/// into `https://chat.com/…` for base "/chat" or `https:/.com/…` for a root deploy.
/// A `/cryptirc` immediately preceded by another `/` is the start of a `//host`
/// authority, never a path literal (the frontend's paths are all `'/cryptirc/…'`,
/// `` `…/cryptirc/ws` ``, `path=/cryptirc;` …), so exactly those are skipped.
fn rewrite_base_path(raw: &str, base_path_trimmed: &str) -> String {
    const NEEDLE: &str = "/cryptirc";
    let mut out = String::with_capacity(raw.len());
    let mut last = 0;
    for (i, _) in raw.match_indices(NEEDLE) {
        out.push_str(&raw[last..i]);
        if i > 0 && raw.as_bytes()[i - 1] == b'/' {
            out.push_str(NEEDLE);
        } else {
            out.push_str(base_path_trimmed);
        }
        last = i + NEEDLE.len();
    }
    out.push_str(&raw[last..]);
    out
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

#[cfg(test)]
mod app_js_template_tests {
    use super::render_app_js;

    #[test]
    fn substitutes_build_and_version_placeholders() {
        let raw = "const CRYPTIRC_VERSION='__CRYPTIRC_VERSION__';const CRYPTIRC_BUILD='__CRYPTIRC_BUILD__';";
        let out = render_app_js(raw, "", "abc1234", "0.4.3");
        assert_eq!(out, "const CRYPTIRC_VERSION='0.4.3';const CRYPTIRC_BUILD='abc1234';");
    }

    #[test]
    fn served_app_js_version_matches_cargo_toml() {
        // The real embedded app.js source, templated exactly as `main()` does —
        // catches a future edit that reintroduces a hardcoded version literal
        // (the whole point of this fix: Cargo.toml is the ONLY place a human
        // edits the version).
        let out = render_app_js(include_str!("../static/app.js"), "/cryptirc", "dev", env!("CARGO_PKG_VERSION"));
        let needle = format!("const CRYPTIRC_VERSION='{}';", env!("CARGO_PKG_VERSION"));
        assert!(out.contains(&needle), "expected {:?} in rendered app.js", needle);
        assert!(!out.contains("__CRYPTIRC_VERSION__"), "version placeholder left un-substituted");
    }

    #[test]
    fn rewrites_base_path() {
        let out = render_app_js("fetch('/cryptirc/api')", "/custom", "dev", "0.4.3");
        assert_eq!(out, "fetch('/custom/api')");
    }

    /// F18: the hard-coded https://cryptirc.com links must survive every base path,
    /// while every `/cryptirc` PATH literal is still rewritten.
    #[test]
    fn cryptirc_com_links_survive_every_base_path() {
        let raw = r#"fetch('/cryptirc/auth/login');ws=`${p}://${h}/cryptirc/ws`;document.cookie='t=;path=/cryptirc';"link":"https://cryptirc.com/#security","l2":"https://cryptirc.com/#selfhost";if(u.pathname==='/cryptirc')x();"#;
        for (base, prefix) in [("", ""), ("/cryptirc", "/cryptirc"), ("/chat", "/chat")] {
            let out = render_app_js(raw, base, "dev", "0");
            assert!(out.contains("\"link\":\"https://cryptirc.com/#security\""), "base {:?}: {}", base, out);
            assert!(out.contains("https://cryptirc.com/#selfhost"), "base {:?}: {}", base, out);
            assert!(out.contains(&format!("fetch('{}/auth/login')", prefix)), "base {:?}: {}", base, out);
            assert!(out.contains(&format!("${{h}}{}/ws`", prefix)), "base {:?}: {}", base, out);
            assert!(out.contains(&format!("path={}'", prefix)), "base {:?}: {}", base, out);
            assert!(out.contains(&format!("pathname==='{}'", prefix)), "base {:?}: {}", base, out);
        }
    }

    /// F18 against the REAL embedded frontend: for base "/" (trimmed "") and "/chat"
    /// no path literal is left un-rewritten, and both cryptirc.com links are intact.
    #[test]
    fn real_app_js_rewrite_keeps_links_and_rewrites_all_paths() {
        let raw = include_str!("../static/app.js");
        let host_refs = raw.matches("//cryptirc").count();
        assert!(host_refs >= 2, "expected the cryptirc.com news links in app.js");
        for base in ["", "/chat"] {
            let out = render_app_js(raw, base, "dev", "0");
            assert_eq!(out.matches("/cryptirc").count(), host_refs,
                "base {:?}: only the //cryptirc.com authorities may keep /cryptirc", base);
            assert!(out.contains("\"link\":\"https://cryptirc.com/#security\""));
            assert!(out.contains("\"link\":\"https://cryptirc.com/#selfhost\""));
            assert!(!out.contains("https:/.com") && !out.contains("https://chat.com"));
            assert!(out.contains(&format!("{}/ws`", base)));
            assert!(out.matches(&format!("'{}/auth/", base)).count() >= raw.matches("'/cryptirc/auth/").count());
        }
        // The default deploy is byte-identical to the old blanket replace.
        assert_eq!(render_app_js(raw, "/cryptirc", "dev", "0"), raw.replace("__CRYPTIRC_BUILD__", "dev").replace("__CRYPTIRC_VERSION__", "0"));
    }

    // r10: the frontend id (stale-page reload banner).
    #[test]
    fn r10_frontend_id_tracks_the_served_assets() {
        use super::{frontend_asset_id, frontend_id, ServerEvent};
        let a = frontend_asset_id(&["app", "e2e"]);
        assert_eq!(a.len(), 12);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(a, frontend_asset_id(&["app", "e2e"]));
        assert_ne!(a, frontend_asset_id(&["app", "e2f"]));                      // one byte changed
        assert_ne!(frontend_asset_id(&["ab", "c"]), frontend_asset_id(&["a", "bc"]));  // parts are delimited
        // build.rs hashed the static/ tree (every embedded file)
        let sh = option_env!("CRYPTIRC_STATIC_HASH").expect("build.rs sets CRYPTIRC_STATIC_HASH");
        let (hex, n) = sh.split_once('-').expect("<hash>-<file count>");
        assert!(hex.len() == 16 && hex.chars().all(|c| c.is_ascii_hexdigit()), "{sh}");
        // exactly the files this crate embeds: count the distinct static/ include paths here
        let me = include_str!("main.rs");
        let mut embedded = std::collections::BTreeSet::new();
        for mac in ["include_str!(\"../static/", "include_bytes!(\"../static/"] {
            let mut rest = me;
            while let Some(i) = rest.find(mac) { rest = &rest[i + mac.len()..]; if let Some(e) = rest.find('"') { embedded.insert(&rest[..e]); } }
        }
        assert!(embedded.len() >= 30, "app/e2e/index/sw, Sortable, pets, icons, sounds, fonts: {embedded:?}");
        assert_eq!(n.parse::<usize>().unwrap(), embedded.len(), "build.rs hashed exactly the embedded static files: {sh} vs {embedded:?}");
        // the served app.js carries the same id the server sends in AuthOk
        let raw = include_str!("../static/app.js");
        assert_eq!(raw.matches("__CRYPTIRC_ASSETS__").count(), 1, "exactly one placeholder (the CRYPTIRC_ASSETS const)");
        let served = render_app_js(raw, "/cryptirc", "dev", env!("CARGO_PKG_VERSION")).replace("__CRYPTIRC_ASSETS__", frontend_id());
        assert!(served.contains(&format!("const CRYPTIRC_ASSETS='{}';", frontend_id())));
        let ev = serde_json::to_string(&ServerEvent::AuthOk { username: "u".into(), assets: frontend_id().into() }).unwrap();
        assert_eq!(ev, format!("{{\"type\":\"auth_ok\",\"username\":\"u\",\"assets\":\"{}\"}}", frontend_id()));
    }
}

#[cfg(test)]
mod ws_fix_tests {
    use super::*;

    #[test]
    fn redact_mode_key_and_register() {
        let r = redact_for_log("MODE #chan +k s3cretkey");
        assert!(!r.contains("s3cretkey"), "{r}");
        assert!(r.starts_with("MODE #chan +k"), "{r}");
        let r = redact_for_log("MODE #chan +ok bob s3cretkey");
        assert!(!r.contains("s3cretkey") && r.contains("2 param"), "{r}");
        assert_eq!(redact_for_log("MODE #chan"), "MODE #chan");
        let r = redact_for_log("REGISTER acct a@b.c hunter2pass");
        assert!(!r.contains("hunter2pass") && !r.contains("a@b.c"), "{r}");
        let r = redact_for_log("VERIFY acct 123456");
        assert!(!r.contains("123456"), "{r}");
        let r = redact_for_log("IDENTIFY hunter2pass");
        assert!(!r.contains("hunter2pass"), "{r}");
    }

    #[test]
    fn redact_handles_tag_source_and_leading_space_prefixes() {
        for line in [
            " OPER admin operpass99",
            "@label=1 OPER admin operpass99",
            ":me!u@h OPER admin operpass99",
            "@a=b :me OPER admin operpass99",
        ] {
            let r = redact_for_log(line);
            assert!(!r.contains("operpass99"), "{line:?} -> {r}");
        }
        for line in [
            " PRIVMSG NickServ :IDENTIFY nspass77",
            "@+draft/x=1 PRIVMSG NickServ :IDENTIFY nspass77",
            ":nick PRIVMSG NS :IDENTIFY nspass77",
            "  NS IDENTIFY nspass77",
            "@t=1 NICKSERV IDENTIFY nspass77",
        ] {
            let r = redact_for_log(line);
            assert!(!r.contains("nspass77"), "{line:?} -> {r}");
        }
        let r = redact_for_log("@label=1 PRIVMSG #chan :private words here");
        assert!(!r.contains("private"), "{r}");
        assert!(r.contains("#chan") && r.contains("body redacted"), "{r}");
    }

    #[test]
    fn redact_keeps_existing_rules() {
        assert_eq!(redact_for_log("PASS x"), "PASS <redacted>");
        assert_eq!(redact_for_log("OPER a b"), "OPER <redacted>");
        assert_eq!(redact_for_log("JOIN #a,#b k1,k2"), "JOIN #a,#b <key redacted>");
        assert_eq!(redact_for_log("JOIN #a"), "JOIN #a");
        assert_eq!(redact_for_log("AUTHENTICATE PLAIN"), "AUTHENTICATE <redacted>");
        assert_eq!(redact_for_log("SQUERY UserServ :LOGIN a b"), "SQUERY UserServ <redacted>");
        assert_eq!(redact_for_log("PRIVMSG NickServ@services.net :ID x"), "PRIVMSG NickServ@services.net :<redacted>");
        assert_eq!(redact_for_log("PRIVMSG #c :hello"), "PRIVMSG #c :<6B body redacted>");
        assert_eq!(redact_for_log("NS"), "NS");
        assert_eq!(redact_for_log("NICK newnick"), "NICK newnick");
        assert_eq!(redact_for_log("WHOIS bob"), "WHOIS bob");
        assert_eq!(redact_for_log("QUIT :bye all"), "QUIT <8B>");
        let r = redact_for_log("UNKNOWNVERB secret stuff");
        assert!(!r.contains("secret"), "{r}");
    }

    #[test]
    fn redact_escapes_control_chars_and_is_char_safe() {
        let r = redact_for_log("WHOIS bo\x1b[31mb");
        assert!(!r.contains('\x1b'), "{r:?}");
        let long: String = "ж".repeat(500);
        let _ = redact_for_log(&format!("WHOIS {long}"));
        let _ = redact_for_log(&format!("MODE {long} +k x"));
        let _ = redact_for_log(&long);
    }

    #[test]
    fn canonical_ids() {
        let id = "13dac991-6798-4923-9421-e6a174f9a8ef";
        let up = "13DAc991-6798-4923-9421-E6A174F9A8EF";
        assert_eq!(canonical_network_id(up), id);
        assert_eq!(canonical_network_id(id), id);
        assert_eq!(canonical_network_id("not-a-uuid"), "not-a-uuid");
        assert!(is_noncanonical_network_id(up));
        assert!(!is_noncanonical_network_id(id));
        assert!(!is_noncanonical_network_id("status"));
        let cmd = canonicalize_cmd_ids(ClientMessage::Connect { id: up.into() });
        assert!(matches!(cmd, ClientMessage::Connect { ref id } if id == "13dac991-6798-4923-9421-e6a174f9a8ef"));
        let cmd = canonicalize_cmd_ids(ClientMessage::Send { conn_id: up.into(), raw: "x".into() });
        assert!(matches!(cmd, ClientMessage::Send { ref conn_id, .. } if conn_id == "13dac991-6798-4923-9421-e6a174f9a8ef"));
    }

    #[test]
    fn target_counting() {
        assert_eq!(send_target_count("PRIVMSG #a :hi"), 1);
        assert_eq!(send_target_count("PRIVMSG #a,#b,bob :hi"), 3);
        assert_eq!(send_target_count("notice a,,b :x"), 2);
        assert_eq!(send_target_count("@t=1 :me PRIVMSG a,b,c :x"), 3);
        assert_eq!(send_target_count("JOIN #a,#b,#c"), 1);
        let many = (0..6000).map(|i| format!("n{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(send_target_count(&format!("PRIVMSG {many} :x")), 6000);
        // r4 C2-2: runs of spaces (as IRC servers and OutgoingLine read them) don't hide
        // the target list; the old splitn(3, ' ') counted these as 1.
        assert_eq!(send_target_count("PRIVMSG  #a,#b :x"), 2);
        assert_eq!(send_target_count(&format!("PRIVMSG   {many}   :x")), 6000);
        assert_eq!(send_target_count(&format!("@t=1  :me  privmsg  {many} :x")), 6000);
        assert_eq!(send_target_count(&format!("NOTICE  {many} :x")), 6000);
        // The count always matches the targets the Send handler's echo/log loop walks.
        for line in ["PRIVMSG  #a,#b,,c :x", "  NOTICE #a  :x y", "PRIVMSG", "PRIVMSG  ", "PRIVMSG a,b,c d e"] {
            let out = OutgoingLine::parse(line);
            let walked = out.params.first().map_or(0, |t| t.split(',').filter(|t| !t.is_empty()).count());
            assert_eq!(send_target_count(line), walked.max(1), "{line:?}");
        }
        assert!(is_plausible_target("#chan") && is_plausible_target("bob"));
        assert!(!is_plausible_target("") && !is_plausible_target("a\x01b") && !is_plausible_target(&"x".repeat(201)));
    }

    /// r6 (agy P1 main.rs:4759): EVERY ClientMessage variant that carries a `conn_id`
    /// field is canonicalised (read from this file's own source, so a variant added later
    /// without canonicalisation fails here), and the optional E2E ones actually are.
    #[test]
    fn r6_every_conn_id_variant_is_canonicalised() {
        let src = include_str!("main.rs");
        let enum_start = src.find("pub enum ClientMessage {").expect("enum");
        let enum_body = &src[enum_start..enum_start + src[enum_start..].find("\n}\n").expect("enum end")];
        let canon_start = src.find("fn canonicalize_cmd_ids(").expect("fn");
        let canon_body = &src[canon_start..canon_start + src[canon_start..].find("\n}\n").expect("fn end")];
        let mut checked = 0;
        for line in enum_body.lines() {
            let t = line.trim_start();
            if t.starts_with("//") || !t.contains("conn_id") { continue; }
            let name: String = t.chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            if name.is_empty() { continue; }
            assert!(canon_body.contains(&format!("ClientMessage::{name} {{")), "{name} carries a conn_id but is not canonicalised");
            checked += 1;
        }
        assert!(checked >= 15, "found only {checked} conn_id variants — parser out of date?");
        let up = "13DAC991-6798-4923-9421-E6A174F9A8EF";
        let lo = "13dac991-6798-4923-9421-e6a174f9a8ef";
        let c = canonicalize_cmd_ids(ClientMessage::E2EFetchBundle { username: "bob".into(), conn_id: Some(up.into()), req: None });
        assert!(matches!(c, ClientMessage::E2EFetchBundle { conn_id: Some(ref id), .. } if id == lo));
        let c = canonicalize_cmd_ids(ClientMessage::E2ERelayX3DH { target_nick: "bob".into(), header: serde_json::json!({}), conn_id: Some(up.into()) });
        assert!(matches!(c, ClientMessage::E2ERelayX3DH { conn_id: Some(ref id), .. } if id == lo));
        let c = canonicalize_cmd_ids(ClientMessage::E2EFetchBundle { username: "bob".into(), conn_id: None, req: None });
        assert!(matches!(c, ClientMessage::E2EFetchBundle { conn_id: None, .. }));
    }

    /// r5 (codex P1 main.rs:7399): the E2E nick fold follows the network's own rules and is
    /// never wider than them.
    #[test]
    fn r5_e2e_nick_fold_follows_the_network() {
        use cryptirc::ircproto::CaseMapping as C;
        let f = |cm: Option<C>, u: bool, s: &str| e2e_nick_fold(cm, u, s);
        assert_eq!(f(Some(C::Rfc1459), false, "Bob[Work]"), f(Some(C::Rfc1459), false, "bob{work}"));
        assert_eq!(f(Some(C::Rfc1459), false, "a\\b~"), f(Some(C::Rfc1459), false, "A|B^"));
        assert_eq!(f(Some(C::StrictRfc1459), false, "Bob[Work]"), f(Some(C::StrictRfc1459), false, "bob{work}"));
        assert_ne!(f(Some(C::StrictRfc1459), false, "a~"), f(Some(C::StrictRfc1459), false, "a^"));
        // ascii: brackets are different nicks, and so are non-ASCII case variants
        assert_ne!(f(Some(C::Ascii), false, "Bob[Work]"), f(Some(C::Ascii), false, "bob{work}"));
        assert_ne!(f(Some(C::Ascii), false, "\u{c9}lan"), f(Some(C::Ascii), false, "\u{e9}lan"), "never wider than ascii");
        assert_eq!(f(Some(C::Ascii), false, "BoB"), "bob");
        // UTF8MAPPING=rfc8265 (Ergo precis): Unicode case + width + composition
        assert_eq!(f(Some(C::Ascii), true, "\u{c9}lan"), f(Some(C::Ascii), true, "\u{e9}lan"));
        assert_eq!(f(Some(C::Ascii), true, "e\u{301}lan"), f(Some(C::Ascii), true, "\u{e9}lan"));
        assert_eq!(f(Some(C::Ascii), true, "\u{FF22}ob"), "bob");
        // unknown mapping: ascii only
        assert_eq!(f(None, false, "BOB"), "bob");
        assert_ne!(f(None, false, "a[b]"), f(None, false, "a{b}"));
    }

    /// r4 F1-2: every channel of a JOIN/PART list is persisted, keys by list position.
    #[test]
    fn join_part_lists_persist_every_channel() {
        let o = OutgoingLine::parse("JOIN #a,#b,#c ka,kb");
        assert_eq!(join_part_channels(&o.params, true), vec![("#a", "ka"), ("#b", "kb"), ("#c", "")]);
        let o = OutgoingLine::parse("@t=1 :me join  #a,#B  :ka,kb");
        assert_eq!(join_part_channels(&o.params, true), vec![("#a", "ka"), ("#B", "kb")]);
        let o = OutgoingLine::parse("JOIN #solo");
        assert_eq!(join_part_channels(&o.params, true), vec![("#solo", "")]);
        // PART's second param is the reason, never a key.
        let o = OutgoingLine::parse("PART #busy,#noisy :bye now");
        assert_eq!(join_part_channels(&o.params, false), vec![("#busy", ""), ("#noisy", "")]);
        // Invalid names / `JOIN 0` / duplicates are skipped; the list is bounded.
        let o = OutgoingLine::parse("JOIN 0");
        assert!(join_part_channels(&o.params, true).is_empty());
        let o = OutgoingLine::parse("JOIN #a,,nochan,#A,&b k1,k2,k3,k4,k5");
        assert_eq!(join_part_channels(&o.params, true), vec![("#a", "k1"), ("&b", "k5")]);
        let many = (0..300).map(|i| format!("#c{i}")).collect::<Vec<_>>().join(",");
        let line = format!("PART {many}");
        let o = OutgoingLine::parse(&line);
        assert_eq!(join_part_channels(&o.params, false).len(), MAX_JOIN_PART_PERSIST);
        assert!(join_part_channels(&[], true).is_empty());
    }

    #[test]
    fn parse_error_summary_never_echoes_client_text() {
        let evil = format!("x\nFAKE LOG LINE {}", "A".repeat(60_000));
        let frame = serde_json::json!({ "type": evil }).to_string();
        let e = serde_json::from_str::<ClientMessage>(&frame).unwrap_err();
        let s = ws_parse_error_summary(&e);
        // At most a short [A-Za-z0-9_-] slug of the bad type name survives: no
        // newline / spaces (so no forged log line), bounded length.
        assert!(!s.contains('\n') && !s.contains("FAKE LOG") && s.len() < 120, "{s:?}");
        assert!(s.contains("unknown type"), "{s}");
        let e = serde_json::from_str::<ClientMessage>(r#"{"type":"unlock_vault","passphrase":12345678}"#).unwrap_err();
        let s = ws_parse_error_summary(&e);
        assert!(!s.contains("12345678"), "{s}");
        let e = serde_json::from_str::<ClientMessage>("{not json").unwrap_err();
        assert!(ws_parse_error_summary(&e).starts_with("syntax"));
    }

    #[test]
    fn large_frames_only_for_self_capped_saves() {
        assert!(cmd_allows_large_frame(&ClientMessage::SaveStats { data: String::new() }));
        assert!(cmd_allows_large_frame(&ClientMessage::SavePreferences { prefs: String::new() }));
        assert!(!cmd_allows_large_frame(&ClientMessage::Send { conn_id: String::new(), raw: String::new() }));
        assert!(!cmd_allows_large_frame(&ClientMessage::E2EStoreIdentity { blob: String::new(), expect: None }));
        // The transport cap must carry the largest handler cap even fully quote-escaped.
        assert!(WS_MAX_FRAME_BYTES >= 2 * 2_000_000);
    }

    #[tokio::test]
    async fn atomic_user_file_write_replaces_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("cryptirc-wsfix-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("notepad.enc");
        write_user_file_atomic(&p, b"v1").await.unwrap();
        write_user_file_atomic(&p, b"v2-longer").await.unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"v2-longer");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1, "no tmp file left behind");
        // A failing write (target dir gone) reports the error instead of pretending.
        let bad = dir.join("missing-subdir").join("x.enc");
        assert!(write_user_file_atomic(&bad, b"x").await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod disconnect_reason_tests {
    use super::ClientMessage;

    /// SCHEMA LAW: `reason` is additive + `serde(default)`. The Disconnect button
    /// (and any client cached from before 0.4.8) sends no `reason` at all, so if
    /// this ever stops deserializing, the button silently breaks for everyone.
    #[test]
    fn disconnect_without_reason_still_parses() {
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"disconnect","id":"abc"}"#).unwrap();
        match m {
            ClientMessage::Disconnect { id, reason, from_lock } => {
                assert_eq!(id, "abc");
                assert_eq!(reason, None, "absent reason must default to None, not error");
                assert!(!from_lock);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn disconnect_with_reason_parses() {
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"disconnect","id":"abc","reason":"see you tomorrow"}"#)
                .unwrap();
        match m {
            ClientMessage::Disconnect { id, reason, from_lock } => {
                assert_eq!(id, "abc");
                assert_eq!(reason.as_deref(), Some("see you tomorrow"));
                assert!(!from_lock);
            }
            _ => panic!("wrong variant"),
        }
    }

    /// r3 WW-2: `from_lock` is server-internal — a client cannot set it on the wire.
    #[test]
    fn from_lock_is_never_read_from_the_wire() {
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"disconnect","id":"abc","from_lock":true}"#).unwrap();
        assert!(matches!(m, ClientMessage::Disconnect { from_lock: false, .. }));
    }

    /// r3 WW-2: the disconnects app.js sends right after `lock_vault` (one burst on one
    /// socket) are tagged; anything else ends the burst, so a later Disconnect is explicit.
    #[test]
    fn lock_burst_tags_only_the_lock_disconnects() {
        let dc = |id: &str| ClientMessage::Disconnect { id: id.into(), reason: None, from_lock: false };
        let tagged = |m: &ClientMessage| matches!(m, ClientMessage::Disconnect { from_lock: true, .. });
        let mut burst = None;
        let t0 = tokio::time::Instant::now();
        // A plain Disconnect click is explicit.
        assert!(!tagged(&super::mark_lock_burst(dc("a"), &mut burst, t0)));
        // lock_vault + disconnect x2 = lock burst.
        assert!(matches!(super::mark_lock_burst(ClientMessage::LockVault {}, &mut burst, t0), ClientMessage::LockVault {}));
        assert!(tagged(&super::mark_lock_burst(dc("a"), &mut burst, t0)));
        assert!(tagged(&super::mark_lock_burst(dc("b"), &mut burst, t0 + std::time::Duration::from_millis(300))));
        // Any other command ends it; the next Disconnect is explicit again.
        let _ = super::mark_lock_burst(ClientMessage::GetState {}, &mut burst, t0);
        assert!(!tagged(&super::mark_lock_burst(dc("a"), &mut burst, t0)));
        // unlock_vault also ends it.
        let _ = super::mark_lock_burst(ClientMessage::LockVault {}, &mut burst, t0);
        let _ = super::mark_lock_burst(ClientMessage::UnlockVault { passphrase: "x".into() }, &mut burst, t0);
        assert!(!tagged(&super::mark_lock_burst(dc("a"), &mut burst, t0)));
        // r4 (w3-srv INFO 5): the burst is time-bounded — a Disconnect long after the lock,
        // with nothing in between, is explicit.
        let _ = super::mark_lock_burst(ClientMessage::LockVault {}, &mut burst, t0);
        assert!(tagged(&super::mark_lock_burst(dc("a"), &mut burst, t0 + super::LOCK_BURST_WINDOW)));
        assert!(!tagged(&super::mark_lock_burst(dc("b"), &mut burst, t0 + super::LOCK_BURST_WINDOW + std::time::Duration::from_millis(1))));
    }

    /// The client sends `reason: null` when nothing was typed — must be treated
    /// as "no reason", i.e. fall through to the configured Quit Message.
    #[test]
    fn disconnect_with_null_reason_parses_as_none() {
        let m: ClientMessage =
            serde_json::from_str(r#"{"type":"disconnect","id":"abc","reason":null}"#).unwrap();
        match m {
            ClientMessage::Disconnect { reason, .. } => assert_eq!(reason, None),
            _ => panic!("wrong variant"),
        }
    }

    /// Mirrors the handler's own normalisation: a reason that is blank-once-cleaned
    /// must degrade to None so the configured Quit Message is used instead of an
    /// empty QUIT reason, and an embedded CRLF must never survive.
    #[test]
    fn blank_and_crlf_reasons_normalise_like_the_handler() {
        let norm = |r: Option<&str>| -> Option<String> {
            r.map(|r| crate::strip_crlf(r).trim().to_string())
                .filter(|r| !r.is_empty())
        };
        assert_eq!(norm(Some("   ")), None);
        assert_eq!(norm(Some("\r\n")), None);
        assert_eq!(norm(Some("bye")), Some("bye".to_string()));
        let injected = norm(Some("bye\r\nJOIN #evil")).unwrap();
        assert!(!injected.contains('\r') && !injected.contains('\n'),
                "CRLF must not survive into the QUIT line: {injected:?}");
    }
}

#[cfg(test)]
mod e2e_r2_protocol_tests {
    use super::*;

    #[test]
    fn legacy_trust_commands_parse_as_no_ops() {
        for frame in [
            r#"{"type":"e2e_load_trust"}"#,
            r#"{"type":"e2e_update_trust","nick":"peer","fingerprint":"legacy","verified":true}"#,
        ] {
            assert!(matches!(serde_json::from_str(frame), Ok(ClientMessage::E2ELegacyTrust {})));
        }
    }

    /// SCHEMA LAW (r2): the new optional fields must not break any existing sender —
    /// the TUI's / an older app.js's auth frame, older keyring stores and session stores.
    #[test]
    fn old_frames_still_parse() {
        let m: ClientMessage = serde_json::from_str(r#"{"type":"auth","token":"t"}"#).unwrap();
        assert!(matches!(m, ClientMessage::Auth { e2e: 0, .. }));
        let m: ClientMessage = serde_json::from_str(r#"{"type":"auth","token":"t","e2e":2}"#).unwrap();
        assert!(matches!(m, ClientMessage::Auth { e2e: 2, .. }));
        let m: ClientMessage = serde_json::from_str(r#"{"type":"e2e_store_keyring","blob":"e2k2.x","migrated":true}"#).unwrap();
        assert!(matches!(m, ClientMessage::E2EStoreKeyring { expect: None, .. }));
        let m: ClientMessage = serde_json::from_str(r#"{"type":"e2e_store_session","partner":"bob","blob":"e2e2.x"}"#).unwrap();
        assert!(matches!(m, ClientMessage::E2EStoreSession { dv: None, snd: false, .. }));
        // the stored reply keeps its old shape unless there was a conflict
        let s = serde_json::to_string(&ServerEvent::E2EKeyringStored { migrated: true, conflict: false, blob: None }).unwrap();
        assert_eq!(s, r#"{"type":"e2e_keyring_stored","migrated":true}"#);
    }

    #[test]
    fn legacy_gate_line_classification() {
        assert_eq!(e2e_split_chat_line("PRIVMSG #a,bob :hi there"), Some(("PRIVMSG".into(), "#a,bob".into(), "hi there".into())));
        assert_eq!(e2e_split_chat_line("@+typing=active TAGMSG bob"), None);
        assert_eq!(e2e_split_chat_line("@t=1 notice bob :x"), Some(("NOTICE".into(), "bob".into(), "x".into())));
        assert_eq!(e2e_split_chat_line("JOIN #a"), None);
        assert!(e2e_text_is_cleartext("hello"));
        assert!(e2e_text_is_cleartext("\u{1}ACTION waves\u{1}"));          // /me carries user text
        assert!(!e2e_text_is_cleartext("\u{1}VERSION CryptIRC\u{1}"));    // automatic CTCP reply
        assert!(!e2e_text_is_cleartext("sd8~eyJ2IjoxfQ=="));
        assert!(!e2e_text_is_cleartext("[e2edm2]eyJ9"));
        assert!(!e2e_text_is_cleartext("[e2ex3dh]~abcd~1~2~AAAA"));
        assert!(!e2e_text_is_cleartext(""));
    }

    #[test]
    fn r3_legacy_gate_spacing_casefold_and_target_forms() {
        // runs of spaces separate parameters, as servers parse them
        assert_eq!(e2e_split_chat_line("PRIVMSG  #chan :secret"), Some(("PRIVMSG".into(), "#chan".into(), "secret".into())));
        assert_eq!(e2e_split_chat_line("PRIVMSG #chan  :secret"), Some(("PRIVMSG".into(), "#chan".into(), "secret".into())));
        assert_eq!(e2e_split_chat_line("  @a=b   :me!u@h   privmsg   bob   :x y"), Some(("PRIVMSG".into(), "bob".into(), "x y".into())));
        assert_eq!(e2e_split_chat_line("PRIVMSG #chan secret"), Some(("PRIVMSG".into(), "#chan".into(), "secret".into())));
        assert_eq!(e2e_split_chat_line("PRIVMSG   "), None);
        // widest case-fold: RFC1459 specials and case
        assert_eq!(e2e_fold_all("#Team[Private]"), e2e_fold_all("#team{private}"));
        assert_eq!(e2e_fold_all("Bob\\^"), e2e_fold_all("bob|~"));
        // r4 V3W-N2: rfc8265/PRECIS spellings — fullwidth forms and decomposed accents.
        assert_eq!(e2e_fold_all("\u{FF03}\u{FF53}\u{FF45}\u{FF43}"), "#sec");          // ＃ｓｅｃ
        assert_eq!(e2e_fold_all("\u{FF03}\u{FF33}\u{FF25}\u{FF23}"), "#sec");          // ＃ＳＥＣ
        assert_eq!(e2e_fold_all("#se\u{301}c"), e2e_fold_all("#s\u{e9}c"));              // e + U+0301 = é
        assert_eq!(e2e_fold_all("#SE\u{301}C"), e2e_fold_all("#s\u{e9}c"));
        assert_eq!(e2e_fold_all("\u{FF22}\u{FF4F}\u{FF42}"), "bob");                    // Ｂｏｂ
        assert_eq!(e2e_fold_all("#\u{FF3B}x\u{FF3D}"), "#{x}", "fullwidth brackets fold like [ ]");
        assert_ne!(e2e_fold_all("#sec"), e2e_fold_all("#sec2"));
        {
            let names = |t: &str| e2e_target_names(t).into_iter().map(|(_, k)| k).collect::<Vec<_>>();
            // behind STATUSMSG prefixes, and with a fullwidth channel/STATUSMSG prefix too
            for t in ["@#\u{FF53}\u{FF45}\u{FF43}", "@\u{FF03}\u{FF53}\u{FF45}\u{FF43}", "\u{FF20}#se\u{301}c"] {
                let n = names(t);
                assert!(n.contains(&"#sec".to_string()) || n.contains(&e2e_fold_all("#s\u{e9}c")), "{t:?} -> {n:?}");
            }
            // a fullwidth nick behind nick!user@host
            assert!(names("\u{FF22}ob!u@h").contains(&"bob".to_string()));
        }
        let names = |t: &str| e2e_target_names(t).into_iter().map(|(_, k)| k).collect::<Vec<_>>();
        // STATUSMSG prefixes (incl. '&' and stacked ones) reach the channel
        for t in ["@#sec", "+#sec", "%#sec", "~#sec", "&#sec", "@+#sec"] {
            assert!(names(t).contains(&"#sec".to_string()), "{}", t);
        }
        // a '&' channel is itself, and also what is behind '&' when that is a channel
        assert_eq!(names("&local"), vec!["&local".to_string()]);
        // nick!user@host / nick@server / nick%host reach the nick
        for t in ["bob!b@host", "bob@irc.example.org", "Bob%host"] {
            assert!(names(t).contains(&"bob".to_string()), "{}", t);
        }
        // channels and server masks are not split on '!'/'@'
        assert_eq!(names("#a@b"), vec!["#a@b".to_string()]);
        assert_eq!(names("$*.org"), vec!["$*.org".to_string()]);
    }
}

#[cfg(test)]
mod srv_b_r3_tests {
    use super::*;

    /// r3 C1-5: the vault-KDF permit is held by the blocking job itself, so aborting the
    /// awaiting task (WS socket teardown aborts recv_task) does NOT free it while the
    /// derivation is still running.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn vault_kdf_permit_outlives_an_aborted_caller() {
        let sem: &'static Semaphore = Box::leak(Box::new(Semaphore::new(2)));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let h = tokio::spawn(async move { run_vault_kdf(sem, move || { let _ = release_rx.recv(); 7 }).await });
        for _ in 0..200 { if sem.available_permits() == 1 { break; } tokio::time::sleep(std::time::Duration::from_millis(5)).await; }
        assert_eq!(sem.available_permits(), 1, "job holds one permit");
        h.abort();
        let _ = h.await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(sem.available_permits(), 1, "permit must stay held while the derive still runs");
        release_tx.send(()).unwrap();
        for _ in 0..200 { if sem.available_permits() == 2 { break; } tokio::time::sleep(std::time::Duration::from_millis(5)).await; }
        assert_eq!(sem.available_permits(), 2, "released when the derive ends");
    }

    /// The 0d3570d shape (permit held by the async caller around spawn_blocking), kept
    /// here as the red half of the C1-5 proof: an abort frees the permit early.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn old_kdf_permit_shape_leaked_on_abort() {
        let sem: &'static Semaphore = Box::leak(Box::new(Semaphore::new(2)));
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let h = tokio::spawn(async move {
            let _p = sem.acquire().await;
            tokio::task::spawn_blocking(move || { let _ = release_rx.recv(); }).await.ok()
        });
        for _ in 0..200 { if sem.available_permits() == 1 { break; } tokio::time::sleep(std::time::Duration::from_millis(5)).await; }
        h.abort();
        let _ = h.await;
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(sem.available_permits(), 2, "old shape: permit freed while the blocking job still runs");
        release_tx.send(()).unwrap();
    }

    /// r3 WS-8: a socket that has not read yet keeps the newest snapshot of EVERY kind —
    /// its own PasswordSafe reply is not pushed out by 8 later Preferences broadcasts
    /// (one mixed 8-slot ring dropped it: Lagged, and that kind never arrived).
    #[test]
    fn bulk_snapshot_kinds_do_not_evict_each_other() {
        let user = "srvb-r3-bulk-test";
        let [mut np, mut st, mut pw, mut pref] = user_bulk_subscribe(user);
        send_bulk_to_user(user, ServerEvent::PasswordSafe { data: "pw-1".into() });
        send_bulk_to_user(user, ServerEvent::Notepad { content: "np-1".into() });
        for i in 0..8 { send_bulk_to_user(user, ServerEvent::Preferences { prefs: format!("p-{i}") }); }
        assert!(matches!(pw.try_recv(), Ok(ServerEvent::PasswordSafe { ref data }) if data == "pw-1"));
        assert!(matches!(np.try_recv(), Ok(ServerEvent::Notepad { ref content }) if content == "np-1"));
        assert!(st.try_recv().is_err(), "no StatsData was sent");
        // Preferences lagged, but the newest copy is delivered.
        let mut last = None;
        loop {
            match pref.try_recv() {
                Ok(ServerEvent::Preferences { prefs }) => last = Some(prefs),
                Err(broadcast::error::TryRecvError::Lagged(_)) => continue,
                _ => break,
            }
        }
        assert_eq!(last.as_deref(), Some("p-7"));
        drop((np, st, pw, pref));
        user_bulk_prune(user);
        assert!(user_bulk_events().get(user).is_none());
    }

    /// r3 C2-1 (security-review follow-up): Sole only for an owner list of exactly [me].
    #[test]
    fn id_ownership_is_sole_only_for_exactly_this_account() {
        let v = |xs: &[&str]| xs.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(classify_id_owners(Some(&v(&["alice"])), "alice"), IdOwnership::Sole);
        assert_eq!(classify_id_owners(Some(&v(&["alice", "bob"])), "alice"), IdOwnership::Shared);
        assert_eq!(classify_id_owners(Some(&v(&["alice", "bob"])), "bob"), IdOwnership::Shared);
        // the one remaining owner is the OTHER account: not sole (153eddc said "not shared")
        assert_eq!(classify_id_owners(Some(&v(&["alice"])), "bob"), IdOwnership::NotListed);
        assert_eq!(classify_id_owners(Some(&v(&[])), "bob"), IdOwnership::NotListed);
        assert_eq!(classify_id_owners(None, "alice"), IdOwnership::Unverified, "unreadable = fail closed");
        assert!(IdOwnership::Unverified.maybe_shared() && IdOwnership::Shared.maybe_shared());
        assert!(!IdOwnership::Sole.maybe_shared() && !IdOwnership::NotListed.maybe_shared());
        assert_eq!(IdOwnership::Unverified.refusal(), Some(ID_OWNERS_UNVERIFIED_MSG));
        assert_eq!(IdOwnership::Shared.refusal(), Some(CONTESTED_NETWORK_MSG));
    }

    /// r3 C2-1: the owner list is read fresh from the disk, so the other account's copy
    /// changing or vanishing between two checks is seen, and only the account whose copy
    /// remains becomes Sole; a re-cased legacy file name still counts.
    #[tokio::test]
    async fn id_owners_follow_the_disk_between_checks() {
        let dir = std::env::temp_dir().join(format!("cryptirc-idowners-{}", Uuid::new_v4()));
        let d = dir.to_string_lossy().to_string();
        let id = "11111111-2222-3333-4444-555555555555";
        assert_eq!(network_id_owners(&d, id).await, Some(vec![]), "no networks dir yet");
        for u in ["alice", "bob"] {
            std::fs::create_dir_all(dir.join("networks").join(u)).unwrap();
            std::fs::write(dir.join("networks").join(u).join(format!("{id}.json")), "{}").unwrap();
        }
        std::fs::create_dir_all(dir.join("networks").join("carol")).unwrap();
        std::fs::write(dir.join("networks").join("carol").join("other.json"), "{}").unwrap();
        let o = network_id_owners(&d, id).await;
        assert_eq!(o, Some(vec!["alice".to_string(), "bob".to_string()]));
        assert_eq!(classify_id_owners(o.as_deref(), "alice"), IdOwnership::Shared);
        // bob's copy is rewritten (save = tmp + rename): still an owner
        std::fs::write(dir.join("networks/bob").join(format!("{id}.json.tmp")), "{\"x\":1}").unwrap();
        std::fs::rename(dir.join("networks/bob").join(format!("{id}.json.tmp")), dir.join("networks/bob").join(format!("{id}.json"))).unwrap();
        assert_eq!(classify_id_owners(network_id_owners(&d, id).await.as_deref(), "alice"), IdOwnership::Shared);
        // alice's copy vanishes: bob is now the sole owner, alice is NOT
        std::fs::remove_file(dir.join("networks/alice").join(format!("{id}.json"))).unwrap();
        let o = network_id_owners(&d, id).await;
        assert_eq!(classify_id_owners(o.as_deref(), "alice"), IdOwnership::NotListed);
        assert_eq!(classify_id_owners(o.as_deref(), "bob"), IdOwnership::Sole);
        // the normal sole-owner path: a fresh id only bob names
        let id2 = "22222222-2222-3333-4444-555555555555";
        std::fs::write(dir.join("networks/bob").join(format!("{id2}.json")), "{}").unwrap();
        assert_eq!(classify_id_owners(network_id_owners(&d, id2).await.as_deref(), "bob"), IdOwnership::Sole);
        // a legacy re-cased file name under another account still makes the id shared
        std::fs::write(dir.join("networks/carol").join(format!("{}.json", id2.to_ascii_uppercase())), "{}").unwrap();
        assert_eq!(classify_id_owners(network_id_owners(&d, id2).await.as_deref(), "bob"), IdOwnership::Shared);
        // an account dir that can't even be searched: THIS id is unverified (fail closed)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.join("networks/carol"), std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read_dir(dir.join("networks/carol")).is_err() {   // (root ignores modes)
                assert_eq!(network_id_owners(&d, id2).await, None);
                assert_eq!(classify_id_owners(network_id_owners(&d, id2).await.as_deref(), "bob"), IdOwnership::Unverified);
            }
            std::fs::set_permissions(dir.join("networks/carol"), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // r4 (w3-srv INFO 4): narrowed. A searchable but unlistable account dir (0o100) and
        // a non-UTF-8 entry no longer make every id fail closed: an exact `<id>.json` in the
        // unlistable dir still counts, an id it doesn't hold stays Sole for its real owner.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            use std::os::unix::fs::PermissionsExt;
            let id3 = "33333333-aaaa-3333-4444-555555555555";
            let id4 = "44444444-aaaa-3333-4444-555555555555";
            std::fs::write(dir.join("networks/carol").join(format!("{id3}.json")), "{}").unwrap();
            std::fs::write(dir.join("networks/bob").join(format!("{id3}.json")), "{}").unwrap();
            std::fs::write(dir.join("networks/bob").join(format!("{id4}.json")), "{}").unwrap();
            let odd = dir.join("networks").join(std::ffi::OsStr::from_bytes(b"bad\xffname"));
            let _ = std::fs::create_dir_all(&odd);
            std::fs::set_permissions(dir.join("networks/carol"), std::fs::Permissions::from_mode(0o100)).unwrap();
            if std::fs::read_dir(dir.join("networks/carol")).is_err() {   // (root ignores modes)
                assert_eq!(classify_id_owners(network_id_owners(&d, id3).await.as_deref(), "bob"), IdOwnership::Shared);
                assert_eq!(classify_id_owners(network_id_owners(&d, id4).await.as_deref(), "bob"), IdOwnership::Sole);
            }
            std::fs::set_permissions(dir.join("networks/carol"), std::fs::Permissions::from_mode(0o700)).unwrap();
            assert_eq!(classify_id_owners(network_id_owners(&d, id4).await.as_deref(), "bob"), IdOwnership::Sole);
            assert_eq!(network_id_owners(&d, id3).await, Some(vec!["bob".to_string(), "carol".to_string()]));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r3 C2-1 (follow-up 2): a fresh claim drops every event of the replaced session
    /// until the fresh session's first Connecting; other ids are untouched.
    #[test]
    fn fresh_claim_quarantine_drops_until_the_fresh_connecting() {
        use cryptirc::ipc::{ConnLifecycle, IpcMessage};
        let id = "33333333-2222-3333-4444-555555555555".to_string();
        let other = "44444444-2222-3333-4444-555555555555".to_string();
        let line = |c: &str| IpcMessage::RawLine { conn_id: c.into(), line: ":v PRIVMSG #x :hi".into(), replayed: true, backlog: false, recv_ts: 0, seq: 0 };
        let owner = |c: &str| if c == id { Some("bob".to_string()) } else { None };
        fresh_claim_quarantine().insert(id.clone(), "bob".into());
        assert!(!fresh_claim_admits_with(&line(&id), owner), "old session's replayed line dropped");
        assert!(!fresh_claim_admits_with(&IpcMessage::ConnStatus { conn_id: id.clone(), state: ConnLifecycle::Disconnected { reason: "Replaced".into() } }, owner));
        assert!(fresh_claim_admits_with(&line(&other), owner), "other ids unaffected");
        assert!(fresh_claim_admits_with(&IpcMessage::ConnStatus { conn_id: id.clone(), state: ConnLifecycle::Connecting }, owner), "fresh session starts");
        assert!(fresh_claim_admits_with(&line(&id), owner), "quarantine lifted");
        assert!(!fresh_claim_quarantine().contains_key(&id));
    }

    /// r4 C1-2 / C2-1: the quarantine is bound to the claiming account. A Connecting that
    /// arrives while conn_owners does not (yet / any more) name the claimant — e.g. the
    /// replaced session's own reconnect attempt, processed before the claim's owner insert,
    /// or after the id changed hands — does NOT lift it.
    #[test]
    fn fresh_claim_quarantine_is_bound_to_the_claimant() {
        use cryptirc::ipc::{ConnLifecycle, IpcMessage};
        let id = "55555555-2222-3333-4444-555555555555".to_string();
        let connecting = IpcMessage::ConnStatus { conn_id: id.clone(), state: ConnLifecycle::Connecting };
        let line = IpcMessage::RawLine { conn_id: id.clone(), line: ":v PRIVMSG alice :private".into(), replayed: false, backlog: false, recv_ts: 0, seq: 0 };
        fresh_claim_quarantine().insert(id.clone(), "bob".into());
        // Not owned yet (claim between quarantine and owner insert): stays closed.
        assert!(!fresh_claim_admits_with(&connecting, |_| None));
        assert!(!fresh_claim_admits_with(&line, |_| None));
        // Owned by someone else: stays closed.
        assert!(!fresh_claim_admits_with(&connecting, |_| Some("alice".into())));
        assert!(!fresh_claim_admits_with(&line, |_| Some("alice".into())));
        assert!(fresh_claim_quarantine().contains_key(&id));
        // A later claim by alice re-binds it; only alice's Connecting lifts it.
        fresh_claim_quarantine().insert(id.clone(), "alice".into());
        assert!(!fresh_claim_admits_with(&connecting, |_| Some("bob".into())));
        assert!(fresh_claim_admits_with(&connecting, |_| Some("alice".into())));
        assert!(fresh_claim_admits_with(&line, |_| Some("alice".into())));
        assert!(!fresh_claim_quarantine().contains_key(&id));
    }

    /// r3 A1-4: the Send handler classifies by the real verb/params.
    #[test]
    fn outgoing_line_parse_matches_irc_grammar() {
        let p = OutgoingLine::parse("PRIVMSG #chan :hello world");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("PRIVMSG", vec!["#chan", "hello world"]));
        let p = OutgoingLine::parse("@+draft/reply=abc PRIVMSG #chan :hi there");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("PRIVMSG", vec!["#chan", "hi there"]));
        let p = OutgoingLine::parse(":me!u@h notice  bob   :x  y");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("NOTICE", vec!["bob", "x  y"]));
        let p = OutgoingLine::parse("  @t=1 :src PRIVMSG  #a,#b  :\u{1}ACTION waves\u{1}");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("PRIVMSG", vec!["#a,#b", "\u{1}ACTION waves\u{1}"]));
        // a middle (non-trailing) text param is one word, as servers read it
        let p = OutgoingLine::parse("PRIVMSG #c hello world");
        assert_eq!(p.params, vec!["#c", "hello", "world"]);
        let p = OutgoingLine::parse("@+typing=active TAGMSG bob");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("TAGMSG", vec!["bob"]));
        let p = OutgoingLine::parse("JOIN  #a,#b   ka,kb");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("JOIN", vec!["#a,#b", "ka,kb"]));
        let p = OutgoingLine::parse("part #a :bye now");
        assert_eq!((p.verb.as_str(), p.params.clone()), ("PART", vec!["#a", "bye now"]));
        let p = OutgoingLine::parse("PRIVMSG #chan :");
        assert_eq!(p.params, vec!["#chan", ""]);
        assert_eq!(OutgoingLine::parse("").verb, "");
        assert_eq!(OutgoingLine::parse("@only-tags").verb, "");
        let p = OutgoingLine::parse("QUIT");
        assert_eq!((p.verb.as_str(), p.params.len()), ("QUIT", 0));
        // a body that merely contains a verb is not that verb
        assert_eq!(OutgoingLine::parse("PRIVMSG #c :JOIN #x").verb, "PRIVMSG");
    }
}

#[cfg(test)]
mod r7_srv_a_news_tests {
    //! r7 (codex P1 main.rs:4422): the news feed is refreshed by one fetch at a time, and a
    //! failed refresh backs off instead of sending every request to the origin.
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    type Cache = tokio::sync::Mutex<Option<(String, Instant)>>;

    async fn burst(cache: &Arc<Cache>, slot: &Arc<tokio::sync::Mutex<NewsRefresh>>, calls: &Arc<AtomicUsize>, n: usize, ok: bool) -> Vec<Option<String>> {
        let mut hs = Vec::new();
        for _ in 0..n {
            let (cache, slot, calls) = (cache.clone(), slot.clone(), calls.clone());
            hs.push(tokio::spawn(async move {
                news_serve(&cache, &slot, Duration::from_secs(45), || async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(300)).await;   // a slow origin
                    if ok { Some("{\"posts\":[1]}".to_string()) } else { None }
                }).await
            }));
        }
        let mut out = Vec::new();
        for h in hs { out.push(h.await.unwrap()); }
        out
    }

    #[tokio::test]
    async fn a_burst_on_an_empty_cache_with_the_origin_down_makes_one_upstream_request() {
        let (cache, slot, calls) = (Arc::new(Cache::new(None)), Arc::new(tokio::sync::Mutex::new(NewsRefresh::default())), Arc::new(AtomicUsize::new(0)));
        let r = burst(&cache, &slot, &calls, 50, false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "single flight");
        assert!(r.iter().all(|x| x.is_none()), "502 for all: nothing cached");
        // Inside the backoff: no upstream request at all.
        let r = burst(&cache, &slot, &calls, 50, false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "backoff");
        assert!(r.iter().all(|x| x.is_none()));
        assert_eq!(slot.lock().await.fail_streak, 1);
    }

    #[tokio::test]
    async fn an_expired_copy_is_served_stale_while_one_refresh_runs_and_after_it_fails() {
        let old = Instant::now() - Duration::from_secs(120);
        let cache = Arc::new(Cache::new(Some(("STALE".to_string(), old))));
        let (slot, calls) = (Arc::new(tokio::sync::Mutex::new(NewsRefresh::default())), Arc::new(AtomicUsize::new(0)));
        let t0 = Instant::now();
        let r = burst(&cache, &slot, &calls, 50, false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(r.iter().all(|x| x.as_deref() == Some("STALE")));
        assert!(t0.elapsed() < Duration::from_secs(2));
        let r = burst(&cache, &slot, &calls, 20, false).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "no upstream request inside the backoff");
        assert!(r.iter().all(|x| x.as_deref() == Some("STALE")));
    }

    #[tokio::test]
    async fn a_successful_refresh_is_cached_and_clears_the_backoff() {
        let cache = Arc::new(Cache::new(None));
        let slot = Arc::new(tokio::sync::Mutex::new(NewsRefresh { fail_streak: 3, retry_at: None }));
        let calls = Arc::new(AtomicUsize::new(0));
        let r = burst(&cache, &slot, &calls, 30, true).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "the others waited for that one fetch");
        assert!(r.iter().all(|x| x.as_deref() == Some("{\"posts\":[1]}")));
        let s = slot.lock().await;
        assert_eq!((s.fail_streak, s.retry_at.is_none()), (0, true));
        drop(s);
        burst(&cache, &slot, &calls, 10, true).await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "fresh copy served from the cache");
    }

    #[test]
    fn the_backoff_doubles_up_to_its_cap() {
        let secs: Vec<u64> = (1..=8u32).map(|n| (NEWS_BACKOFF_MIN_SECS << (n - 1).min(5)).min(NEWS_BACKOFF_MAX_SECS)).collect();
        assert_eq!(secs, vec![15, 30, 60, 120, 240, 300, 300, 300]);
    }
}

#[cfg(test)]
mod r8_srv_a_news_rate_tests {
    //! r8 (agy P1 main.rs:4426): the per-account news rate map is pruned of expired windows.
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn expired_rate_entries_are_dropped_once_the_map_is_large() {
        let map: DashMap<String, (Instant, u32)> = DashMap::new();
        let w = Duration::from_secs(60);
        let now = Instant::now();
        let old = now.checked_sub(Duration::from_secs(120)).unwrap_or(now);
        // 3000 accounts that read the news more than a window ago (e.g. since deleted).
        for k in 0..3000 { map.insert(format!("gone{}", k), (old, 5)); }
        assert!(news_rate_check(&map, "alice", now, w, 30));
        assert_eq!(map.len(), 1, "only accounts inside the current window remain");
        // Below the threshold nothing is swept (no work on the common path).
        for k in 0..10 { map.insert(format!("idle{}", k), (old, 1)); }
        assert!(news_rate_check(&map, "bob", now, w, 30));
        assert_eq!(map.len(), 12);
    }

    #[test]
    fn the_per_account_limit_is_unchanged() {
        let map: DashMap<String, (Instant, u32)> = DashMap::new();
        let (w, now) = (Duration::from_secs(60), Instant::now());
        let ok = (0..35).filter(|_| news_rate_check(&map, "carol", now, w, 30)).count();
        assert_eq!(ok, 30);
        // A new window starts afresh.
        assert!(news_rate_check(&map, "carol", now + Duration::from_secs(61), w, 30));
    }
}

#[cfg(test)]
mod tweet_route_tests {
    use super::*;

    struct Server(tokio::task::JoinHandle<()>);
    impl Drop for Server {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    #[test]
    fn media_proxy_signature_and_range_validation() {
        let alice = media_subject("alice");
        assert_eq!(alice, media_subject("Alice"));
        assert_ne!(alice, media_subject("bob"));
        assert!(!alice.contains("alice") && alice.len() == 16);
        let (url, proxy, expires) =
            sign_media_path("/cryptirc", "https://pbs.twimg.com/media/example.jpg?name=small", &alice).unwrap();
        assert!(proxy.starts_with("/cryptirc/tweet/media?"));
        let parsed = reqwest::Url::parse(&format!("https://local.test{proxy}")).unwrap();
        let params: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(params["url"], url);
        assert_eq!(params["exp"].parse::<i64>().unwrap(), expires);
        assert_eq!(params["a"], alice);
        let verified = verify_media_signature(&url, expires, &alice, &params["sig"]).unwrap();
        assert_eq!(verified, (url.clone(), twitter::ProxyMediaKind::Image));
        let mut tampered = params["sig"].clone();
        let first = tampered.remove(0);
        tampered.insert(0, if first == 'A' { 'B' } else { 'A' });
        assert!(verify_media_signature(&url, expires, &alice, &tampered).is_none());
        assert!(verify_media_signature(&url, chrono::Utc::now().timestamp() - 1, &alice, &params["sig"]).is_none());
        // A signature binds the exact normalized URL and the account it was issued to.
        assert!(verify_media_signature("https://pbs.twimg.com/media/other.jpg?name=small", expires, &alice, &params["sig"]).is_none());
        assert!(verify_media_signature(&url, expires, &media_subject("bob"), &params["sig"]).is_none());
        assert!(sign_media_path("", "https://pbs.twimg.com/media/example.jpg", "").is_none());
        assert!(sign_media_path("", "https://evil.test/media/a.jpg", &alice).is_none());
        // Port hardening: unrecognized paths, SVG, playlists are never signed.
        for raw in [
            "https://pbs.twimg.com/avatar.jpg",
            "https://pbs.twimg.com/media/a.svg",
            "https://pbs.twimg.com/media/a?format=svg",
            "https://video.twimg.com/ext_tw_video/1/pu/pl/playlist.m3u8",
            "https://video.twimg.com/ext_tw_video/1/pu/vid/a.mp4?redirect=https://evil.test",
        ] {
            assert!(sign_media_path("", raw, &alice).is_none(), "{raw}");
        }
        let (_, video, _) = sign_media_path("", "https://video.twimg.com/ext_tw_video/1/pu/vid/640x360/a.mp4?tag=12", &alice).unwrap();
        assert!(video.starts_with("/tweet/media?"));
    }

    fn router(state: TweetRouteState, base: &str) -> Router {
        let inner = Router::new()
            .route("/tweet/config", get(route_tweet_config))
            .route("/tweet/preview", get(route_tweet_preview))
            .route("/tweet/thread", get(route_tweet_thread))
            .route("/tweet/media", get(route_tweet_media))
            .route("/tweet/media/sign", post(route_tweet_media_sign));
        if base.is_empty() { inner } else { Router::new().nest(base, inner) }
            .layer(middleware::from_fn(security_headers_mw))
            .with_state(state)
    }

    #[tokio::test]
    async fn route_tweet_auth_cache_budget_query_and_base_paths() {
        for base in ["", "/cryptirc", "/nested/prefix"] {
            let fixture = preview::tweet_tests::Fixture::new();
            let auth = Arc::new(AuthManager::new(fixture.path.to_str().unwrap()).unwrap());
            // v0.5.8 sessions are only valid while the account record exists on disk. A
            // minimal record is enough (and avoids three debug-build Argon2 hashes, whose CPU
            // load slows the timing-sensitive auth tests running in parallel).
            std::fs::create_dir_all(fixture.path.join("users")).unwrap();
            std::fs::write(fixture.path.join("users/alice.json"), r#"{"username":"alice"}"#).unwrap();
            let token = auth.issue_session("alice");
            let rates = Arc::new(DashMap::new());
            let mut state = test_state(auth, &fixture, base);
            state.rates = rates.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let app = router(state, base);
            let _server = Server(tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            }));
            let endpoint = format!("http://{address}{base}/tweet/preview");
            let client = reqwest::Client::builder().no_proxy().build().unwrap();
            let url = "https://x.com/example/status/123";
            let status = |r: &reqwest::Response| r.status().as_u16();

            let config = format!("http://{address}{base}/tweet/config");
            assert_eq!(status(&client.get(&config).send().await.unwrap()), 401);
            let response = client.get(&config).bearer_auth(&token).send().await.unwrap();
            assert_eq!(status(&response), 200);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
            assert_eq!(body, serde_json::json!({"schema_version":1,"preview":true,"thread":false}));

            let thread_endpoint = format!("http://{address}{base}/tweet/thread");
            assert_eq!(status(&client.get(&thread_endpoint).query(&[("url", url)]).send().await.unwrap()), 401);
            let thread = client.get(&thread_endpoint).bearer_auth(&token).query(&[("url", url)]).send().await.unwrap();
            assert_eq!(status(&thread), 200);
            let thread: serde_json::Value = serde_json::from_slice(&thread.bytes().await.unwrap()).unwrap();
            assert_eq!(thread["availability"]["reason"], "provider_disabled");

            let sign_endpoint = format!("http://{address}{base}/tweet/media/sign");
            let avatar = "https://pbs.twimg.com/profile_images/1/synthetic_normal.jpg";
            let sign_body = serde_json::json!({"urls":[avatar]}).to_string();
            let sign = |token: Option<&str>, body: String| {
                let mut request = client.post(&sign_endpoint).header("content-type", "application/json").body(body);
                if let Some(token) = token { request = request.bearer_auth(token); }
                request.send()
            };
            assert_eq!(status(&sign(None, sign_body.clone()).await.unwrap()), 401);
            // Not yet retrieved by this viewer: the fallback is not an open CDN proxy.
            let refused = sign(Some(&token), sign_body.clone()).await.unwrap();
            assert_eq!(status(&refused), 403);
            assert_eq!(refused.headers()["cache-control"], "private, no-store");

            let response = client.get(&endpoint).query(&[("url", url)]).send().await.unwrap();
            assert_eq!(status(&response), 401);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            assert_eq!(response.headers()["vary"], "Authorization");
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 0);
            let response = client.get(&endpoint).bearer_auth(&token).query(&[("url", url)]).send().await.unwrap();
            assert_eq!(status(&response), 200);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            let body: serde_json::Value = serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
            assert_eq!(body["id"], "123");
            let response = client
                .get(&endpoint)
                .bearer_auth(&token)
                .query(&[("url", "https://mobile.twitter.com/other/status/123/photo/2?secret=ignored")])
                .send()
                .await
                .unwrap();
            assert_eq!(status(&response), 200);
            assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
            // A warm cache never answers an unauthenticated request.
            assert_eq!(status(&client.get(&endpoint).query(&[("url", url)]).send().await.unwrap()), 401);

            let signed = sign(Some(&token), sign_body.clone()).await.unwrap();
            assert_eq!(status(&signed), 200);
            assert_eq!(signed.headers()["cache-control"], "private, no-store");
            let signed: serde_json::Value = serde_json::from_slice(&signed.bytes().await.unwrap()).unwrap();
            let proxy_url = signed["urls"][0]["proxy_url"].as_str().unwrap().to_string();
            assert!(proxy_url.starts_with(&format!("{base}/tweet/media?")));
            assert_eq!(status(&sign(Some(&token), serde_json::json!({"urls":["https://evil.test/a.jpg"]}).to_string()).await.unwrap()), 400);
            assert_eq!(status(&sign(Some(&token), serde_json::json!({"urls":[]}).to_string()).await.unwrap()), 400);
            assert_eq!(status(&sign(Some(&token), "not json".into()).await.unwrap()), 400);

            // Redemption checks that need no network: bad signature, bad range.
            let media = format!("http://{address}{proxy_url}");
            let forged = media.replace("sig=", "sig=AAAA");
            assert_eq!(status(&client.get(&forged).send().await.unwrap()), 403);
            for range in ["bytes=abc", "bytes=0-1,3-4", "items=0-1", "bytes=5-1", "bytes=-0"] {
                assert_eq!(status(&client.get(&media).header("range", range).send().await.unwrap()), 416, "{range}");
            }
            assert_eq!(status(&client.get(format!("{media}&extra=1")).send().await.unwrap()), 400);

            for params in [
                vec![("url", "https://x.com.evil/a/status/123")],
                vec![("url", url), ("refresh", "0")],
                vec![("url", url), ("target", "secret")],
                vec![],
            ] {
                let response = client.get(&endpoint).bearer_auth(&token).query(&params).send().await.unwrap();
                assert_eq!(status(&response), 400);
                assert_eq!(response.headers()["cache-control"], "private, no-store");
            }
            let oversized = format!("{url}?a={}", "x".repeat(2048));
            assert_eq!(status(&client.get(&endpoint).bearer_auth(&token).query(&[("url", oversized.as_str())]).send().await.unwrap()), 400);
            let permits = fixture.semaphore().try_acquire_many_owned(8).unwrap();
            let busy = client.get(&endpoint).bearer_auth(&token).query(&[("url", "https://x.com/a/status/124")]).send().await.unwrap();
            assert_eq!(status(&busy), 503);
            drop(permits);
            // The same function backs AppState.preview_rate_ok for generic previews.
            rates.clear();
            for _ in 0..29 {
                assert!(preview_rate_ok(&rates, "alice"));
            }
            assert_eq!(status(&client.get(&endpoint).bearer_auth(&token).query(&[("url", url)]).send().await.unwrap()), 200);
            let limited = client.get(&endpoint).bearer_auth(&token).query(&[("url", url)]).send().await.unwrap();
            assert_eq!(status(&limited), 429);
            assert!(limited.headers().contains_key("retry-after"));
            assert_eq!(limited.headers()["cache-control"], "private, no-store");
            // Admin Off: signing and redeeming both refuse (still no network).
            rates.clear();
            std::fs::write(fixture.path.join("admin_settings.json"), r#"{"link_preview_mode":"off"}"#).unwrap();
            assert_eq!(status(&sign(Some(&token), sign_body.clone()).await.unwrap()), 403);
            assert_eq!(status(&client.get(&media).send().await.unwrap()), 403);
            let body: serde_json::Value = serde_json::from_slice(
                &client.get(&config).bearer_auth(&token).send().await.unwrap().bytes().await.unwrap(),
            )
            .unwrap();
            assert_eq!(body["preview"], false);
        }
    }

    /// Route state for tests: an upstream that NEVER touches the network (it panics), so a
    /// test that reaches the CDN fetch by mistake fails loudly instead of resolving twimg.
    fn test_state(auth: Arc<AuthManager>, fixture: &preview::tweet_tests::Fixture, base: &str) -> TweetRouteState {
        struct NoNetwork;
        impl MediaUpstream for NoNetwork {
            fn fetch(&self, _: String, _: twitter::ProxyMediaKind, _: Option<String>) -> MediaFetchFuture {
                panic!("test reached the CDN fetch");
            }
        }
        TweetRouteState {
            auth,
            service: fixture.service.clone(),
            rates: Arc::new(DashMap::new()),
            base_path: base.to_string(),
            media_streams: Arc::new(Semaphore::new(MEDIA_PROXY_MAX_STREAMS)),
            media_accounts: Default::default(),
            media_upstream: Arc::new(NoNetwork),
            media_limits: MediaLimits::default(),
        }
    }

    /// A local, endless JPEG "CDN": counts fetches, never resolves or connects anywhere.
    struct EndlessUpstream(Arc<AtomicUsize>);
    impl MediaUpstream for EndlessUpstream {
        fn fetch(&self, _: String, _: twitter::ProxyMediaKind, _: Option<String>) -> MediaFetchFuture {
            self.0.fetch_add(1, Ordering::SeqCst);
            let body = futures_util::stream::repeat_with(|| Ok(axum::body::Bytes::from(vec![0u8; 16 * 1024])));
            Box::pin(async move {
                Ok(UpstreamMedia {
                    status: 200,
                    content_type: Some("image/jpeg".into()),
                    content_length: None,
                    content_range: None,
                    accept_ranges: Some("bytes".into()),
                    etag: None,
                    last_modified: None,
                    body: Box::pin(body),
                })
            })
        }
    }

    async fn media_server(
        limits: MediaLimits,
        streams: usize,
    ) -> (Server, SocketAddr, TweetRouteState, preview::tweet_tests::Fixture) {
        let fixture = preview::tweet_tests::Fixture::new();
        let auth = Arc::new(AuthManager::new(fixture.path.to_str().unwrap()).unwrap());
        let mut state = test_state(auth, &fixture, "");
        state.media_upstream = Arc::new(EndlessUpstream(Arc::new(AtomicUsize::new(0))));
        state.media_limits = limits;
        state.media_streams = Arc::new(Semaphore::new(streams));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = router(state.clone(), "");
        let server = Server(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        (server, address, state, fixture)
    }

    fn signed_media(address: SocketAddr, user: &str) -> String {
        let (_, path, _) = sign_media_path("", "https://pbs.twimg.com/media/synthetic.jpg?name=orig", &media_subject(user)).unwrap();
        format!("http://{address}{path}")
    }

    fn active_streams(state: &TweetRouteState) -> usize {
        state.media_accounts.lock().unwrap().values().sum()
    }

    /// Self-review fix (red before: the deadline/idle checks ran only when the client
    /// polled the body, so a client that stopped reading held the CDN connection, the
    /// global permit and its slot forever). The pump now owns them on its own timers.
    #[tokio::test]
    async fn media_stream_non_reading_client_releases_permit_at_deadline() {
        let limits = MediaLimits {
            headers: MEDIA_PROXY_HEADER_TIMEOUT,
            max_duration: std::time::Duration::from_millis(400),
            idle: std::time::Duration::from_secs(30), // only the deadline can end it
            per_account: 3,
        };
        let (_server, address, state, _fixture) = media_server(limits, 2).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        // Headers arrive, then the client never reads the body (the response is held).
        let held = client.get(signed_media(address, "alice")).send().await.unwrap();
        assert_eq!(held.status().as_u16(), 200);
        assert_eq!(held.headers()["content-type"], "image/jpeg");
        assert_eq!(held.headers()["x-content-type-options"], "nosniff");
        assert_eq!(held.headers()["cache-control"], "private, no-store", "audit fix: never cacheable");
        assert_eq!(state.media_streams.available_permits(), 1, "stream holds a global permit");
        assert_eq!(active_streams(&state), 1, "stream holds an account slot");
        tokio::time::sleep(std::time::Duration::from_millis(900)).await;
        assert_eq!(state.media_streams.available_permits(), 2, "permit released at the deadline");
        assert_eq!(active_streams(&state), 0, "account slot released at the deadline");
        drop(held);
        // A client that stops reading is also cut off after `idle`, long before the deadline.
        let limits = MediaLimits {
            headers: MEDIA_PROXY_HEADER_TIMEOUT,
            max_duration: std::time::Duration::from_secs(600),
            idle: std::time::Duration::from_millis(300),
            per_account: 3,
        };
        let (_server, address, state, _fixture) = media_server(limits, 2).await;
        let held = client.get(signed_media(address, "alice")).send().await.unwrap();
        assert_eq!(held.status().as_u16(), 200);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        assert_eq!(state.media_streams.available_permits(), 2, "stalled reader released after idle");
        drop(held);
    }

    /// Self-review fix (red before: no per-account bound — one account could take every
    /// global stream permit). Signatures are bound to the account; at most N streams each.
    #[tokio::test]
    async fn media_stream_per_account_cap_leaves_other_accounts_working() {
        let limits = MediaLimits {
            headers: MEDIA_PROXY_HEADER_TIMEOUT,
            max_duration: std::time::Duration::from_secs(600),
            idle: std::time::Duration::from_secs(600),
            per_account: 2,
        };
        let (_server, address, state, _fixture) = media_server(limits, 16).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let alice = signed_media(address, "alice");
        let mut held = Vec::new();
        for _ in 0..2 {
            let response = client.get(&alice).send().await.unwrap();
            assert_eq!(response.status().as_u16(), 200);
            held.push(response);
        }
        let third = client.get(&alice).send().await.unwrap();
        assert_eq!(third.status().as_u16(), 429, "N+1th concurrent stream for one account");
        assert!(third.headers().contains_key("retry-after"));
        let bob = client.get(signed_media(address, "bob")).send().await.unwrap();
        assert_eq!(bob.status().as_u16(), 200, "another account still streams");
        assert_eq!(active_streams(&state), 3);
        // Closing alice's streams (client gone) aborts their pumps and frees the slots.
        drop(held);
        drop(bob);
        for _ in 0..50 {
            if active_streams(&state) == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert_eq!(active_streams(&state), 0);
        assert_eq!(state.media_streams.available_permits(), 16);
        let again = client.get(&alice).send().await.unwrap();
        assert_eq!(again.status().as_u16(), 200);
    }

    /// Audit fix (MEDIUM): a stalled resolver / connect / header phase is bounded by one
    /// deadline and releases the account slot and the global permit. Red before: DNS ran
    /// outside every timeout while both were held.
    #[tokio::test]
    async fn media_fetch_stall_is_bounded_and_releases_slots() {
        struct Stalled;
        impl MediaUpstream for Stalled {
            fn fetch(&self, _: String, _: twitter::ProxyMediaKind, _: Option<String>) -> MediaFetchFuture {
                Box::pin(std::future::pending())
            }
        }
        let limits = MediaLimits {
            headers: std::time::Duration::from_millis(300),
            max_duration: std::time::Duration::from_secs(600),
            idle: std::time::Duration::from_secs(600),
            per_account: 3,
        };
        let (_server, address, mut state, _fixture) = media_server(limits, 2).await;
        state.media_upstream = Arc::new(Stalled);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stalled_address = listener.local_addr().unwrap();
        let app = router(state.clone(), "");
        let _stalled = Server(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let _ = address;
        let client = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(5)).build().unwrap();
        let started = std::time::Instant::now();
        let response = client.get(signed_media(stalled_address, "alice")).send().await.unwrap();
        assert_eq!(response.status().as_u16(), 504);
        assert!(started.elapsed() < std::time::Duration::from_secs(3));
        assert_eq!(state.media_streams.available_permits(), 2);
        assert_eq!(active_streams(&state), 0);
    }

    /// Re-check fix (LOW): html5ever's trace output (thread content) never reaches the logs,
    /// even with RUST_LOG=trace; the service's own events still do. Red before: fmt::init().
    #[test]
    fn log_filter_silences_tokenizer_content() {
        use tracing_subscriber::layer::SubscriberExt;
        #[derive(Clone, Default)]
        struct Buffer(Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(data);
                Ok(data.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        // Re-check 2: specific user directives must not win over the exclusion either.
        for env in [
            "trace",
            "html5ever::tokenizer=trace,markup5ever=trace,trace",
            "warn,html5ever::tokenizer=trace,markup5ever::interface[span]=trace,cryptirc=trace",
            "html5ever=trace , markup5ever=trace, cryptirc::preview=trace",
        ] {
            let buffer = Buffer::default();
            let writer = buffer.clone();
            let subscriber = tracing_subscriber::registry()
                .with(log_filter(Some(env)))
                .with(tracing_subscriber::fmt::layer().with_writer(move || writer.clone()).with_ansi(false));
            tracing::subscriber::with_default(subscriber, || {
                tracing::trace!(target: "html5ever::tokenizer", "processing in state Data: secret-thread-text");
                tracing::trace!(target: "markup5ever::interface", "secret-markup");
                tracing::trace!(target: "cryptirc::preview", "visible-service-event");
            });
            let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
            assert!(logged.contains("visible-service-event"), "{env}: {logged}");
            assert!(!logged.contains("secret-thread-text") && !logged.contains("secret-markup"), "{env}: {logged}");
        }
        // Unset/empty RUST_LOG keeps fmt::init()'s default (ERROR only).
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = tracing_subscriber::registry()
            .with(log_filter(Some("")))
            .with(tracing_subscriber::fmt::layer().with_writer(move || writer.clone()).with_ansi(false));
        tracing::subscriber::with_default(subscriber, || {
            tracing::warn!(target: "cryptirc", "a-warning");
            tracing::error!(target: "cryptirc", "an-error");
        });
        let logged = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        assert!(logged.contains("an-error") && !logged.contains("a-warning"), "{logged}");
    }

    #[test]
    fn route_tweet_error_contract_and_generic_compatibility() {
        for error in [
            twitter::PreviewError::InvalidUrl,
            twitter::PreviewError::Busy,
            twitter::PreviewError::Timeout,
            twitter::PreviewError::ProviderChanged,
            twitter::PreviewError::UpstreamFailure,
            twitter::PreviewError::RateLimited(30),
        ] {
            let response = tweet_error(error);
            assert_eq!(response.headers()["cache-control"], "private, no-store");
            assert_eq!(response.headers()["vary"], "Authorization");
        }
        assert_eq!(tweet_error(twitter::PreviewError::RateLimited(30)).headers()["retry-after"], "30");
        let preview = preview::LinkPreview {
            url: "https://example.org".into(),
            domain: "example.org".into(),
            title: None,
            description: None,
            image: None,
            site_name: None,
        };
        assert_eq!(serde_json::to_value(preview).unwrap().as_object().unwrap().len(), 6);
    }
}
