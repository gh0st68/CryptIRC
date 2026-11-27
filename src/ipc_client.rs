//! ipc_client.rs — the web process's side of the IPC boundary. Connects to the
//! irc-core daemon's Unix socket, sends `Attach` on every (re)connect, and
//! dispatches every inbound `IpcMessage` — routing `RawLine`s through
//! `irc::dispatch_line` exactly as the old `run_loop` did for bytes read
//! directly off a socket, translating `ConnStatus`/`SessionSync` into the
//! existing `ServerEvent`s the browser already understands.
//!
//! Web-process-only (not part of the shared lib — the daemon has no use for
//! any of this; it only needs `cryptirc::ipc`/`cryptirc::ipc_framing`, both
//! already shared).

use crate::{irc, AppState, NetworkConfig, SaslConfig, ServerEvent};
use cryptirc::ipc::{ClientIdentity, ConnLifecycle, DialParams, IpcMessage, SaslParams};
use cryptirc::ipc_framing::{read_frame, write_frame};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

/// codex P2 ipc_client.rs:294: a channel is re-burst (NAMES/WHO/MODE/TOPIC) at most
/// once per this window, however many SessionSyncs report it memberless.
const RESYNC_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(120);

/// r4 V3I-N1: how long after a reattach / re-dial a channel the daemon's first snapshot
/// did not list may still be (re)joined before the web forgets it (see
/// deferred_membership_check). Rejoin echoes normally arrive within seconds.
const RESYNC_GRACE: std::time::Duration = std::time::Duration::from_secs(45);

/// r4 V3I-N1: the deferred half of the replay-snapshot membership reconciliation (codex
/// P2 ipc_client.rs:302). After RESYNC_GRACE, each candidate channel that the daemon's
/// LATEST snapshot still does not list is dropped (sessions get the self-part) — only if
/// this is still the same connection entry, it stayed registered and connected throughout
/// (no Reconnecting/Disconnected: `resync_gen` unchanged) and the channel is still tracked.
/// A channel the daemon rejoined meanwhile appears in a later snapshot (the daemon sends
/// one on every self-JOIN) and is kept.
async fn deferred_membership_check(state: AppState, username: String, conn_id: String,
    conn: Arc<Mutex<irc::IrcConnection>>, candidates: Vec<String>, gen: u64) {
    tokio::time::sleep(RESYNC_GRACE).await;
    let same_entry = state.connections.get(&conn_id).map_or(false, |e| Arc::ptr_eq(e.value(), &conn));
    if !same_entry { return; }
    let mut c = conn.lock().await;
    if c.resync_gen != gen || !c.registered || !c.connected { return; }
    // r8 (codex P2 irc_daemon.rs:97): a snapshot that may have been cut by the daemon's size
    // budget is no proof that a channel missing from it was left.
    if cryptirc::irc_daemon::snapshot_may_be_truncated(&c.daemon_channels) { return; }
    let cm = c.casemapping;
    let in_snapshot: HashSet<String> = c.daemon_channels.iter().map(|ch| cm.fold(ch)).collect();
    for name in candidates {
        let key = cm.fold(&name);
        if in_snapshot.contains(&key) { continue; }
        if crate::irc::forget_channel_membership(&state, &username, &conn_id, &mut c, &key, "No longer joined (resynced with irc-core)") {
            info!("[{}] channel no longer joined per irc-core snapshot — dropped", conn_id);
        }
    }
}

/// r4 R1 (w3-irc, graceful irc-core restart): sessions irc-core stopped ON ITS OWN. Its
/// graceful shutdown (SIGTERM) Drops every connection ("Server shutting down"), which every
/// daemon version reports as `Disconnected { reason: "User requested" }` (an older one may
/// first send its ConnGuard's "connection task ended") — while this web had NOT asked for
/// that Drop — and then closes the IPC socket. Those sessions used to stay disconnected after
/// the restart (the web entry was removed, so the next Attach cycle never expected them
/// back). Now such a session is remembered; when the IPC link then drops within
/// DAEMON_STOP_LINK_WINDOW (the daemon went away: a shutdown, not a stray Drop), the next
/// Attach cycle re-dials it through the normal AttachComplete reconciliation (which keeps its
/// locked-vault, removed-network, other-owner and Auto-Reconnect=No rules) unless the user
/// disconnected it meanwhile. Value = when it stopped; a Dial or a user Drop clears an entry,
/// and entries expire after DAEMON_STOP_REDIAL_TTL.
fn daemon_stopped() -> &'static dashmap::DashMap<String, std::time::Instant> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, std::time::Instant>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}
const DAEMON_STOP_REDIAL_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const DAEMON_STOP_LINK_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
/// The ConnStatus reasons of a daemon-side stop on a Drop command: every irc_core version
/// ("User requested"), and an older one's ConnGuard notice, which can overtake it.
const DAEMON_DROP_REASONS: [&str; 2] = ["User requested", "connection task ended"];

/// Whether the irc-core on the CURRENT IPC link announced the `cm_keys` feature
/// (`ipc::DAEMON_FEATURES`): it then finds Dial-time channel keys by exact spelling +
/// the server's CASEMAPPING, so no rfc1459-folded key aliases are added to a Dial.
/// Reset on every (re)connect; an older daemon never sets it.
static DAEMON_CM_KEYS: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// r5 (codex P2 ipc_client.rs:293): whether the irc-core on the CURRENT link announced
/// `hold_ack` (it then honours IpcMessage::Held / Released — see irc::AckCtx).
static DAEMON_HOLD_ACK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Generation of the IPC link: LINK_GEN counts links; CURRENT_LINK is the live one, 0 while
/// no link is up (then every acknowledged held line belongs to an earlier link).
static LINK_GEN: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CURRENT_LINK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// The live link's sender, for release_held (called from sync code too).
static CURRENT_OUT: std::sync::Mutex<Option<mpsc::UnboundedSender<IpcMessage>>> = std::sync::Mutex::new(None);

/// The live IPC link's generation (0 = no link up).
pub(crate) fn current_link() -> u64 { CURRENT_LINK.load(std::sync::atomic::Ordering::Acquire) }

/// The link whose AttachComplete has been handled (its replay is over).
static ATTACHED_LINK: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// Avatars: the live link once its Attach replay is complete, else 0 — no avatar matching
/// while replayed lines may still be arriving (codex re-check H avatar.rs:1005).
pub(crate) fn attached_link() -> u64 { attached_link_of(current_link(), ATTACHED_LINK.load(std::sync::atomic::Ordering::Acquire)) }
pub(crate) fn attached_link_of(current: u64, attached: u64) -> u64 { if current != 0 && attached == current { current } else { 0 } }

/// r8 (codex P2 ipc_client.rs:339): tell a `hold_ack` daemon that this numbered line is held
/// (not durable yet) — sent by irc::log_line the moment the line is queued, so it always
/// precedes the Released a flush may send, and the reader's Processed (which parks it).
pub(crate) fn announce_held(link: u64, seq: u64) {
    if seq == 0 || link != current_link() || !DAEMON_HOLD_ACK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let guard = CURRENT_OUT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() { let _ = tx.send(IpcMessage::Held { seqs: vec![seq] }); }
}

/// r5: tell a `hold_ack` daemon that these held lines (link generation, seq) are now logged —
/// or discarded on purpose — so it counts them as delivered. Only the live link's seqs mean
/// anything to the daemon; others are skipped.
pub(crate) fn release_held(acks: &[(u64, u64)]) {
    let cur = current_link();
    if cur == 0 || !DAEMON_HOLD_ACK.load(std::sync::atomic::Ordering::Acquire) { return; }
    let seqs: Vec<u64> = acks.iter().filter(|(l, _)| *l == cur).map(|(_, s)| *s).collect();
    if seqs.is_empty() { return; }
    let guard = CURRENT_OUT.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(tx) = guard.as_ref() {
        for chunk in seqs.chunks(1000) { let _ = tx.send(IpcMessage::Released { seqs: chunk.to_vec() }); }
    }
}

/// codex P2 main.rs:6834 / agy P2: the endpoint each conn_id was last DIALED with by this
/// web process, recorded before the Dial is sent. A connection's E2E network identity
/// comes from what it really dials (this, or the daemon's SessionSync report), never from
/// the saved config, which UpdateNetwork can change while the connection runs.
fn dialed_endpoints() -> &'static dashmap::DashMap<String, (String, u16)> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, (String, u16)>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}

// r4 C2-6 (codex P2 ipc_client.rs:784): `dialed_endpoints` is also kept on disk, so a web
// restart under an OLDER irc_core — which cannot report the endpoint in SessionSync — still
// knows what each reattached session really dialed, instead of taking the saved config
// (which UpdateNetwork may have changed while the session ran) as its E2E network identity.
// Same data class as the network configs (server host + port, plaintext there too); 0600,
// written atomically. An entry is dropped when its session ends (Drop / terminal
// Disconnected), so the file only holds live sessions.

/// The data dir of this web process (set once, at `run`).
static DIAL_ENDPOINTS_DIR: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn dial_endpoints_file(data_dir: &str) -> String {
    format!("{}/irc-dial-endpoints.json", data_dir.trim_end_matches('/'))
}

/// Read a persisted endpoint map (missing / unreadable / malformed = empty; bounded).
async fn read_dial_endpoints(path: &str) -> HashMap<String, (String, u16)> {
    let Ok(j) = tokio::fs::read_to_string(path).await else { return HashMap::new() };
    match serde_json::from_str::<HashMap<String, (String, u16)>>(&j) {
        Ok(m) => m.into_iter()
            .filter(|(k, (h, _))| !k.is_empty() && k.len() <= 64 && !h.is_empty() && h.len() <= 255)
            .take(10_000).collect(),
        Err(_) => { warn!("ignoring a malformed {}", path); HashMap::new() }
    }
}

/// Write the endpoint map atomically (tmp file 0600, no symlink follow, then rename).
async fn write_dial_endpoints(path: &str, map: &HashMap<String, (String, u16)>) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let json = serde_json::to_vec(map).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let tmp = format!("{}.tmp", path);
    let mut f = tokio::fs::OpenOptions::new().write(true).create(true).truncate(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&tmp).await?;
    f.write_all(&json).await?;
    f.flush().await?;
    drop(f);
    tokio::fs::rename(&tmp, path).await
}

/// At startup: adopt the endpoints a previous web process recorded.
async fn load_dialed_endpoints(data_dir: &str) {
    let _ = DIAL_ENDPOINTS_DIR.set(data_dir.to_string());
    for (k, v) in read_dial_endpoints(&dial_endpoints_file(data_dir)).await {
        dialed_endpoints().entry(k).or_insert(v);
    }
}

/// Save the current endpoint map (background; serialized, newest state wins).
fn persist_dialed_endpoints() {
    let Some(dir) = DIAL_ENDPOINTS_DIR.get() else { return };
    let path = dial_endpoints_file(dir);
    tokio::spawn(async move {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        let _g = LOCK.lock().await;
        let map: HashMap<String, (String, u16)> = dialed_endpoints().iter().map(|e| (e.key().clone(), e.value().clone())).collect();
        if let Err(e) = write_dial_endpoints(&path, &map).await { warn!("could not save {}: {}", path, e); }
    });
}

/// This conn_id's session is gone: forget what it dialed.
fn forget_dialed_endpoint(conn_id: &str) {
    if dialed_endpoints().remove(conn_id).is_some() { persist_dialed_endpoints(); }
}

/// Run forever: connect to the daemon, and on any disconnect (daemon
/// restarted/crashed, or never came up yet) retry after a short fixed delay.
/// Unlike IRC-side reconnect this is a local socket — either the daemon is up
/// or it's not, so there's no need for the exponential backoff the daemon
/// itself uses against real network flakiness.
pub async fn run(sock_path: String, state: AppState) {
    load_dialed_endpoints(&state.data_dir).await;
    let mut peer_rejects: u64 = 0;
    loop {
        match UnixStream::connect(&sock_path).await {
            Ok(stream) => match daemon_peer_ok(&stream) {
                Ok(()) => {
                    peer_rejects = 0;
                    info!("Connected to irc-core daemon at {}", sock_path);
                    // v-srv-b NEW 2: the ghost backstop's proof that this data dir belongs
                    // to the daemon (see drop_ghost_sessions). Checked per connection,
                    // once the socket file certainly exists.
                    let colocated = socket_is_colocated(&sock_path, &state.data_dir);
                    if !colocated {
                        info!("irc-core socket {} is not this data dir's own irc-core.sock — the ownerless-session backstop is off", sock_path);
                    }
                    if let Err(e) = handle_connection(stream, &state, colocated).await {
                        warn!("irc-core IPC connection lost: {}", e);
                    }
                    // r4 R1: only sessions stopped right before the daemon went away count as
                    // stopped by its shutdown.
                    daemon_stopped().retain(|_, t| t.elapsed() < DAEMON_STOP_LINK_WINDOW);
                }
                Err(why) => {
                    // Never hand decrypted DialParams (passwords, SASL, client-key PEM) to
                    // whatever happens to listen at the socket path. Throttled log: this
                    // retries every second.
                    if peer_rejects % 60 == 0 {
                        warn!("refusing irc-core socket {}: {} — retrying", sock_path, why);
                    }
                    peer_rejects = peer_rejects.wrapping_add(1);
                }
            },
            Err(e) => {
                warn!("Could not connect to irc-core daemon at {} ({}) — retrying", sock_path, e);
            }
        }
        *state.ipc_out.lock().await = None;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// The daemon side already only accepts a peer with its own euid (SO_PEERCRED). Mirror
/// that here: only talk to a daemon running as OUR euid. Any working deployment already
/// satisfies this (the daemon would reject us otherwise), so this only bites a process
/// squatting on the socket path (e.g. CRYPTIRC_IPC_SOCK pointed at a shared directory).
fn daemon_peer_ok(stream: &UnixStream) -> Result<(), String> {
    let ours = unsafe { libc::geteuid() };
    match stream.peer_cred() {
        Ok(cred) if cred.uid() == ours => Ok(()),
        Ok(cred) => Err(format!("socket peer runs as uid {} (expected {})", cred.uid(), ours)),
        Err(e) => Err(format!("could not read socket peer credentials: {}", e)),
    }
}

/// True when `sock_path` is `<data_dir>/irc-core.sock` (after resolving symlinks): the
/// default layout, where irc_core was started on this same data dir. An explicit
/// CRYPTIRC_IPC_SOCK elsewhere (a second web on a copied/restored data dir pointed at the
/// live daemon) is not.
fn socket_is_colocated(sock_path: &str, data_dir: &str) -> bool {
    // Resolve the socket path itself, so a symlinked `irc-core.sock` pointing at some
    // other daemon's socket doesn't count.
    let (Ok(sock), Ok(dir)) = (std::fs::canonicalize(sock_path), std::fs::canonicalize(data_dir)) else { return false };
    sock.file_name().map_or(false, |n| n == "irc-core.sock") && sock.parent() == Some(dir.as_path())
}

async fn handle_connection(stream: UnixStream, state: &AppState, colocated: bool) -> anyhow::Result<()> {
    let (mut read_half, write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcMessage>();

    // Install this connection's sender as the one every IrcConnection::send_raw
    // (and the Dial/RawSend/Drop senders below) will use.
    DAEMON_CM_KEYS.store(false, std::sync::atomic::Ordering::Release);
    DAEMON_HOLD_ACK.store(false, std::sync::atomic::Ordering::Release);
    *state.ipc_out.lock().await = Some(out_tx.clone());
    // r5: a new link generation (held lines of earlier links are settled at AttachComplete).
    let link = LINK_GEN.fetch_add(1, std::sync::atomic::Ordering::AcqRel) + 1;
    CURRENT_LINK.store(link, std::sync::atomic::Ordering::Release);
    *CURRENT_OUT.lock().unwrap_or_else(|e| e.into_inner()) = Some(out_tx.clone());

    let mut write_half = write_half;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            // r4 C2-4: consecutive Processed acks already queued collapse into the newest.
            let (msg, next) = match msg {
                IpcMessage::Processed { mut upto } => {
                    let mut next = None;
                    while let Ok(m) = out_rx.try_recv() {
                        match m {
                            IpcMessage::Processed { upto: u } => upto = upto.max(u),
                            other => { next = Some(other); break; }
                        }
                    }
                    (IpcMessage::Processed { upto }, next)
                }
                other => (other, None),
            };
            if write_frame(&mut write_half, &msg).await.is_err() { break; }
            if let Some(m) = next {
                if write_frame(&mut write_half, &m).await.is_err() { break; }
            }
        }
    });

    // Snapshot of conn_ids we believe should be live BEFORE this Attach cycle —
    // compared against what the daemon actually reports once AttachComplete
    // arrives, so a conn_id we expected but the daemon doesn't have (e.g. the
    // daemon itself restarted) gets a fresh Dial. `seen` accumulates as
    // SessionSync arrives during the replay burst.
    let mut expected: HashSet<String> = state.connections.iter().map(|e| e.key().clone()).collect();
    // r4 R1: plus the sessions the previous irc-core stopped on its own (graceful restart).
    let now = std::time::Instant::now();
    daemon_stopped().retain(|_, t| now.duration_since(*t) < DAEMON_STOP_REDIAL_TTL);
    expected.extend(daemon_stopped().iter().map(|e| e.key().clone()));
    let mut seen: HashSet<String> = HashSet::new();
    crate::avatar::replay_cycle_start();
    // Re-cased (non-canonical id) sessions reported in this Attach cycle (see SessionSync).
    let mut noncanonical_seen: HashSet<String> = HashSet::new();

    // Announce our own compiled version/build every (re)connect — the daemon caches
    // this and prefers it for CTCP VERSION over its own (possibly stale, since it's
    // intentionally not restarted on a routine web-only redeploy) compiled-in
    // version. See `ipc::WebVersionCell` / `ipc::IpcMessage::Attach`.
    out_tx.send(IpcMessage::Attach {
        version: env!("CARGO_PKG_VERSION").to_string(),
        build: option_env!("CRYPTIRC_BUILD").unwrap_or("dev").to_string(),
        // r4: proc_ack (C2-4) + send_dropped (C1-9); an older daemon ignores the field.
        features: cryptirc::ipc::WEB_FEATURES.iter().map(|f| f.to_string()).collect(),
    }).ok();

    let result = loop {
        match read_frame(&mut read_half).await {
            Ok(Some(msg)) => {
                // r4 C2-4 (codex P2 ipc_server.rs:681): a numbered line is acknowledged only
                // AFTER it was handled (dispatched, and logged where it is logged), so the
                // daemon replays it as backlog if this process dies before that.
                // r5 (codex P2 ipc_client.rs:293): a line that was only HELD in memory (vault
                // locked) is reported as such first (Held), so a hold_ack daemon keeps it
                // undelivered until flush_held_logs releases it (see irc::AckCtx).
                // r8 (codex P2 ipc_client.rs:339): Held is sent by log_line itself when the line
                // is queued (announce_held), no longer here after dispatch — a flush running
                // meanwhile could have released it already, and a late Held parked it forever.
                let (ack, replay) = match &msg { IpcMessage::RawLine { seq, replayed, .. } => (*seq, *replayed), _ => (0, false) };
                if ack > 0 {
                    let ctx = irc::AckCtx { link, seq: ack, replay };
                    irc::ACK_CTX.scope(std::cell::Cell::new(ctx), async {
                        handle_message(msg, state, &expected, &mut seen, &mut noncanonical_seen, colocated, &out_tx).await;
                    }).await;
                    let _ = out_tx.send(IpcMessage::Processed { upto: ack });
                } else {
                    handle_message(msg, state, &expected, &mut seen, &mut noncanonical_seen, colocated, &out_tx).await;
                }
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(anyhow::Error::from(e)),
        }
    };
    writer_task.abort();
    // r5: no link is up now — held lines of this link wait for the next link's settlement.
    CURRENT_LINK.store(0, std::sync::atomic::Ordering::Release);
    *CURRENT_OUT.lock().unwrap_or_else(|e| e.into_inner()) = None;
    result
}

fn enabled_reaction_label(facts: &cryptirc::ipc::RegistrationFacts) -> Option<bool> {
    let offered = facts.caps.iter().any(|cap| cap.eq_ignore_ascii_case("labeled-response"));
    let enabled = facts.enabled_caps.iter().any(|cap| cap.eq_ignore_ascii_case("labeled-response"));
    // An older core omits enabled_caps altogether. Its empty default cannot
    // erase a live CAP LIST/ACK, but a known enabled list or DEL can.
    (enabled || !offered || !facts.enabled_caps.is_empty()).then_some(enabled)
}

/// Facts may reset the old session; the top-level mapping then corrects both the
/// facts fallback and live 005, as it did before registration facts were added.
pub(crate) fn apply_session_registration(c: &mut irc::IrcConnection, facts: Option<&cryptirc::ipc::RegistrationFacts>, casemapping: &str) -> bool {
    c.daemon_registration = facts.is_some();
    let replaced = facts.map_or(false, |f| crate::avatar::apply_registration_facts(c, f));
    if let Some(facts) = facts { c.keepnick_retry.learn_limit(&facts.isupport); }
    if let Some(facts) = facts.filter(|f| !f.truncated && f.cap_ls_done) {
        c.reactions.advertised = facts.caps.iter().any(|cap| cap == crate::reactions::CAP);
        c.reactions.dislike_advertised = facts.caps.iter().any(|cap| cap == crate::reactions::DISLIKE_CAP);
        if let Some(enabled) = enabled_reaction_label(facts) {
            let cap = if enabled { "labeled-response" } else { "-labeled-response" };
            crate::reactions::note_capabilities(c, "ACK", cap);
        }
    }
    // Choose once: temporarily applying a stale, wider facts mapping can merge
    // distinct channels before the authoritative mapping has a chance to correct it.
    let mapping = if !casemapping.is_empty() {
        Some(cryptirc::ircproto::CaseMapping::from_token(casemapping))
    } else {
        facts.filter(|f| !f.truncated).and_then(|f| cryptirc::ircproto::CaseMapping::from_isupport(&f.isupport))
    };
    if let Some(m) = mapping {
        c.note_server_casemapping(m);
        c.set_casemapping(m);
    }
    replaced
}

async fn handle_message(
    msg: IpcMessage,
    state: &AppState,
    expected: &HashSet<String>,
    seen: &mut HashSet<String>,
    noncanonical_seen: &mut HashSet<String>,
    colocated: bool,
    out_tx: &mpsc::UnboundedSender<IpcMessage>,
) {
    // r3 C2-1 (srv-b): a shared legacy id freshly claimed — nothing from the session it
    // replaced may reach the claimant (see crate::claim_and_dial). r4: bound to the
    // claiming account (needs `state` for conn_owners).
    if !crate::fresh_claim_admits(state, &msg) { return; }
    match msg {
        IpcMessage::RawLine { conn_id, line, replayed, backlog, recv_ts, .. } => {
            if let Some((_username, conn)) = ensure_connection_entry(state, &conn_id).await {
                if let Err(e) = irc::dispatch_line(state, &_username, &conn_id, &conn, &line, replayed, backlog, recv_ts).await {
                    warn!("[{}] dispatch_line error: {}", conn_id, e);
                }
            }
        }

        // The daemon has ENDED this conn_id (every daemon Disconnected is terminal: user
        // Drop, auto_reconnect=false after a server close/error, SASL_FATAL, or the task
        // dying). Handled without ensure_connection_entry so a duplicate/late
        // Disconnected (an older irc_core sends a second "connection task ended" one)
        // can't resurrect an entry we just removed.
        IpcMessage::ConnStatus { conn_id, state: ConnLifecycle::Disconnected { mut reason } } => {
            // The daemon ended this session: nothing to identify any more (r4 C2-6).
            forget_dialed_endpoint(&conn_id);
            state.avatars.forget_session(&conn_id);
            let Some(username) = state.conn_owners.get(&conn_id).map(|r| r.clone()) else { return };
            // r4 R1: a Drop this web did not send, on a session it had — irc-core's own
            // graceful shutdown. Expected back on the next Attach (see daemon_stopped).
            if DAEMON_DROP_REASONS.contains(&reason.as_str()) && !state.disconnect_requested(&conn_id)
                && !crate::user_disconnected(&conn_id)
                && (state.connections.contains_key(&conn_id) || daemon_stopped().contains_key(&conn_id))
            {
                daemon_stopped().entry(conn_id.clone()).or_insert_with(std::time::Instant::now);
                reason = "irc-core stopped (restarting?) — this network reconnects when it is back".into();
            }
            let conn = state.connections.get(&conn_id).map(|c| c.clone());
            if let Some(conn) = conn {
                let mut c = conn.lock().await;
                c.connected = false;
                // Without this, a daemon-internal reconnect (no re-Attach
                // involved) that re-registers leaves `registered` stuck
                // true from before the drop, so the SessionSync that
                // follows sees `registered && !c.registered` = false and
                // never re-fires ServerEvent::Connected — anything gated
                // on "just (re)connected" goes stale until a manual reload.
                c.registered = false;
                c.e2e_bridge = Default::default();
                c.reactions = Default::default();
                c.recent_encrypted_targets.clear();
                c.warn_pending_signal_deliveries(state, &username);
                c.clear_signal_deliveries();
                c.avx.reset();
                // Drop in-flight WHO bookkeeping: the socket that owed us a
                // 315 ENDOFWHO is gone, so those entries would never clear
                // and would suppress a genuine post-reconnect /who. The
                // reconnect's SessionSync re-seeds who_pending for the
                // channels it resyncs.
                c.who_pending.clear();
                c.resync_gen = c.resync_gen.wrapping_add(1);
                c.resync_busy = false;
            }
            if state.disconnect_requested(&conn_id) {
                state.abort_connect_task(&conn_id);
                state.connections.remove(&conn_id);
                state.conn_owners.remove(&conn_id);
                state.clear_disconnect_request(&conn_id);
            } else {
                // Not requested: the daemon stopped on its own and no longer owns this
                // conn_id. Drop the web entry (conn_owners stays — the network is still
                // the user's) so Connect / reconnect_for_user, which both short-circuit
                // on `connections.contains_key`, can dial it again. Keeping it made
                // Connect a silent no-op until the web process restarted.
                state.connections.remove(&conn_id);
            }
            state.send_to_user(&username, ServerEvent::Disconnected { conn_id: conn_id.clone(), reason });
        }

        IpcMessage::ConnStatus { conn_id, state: lifecycle } => {
            // ensure_connection_entry (not just a conn_owners lookup) so a
            // brand-new Dial's very first message — always this one — has
            // somewhere to read `cfg.server` from for display.
            if let Some((username, conn)) = ensure_connection_entry(state, &conn_id).await {
                // A new IRC session starts: the old one's avatar classification no longer applies.
                state.avatars.forget_session(&conn_id);
                let evt = match lifecycle {
                    ConnLifecycle::Connecting => {
                        let mut c = conn.lock().await;
                        c.warn_pending_signal_deliveries(state, &username);
                        c.reset_irc_session();
                        state.avatar_remote.forget_conn(&conn_id);
                        let server = c.dial_endpoint.as_ref().map_or_else(|| c.cfg.server.clone(), |(s, _)| s.clone());
                        ServerEvent::Connecting { conn_id: conn_id.clone(), server }
                    }
                    // Handled by the dedicated arm above.
                    ConnLifecycle::Disconnected { .. } => return,
                    ConnLifecycle::Reconnecting { attempt, delay_secs, reason } => {
                        let mut c = conn.lock().await;
                        c.warn_pending_signal_deliveries(state, &username);
                        c.reset_irc_session();
                        state.avatar_remote.forget_conn(&conn_id);
                        ServerEvent::Reconnecting { conn_id: conn_id.clone(), attempt, delay_secs, reason }
                    }
                };
                state.send_to_user(&username, evt);
            }
        }

        IpcMessage::SessionSync { conn_id, nick, channels, registered, connected, lag_ms, message_tags, echo_message_enabled, self_userhost, casemapping, dial_server, dial_port, chanmodes, registration } => {
            // F2 (rust-ws2) cleanup: a live daemon session whose conn_id is a RE-CASED
            // spelling of a network UUID is a duplicate minted through the old
            // ownership bypass (the server only ever generates lower-case ids). The web
            // never routes it (conn_owners is keyed canonically), so without this it
            // stays online, invisible, until irc_core restarts. Drop it on sight.
            //
            // v-irc I1: but it may be that network's ONLY session (an old web dialled the
            // re-cased id), and dropping it on sight left the user offline until they
            // unlocked and the canonical id was dialled. So the decision waits for
            // AttachComplete (settle_noncanonical_sessions): a true duplicate is dropped
            // then; an only session is kept until its canonical id is dialled.
            if crate::is_noncanonical_network_id(&conn_id) {
                // An alias is re-validated every time it is consulted: once its network is
                // gone / disconnected the session is dropped (see alias_still_wanted).
                let canon = conn_id.to_ascii_lowercase();
                if noncanon_alias().get(&canon).map_or(false, |a| a.value() == &conn_id) {
                    // Still reported → settled again at this cycle's AttachComplete.
                    if alias_still_wanted(state, &canon).await { noncanonical_seen.insert(conn_id.clone()); return; }
                    noncanon_alias().remove(&canon);
                    warn!("[{}] re-cased alias session is no longer wanted (network gone or disconnected) — sending Drop", conn_id);
                    let _ = out_tx.send(IpcMessage::Drop { conn_id: conn_id.clone(), reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
                    return;
                }
                noncanonical_seen.insert(conn_id.clone());
                return;
            }
            // The first snapshot of this conn in this Attach cycle is the daemon's replay of
            // its CURRENT state (see below: membership reconciliation).
            let first_in_cycle = seen.insert(conn_id.clone());
            if let Some((username, conn)) = ensure_connection_entry(state, &conn_id).await {
                let mut resync: Vec<String> = Vec::new();
                let resync_gen: u64;
                let mut newly_registered = None;
                let mut deferred_stale: Option<Vec<String>> = None;
                let reaction_change;
                {
                    let mut c = conn.lock().await;
                    let reaction_previous = crate::reactions::support(&c);
                    // Preserve the legacy registered→unregistered metadata reset,
                    // before merging the incoming session's retained facts.
                    if c.registered && !registered { c.avx.reset(); }
                    // Detect replacement before adopting any fields from this snapshot.
                    // Saved restrictions and subscription hints belong to the old epoch too.
                    if apply_session_registration(&mut c, registration.as_ref(), &casemapping) {
                        state.avatars.forget_session(&conn_id);
                        state.avatar_remote.forget_conn(&conn_id);
                    }
                    // The endpoint the daemon really dials (an r3+ irc_core reports it).
                    let reports_endpoint = !dial_server.is_empty();
                    if reports_endpoint {
                        c.dial_endpoint = Some((dial_server.clone(), dial_port));
                        // r4 C2-6: keep the persisted record what the daemon says.
                        let ep = (dial_server.clone(), dial_port);
                        if dialed_endpoints().get(&conn_id).map_or(true, |e| *e.value() != ep) {
                            dialed_endpoints().insert(conn_id.clone(), ep);
                            persist_dialed_endpoints();
                        }
                    }
                    // agy P2 #30 bypass: an irc_core that does not report its endpoint is
                    // one without the self-NICK spoof guard, which also sends a nick change
                    // as a snapshot BEFORE the NICK line. Adopting that nick would bypass
                    // the guard in the NICK handler (irc.rs), so while registration is
                    // steady its nick drift is left to the NICK line itself. The nick is
                    // still adopted on registration (001) and from a reattach's replay
                    // snapshot (a NICK line may have aged out of the ring meanwhile).
                    let adopt_identity = reports_endpoint || !registered || !c.registered || first_in_cycle;
                    if adopt_identity {
                        if c.nick != nick { c.keepnick_retry.clear_pending(); }
                        c.nick = nick.clone();
                    }
                    // r8 (codex P2 ipc_client.rs:1101): the server's CHANMODES / PREFIX as the
                    // daemon learned them (a re-Attached web has no 005 line of its own once it
                    // aged out of the ring).
                    if let Some(t) = &chanmodes {
                        let tokens: Vec<String> = t.split(' ').map(str::to_string).collect();
                        c.chanmodes.learn(&tokens);
                    }
                    // SessionSync alone owns registered/Connected. Live 001 records
                    // epoch adoption evidence, but leaves these flags to the snapshot
                    // even when coalescing delays it. Only fire Connected on false→true.
                    if registered && !c.registered {
                        let server = c.dial_endpoint.as_ref().map_or_else(|| c.cfg.server.clone(), |(s, _)| s.clone());
                        newly_registered = Some((c.nick.clone(), server));
                    }
                    c.registered = registered;
                    c.connected = connected;
                    // Avatars: this connection's state is fresh on the current link.
                    c.synced_link = current_link();
                    if lag_ms.is_some() { c.lag_ms = lag_ms; }
                    // Restores self-echo suppression / TAGMSG support after a
                    // re-Attach (fresh IrcConnection defaults both false) —
                    // see the SessionSync field doc comment for why this can't
                    // be re-derived by reparsing a forwarded RawLine alone.
                    c.message_tags = message_tags;
                    c.echo_message_enabled = echo_message_enabled;
                    // Re-arm the forged-NICK spoof guard (#30) after a re-Attach: a
                    // fresh IrcConnection starts with an empty self_userhost and would
                    // otherwise never learn it (no self-JOIN fires on reattach). Only
                    // adopt a non-empty value so an old daemon (sends "") can't wipe a
                    // userhost the web side already learned by reparsing.
                    // r4 V3I-N4 (w3-irc LOW): and, like the nick, from an irc_core that does
                    // not report its endpoint (no spoof guard; snapshot sent BEFORE the line)
                    // only on registration / the reattach replay: its steady-state snapshot
                    // after a forged bare `:me CHGHOST evil h` carried `evil@h`, which then let
                    // a forged `:me!evil@x NICK victim` pass the web's ident check. A genuine
                    // change still arrives as the CHGHOST / self-JOIN line, which irc.rs
                    // adopts under its own guard.
                    if !self_userhost.is_empty() && adopt_identity {
                        c.self_userhost = self_userhost.clone();
                    }
                    // The Attach replay's own nick view starts at the snapshot (IrcConnection::
                    // replay_view; recognises our own replayed lines only) and ends at AttachComplete. Starting
                    // at the CURRENT nick is a known, accepted residual inherited from 069f376
                    // (see the field's doc).
                    if first_in_cycle {
                        c.replay_view = Some((c.nick.clone(), c.self_userhost.clone()));
                    }
                    // Rebuild any channel the daemon says we're in but this
                    // (freshly (re)hydrated) web process doesn't have yet —
                    // insert a stub and queue a NAMES/TOPIC resync for it. This
                    // is the "rebuild display state via an ordinary resync
                    // burst" mechanism: no channel-state protocol of its own,
                    // just the same commands a manual /names would send.
                    if let Some(facts) = &registration {
                        let (host, port) = c.dial_endpoint.clone().unwrap_or_else(|| (c.cfg.server.clone(), c.cfg.port));
                        // Saved bouncer evidence may restrict facts, never loosen them.
                        if let Some(record) = state.avatars.session(&conn_id).filter(|r|
                            r.owner == username && r.host == crate::avatar::canonical_host(&host) && r.port == port) {
                            c.behind_bouncer |= record.bouncer;
                        }
                        crate::avatar::request_registration_metadata(&mut c).await;
                        if c.cap_ls_done {
                            state.avatars.refresh_session(&conn_id, &username, (&host, port), c.behind_bouncer, &state.conn_owners);
                        } else {
                            state.avatars.forget_session(&conn_id);
                        }
                        if !facts.truncated && !c.avx.meta2_on {
                            state.avatars.set_session_meta2(&conn_id, false);
                        }
                    }
                    // codex P2 ipc_client.rs:302: the replay snapshot is authoritative for
                    // membership. A channel this web still tracks but the daemon says we
                    // are not in — a KICK/PART during an IPC outage that aged out of the
                    // ring, or a rejoin refused while the link was down — is dropped (and
                    // the sessions told), instead of showing it joined with stale members
                    // forever. Only for the replay of a connection this web already had,
                    // only while the daemon reports it registered, and only for names the
                    // daemon tracks at all (it never tracks e.g. `#a\b`, see
                    // is_trackable_channel). Live snapshots are not used for this: one taken
                    // mid-rejoin (right after 001) is legitimately partial.
                    //
                    // r4 V3I-N1 (w3-irc MED): NOT at once. That snapshot can be one taken
                    // mid-rejoin: the first snapshot of a connection AttachComplete re-dialed
                    // after an irc-core crash/restart is the 001 one (no channel rejoined
                    // yet), and a replayed one can be too (the daemon reconnected to IRC just
                    // before this Attach). Dropping there sent a self-PART for EVERY channel
                    // (app.js then drops them from Favourites on all devices; the TUI closes
                    // every window). So the channels missing from it are only candidates: they
                    // are dropped RESYNC_GRACE later if the daemon's LATEST snapshot still
                    // does not list them and the connection stayed up (deferred_membership_check).
                    c.daemon_channels = channels.clone();
                    if first_in_cycle && expected.contains(&conn_id) && registered && connected
                        && !cryptirc::irc_daemon::snapshot_may_be_truncated(&channels)
                    {
                        let in_snapshot: HashSet<String> = channels.iter().map(|ch| c.casemapping.fold(ch)).collect();
                        let stale: Vec<String> = c.channels.iter()
                            .filter(|(k, ch)| !in_snapshot.contains(*k) && cryptirc::irc_daemon::is_trackable_channel(&ch.name))
                            .map(|(_, ch)| ch.name.clone()).collect();
                        if !stale.is_empty() { deferred_stale = Some(stale); }
                    }
                    let now = std::time::Instant::now();
                    c.resync_recent.retain(|_, t| now.duration_since(*t) < RESYNC_COOLDOWN);
                    for chan in &channels {
                        let key = c.casemapping.fold(chan);
                        let need_resync = match c.channels.get(&key) {
                            None => {
                                // Same cap as the self-JOIN path (#43): a snapshot can't grow
                                // the tracked set past it either.
                                if c.channels.len() >= crate::irc::MAX_CHANNELS_PER_CONN { continue; }
                                c.channels.insert(key.clone(), crate::irc::ChannelState {
                                    name: chan.clone(), topic: String::new(), names: vec![], key: None,
                                });
                                true
                            }
                            // Tracked but memberless — a ring-replayed JOIN recreated the
                            // stub, or a prior resync's NAMES reply was lost. Refresh it so
                            // the user list isn't left permanently empty.
                            Some(ch) if ch.names.is_empty() => true,
                            Some(_) => false,
                        };
                        // codex P2 :294: only when no resync job is running for this
                        // connection and the channel wasn't scheduled recently. A channel
                        // left out now is picked up by a later SessionSync (heartbeat).
                        // r6 (agy P2 ipc_client.rs:610): only for a session that is up — a
                        // snapshot of an ENDED (or not yet registered) one, e.g. an ended
                        // connection's replay, would send NAMES/WHO/MODE/TOPIC to nothing.
                        if need_resync && registered && connected && !c.resync_busy && !c.resync_recent.contains_key(&key) {
                            resync.push(chan.clone());
                            c.resync_recent.insert(key.clone(), now);
                            // Seed who_pending so the resync WHO reply is consumed silently
                            // (not dumped to the status buffer), bounded exactly like the
                            // self-JOIN path so a hostile server can't grow it without limit.
                            if c.who_pending.len() < crate::irc::NAMES_BUF_MAX_CHANNELS
                                || c.who_pending.contains(&key)
                            {
                                c.who_pending.insert(key);
                            }
                        }
                    }
                    if !resync.is_empty() { c.resync_busy = true; }
                    resync_gen = c.resync_gen;
                    let support = crate::reactions::support(&c);
                    reaction_change = (reaction_previous != support).then_some(support);
                    if first_in_cycle && support.0
                        && registration.as_ref().map_or(true, |f| f.truncated || f.enabled_caps.is_empty())
                    {
                        // Ask once per attachment when the retained facts cannot
                        // establish which capabilities the IRC connection enabled.
                        let _ = c.send_raw("CAP LIST").await;
                    }
                }
                // SyncSlot may move the enabling snapshot past its live ACK. Either
                // arrival initializes once. Attach waits for continuity/record checks so
                // an existing subscription only needs the legacy SET at AttachComplete.
                if attached_link() != 0 {
                    crate::avatar::remote::ensure_meta2_initialized(state, &username, &conn).await;
                }
                if let Some(stale) = deferred_stale {
                    tokio::spawn(deferred_membership_check(state.clone(), username.clone(), conn_id.clone(), conn.clone(), stale, resync_gen));
                }
                if let Some((connected_nick, server)) = newly_registered {
                    state.send_to_user(&username, ServerEvent::Connected {
                        conn_id: conn_id.clone(), server, nick: connected_nick,
                    });
                }
                if let Some((enabled, dislike)) = reaction_change {
                    state.send_to_user(&username, ServerEvent::ReactionSupport { conn_id: conn_id.clone(), enabled, dislike });
                }
                if let Some(ms) = lag_ms {
                    state.send_to_user(&username, ServerEvent::LagUpdate { conn_id: conn_id.clone(), ms });
                }
                // Rebuild member lists + topics WITHOUT flooding the server. The old code
                // sent NAMES+TOPIC for EVERY channel in one tight loop; on a reattach with
                // many channels (a routine cryptirc.service restart) that 2xN-command burst
                // tripped the IRC server's flood protection, which dropped/deferred the
                // excess so SOME channels never got their NAMES reply and were left with an
                // empty user list. Pace it in a background task — NAMES first (the visible
                // member list), TOPICs after — one command per tick so the server answers
                // every one. The task holds a clone of `conn`; if the connection drops
                // meanwhile, send_raw just errors harmlessly.
                if !resync.is_empty() {
                    let conn2 = conn.clone();
                    tokio::spawn(async move {
                        // NAMES first (the visible member list), then WHO (away/account
                        // state the nick panel shows), then channel MODE (+ key, feeds the
                        // modes dialog), then TOPIC. All paced one-per-tick so a many-channel
                        // reattach never trips server flood protection. WHO replies are
                        // consumed silently — who_pending was seeded for each `resync`
                        // channel in the locked block above, matching the self-JOIN path.
                        // Stops early once the connection dropped (generation changed).
                        'job: for verb in ["NAMES", "WHO", "MODE", "TOPIC"] {
                            for chan in &resync {
                                {
                                    let mut c = conn2.lock().await;
                                    if c.resync_gen != resync_gen { break 'job; }
                                    let _ = c.send_raw(&format!("{} {}\r\n", verb, chan)).await;
                                }
                                tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                            }
                        }
                        let mut c = conn2.lock().await;
                        if c.resync_gen == resync_gen { c.resync_busy = false; }
                    });
                }
            }
        }

        IpcMessage::AttachComplete {} => {
            // Avatars: sessions irc-core kept get their recorded classification back when the
            // replay proves it is the same session (avatar::restore_after_attach).
            crate::avatar::restore_after_attach(state, seen).await;
            ATTACHED_LINK.store(current_link(), std::sync::atomic::Ordering::Release);
            // r4 R1: this cycle handles them (re-dial below, or the daemon kept them).
            for id in expected { daemon_stopped().remove(id); }
            // Reconciliation: anything we expected before this Attach cycle
            // that the daemon never reported (it restarted and lost its live
            // sockets, or this is a genuinely stale entry) gets re-Dialed —
            // reusing the exact decrypt-and-resolve path a normal Connect uses.
            for conn_id in expected.difference(seen) {
                if state.disconnect_requested(conn_id) || crate::user_disconnected(conn_id) { continue; }
                let Some(username) = state.conn_owners.get(conn_id).map(|r| r.clone()) else { continue };
                // codex P2 ipc_client.rs:347: serialise with Connect / Disconnect /
                // RemoveNetwork / account purge (the same per-config lock) and RE-CHECK
                // everything inside it. Without the lock, a RemoveNetwork from another tab
                // could delete the config + send its Drop between our read and our Dial,
                // and the stale Dial then brought back a credential-bearing session nobody
                // owned any more.
                let cfg_lock = crate::network_config_lock(&username, conn_id);
                let _cfg_guard = cfg_lock.lock().await;
                if state.disconnect_requested(conn_id) { continue; }
                if state.conn_owners.get(conn_id).map_or(true, |o| o.as_str() != username) { continue; }
                // I2: with a LOCKED vault, get_network_config returns secrets still
                // `enc:`-prefixed; re-dialing now would connect UNAUTHENTICATED (and, absent
                // the build_dial_params guard, leak ciphertext). Drop the now-dead entry
                // (the daemon no longer owns it) and defer — reconnect_for_user re-dials on
                // the next vault unlock (it re-seeds conn_owners + dials conns not already
                // live). Leaving it in `connections` would BOTH falsely show it connected
                // AND make reconnect_for_user skip it (its contains_key guard) → stranded.
                if !state.crypto.is_unlocked(&username).await {
                    // r3 WS-6: the next unlock reconnects this network whatever its
                    // Auto-Reconnect setting (integrator decision in 0d3570d: the setting
                    // governs reconnect-after-drop; reconnect_for_user dials every network
                    // the user did not explicitly Disconnect) — one message for both.
                    state.connections.remove(conn_id);
                    state.send_to_user(&username, ServerEvent::Disconnected {
                        conn_id: conn_id.clone(),
                        reason: "Daemon restarted — unlock the vault to reconnect".into(),
                    });
                    continue;
                }
                let Some(cfg) = state.get_network_config(conn_id, &username).await else {
                    // The config is gone (removed meanwhile): nothing to re-dial.
                    state.connections.remove(conn_id);
                    continue;
                };
                // I5: respect an intentional auto_reconnect=false — the daemon may have
                // cleanly stopped this conn; reconciliation must not revive a connection the
                // user configured not to auto-reconnect.
                if !cfg.auto_reconnect {
                    state.connections.remove(conn_id);
                    // agy P2 ipc_client.rs:428: tell the sessions — they still showed it
                    // connected (the locked-vault branch above always did this).
                    state.send_to_user(&username, ServerEvent::Disconnected {
                        conn_id: conn_id.clone(),
                        reason: "Daemon restarted — press Connect to reconnect".into(),
                    });
                    continue;
                }
                info!("[{}] missing from daemon's Attach reply — re-dialing", conn_id);
                dial(state, &username, cfg, out_tx).await;
            }
            let pending_disconnects: Vec<String> = state.disconnect_requests.iter().map(|e| e.key().clone()).collect();
            for conn_id in pending_disconnects {
                if !state.connections.contains_key(&conn_id) {
                    state.clear_disconnect_request(&conn_id);
                    continue;
                }
                let owner = state.conn_owners.get(&conn_id).map(|r| r.clone());
                // C1: if the daemon did NOT report this conn_id in the Attach we just
                // finished, it restarted / lost the socket — there is no live connection to
                // QUIT. Sending a Drop the daemon can't act on yields no Disconnected echo,
                // so the entry would be STRANDED forever in connections/conn_owners/
                // disconnect_requests (Connect + reconnect_for_user both short-circuit on
                // it, the owner-gated pruner won't reap it, and the UI shows it falsely
                // connected). The user asked to disconnect and the socket is already gone —
                // satisfy the disconnect locally instead. Mirrors loop 1's seen-reconcile.
                if !seen.contains(&conn_id) {
                    state.abort_connect_task(&conn_id);
                    state.connections.remove(&conn_id);
                    state.conn_owners.remove(&conn_id);
                    state.clear_disconnect_request(&conn_id);
                    state.clear_pending_dial(&conn_id);
                    if let Some(u) = owner {
                        state.send_to_user(&u, ServerEvent::Disconnected { conn_id: conn_id.clone(), reason: "Disconnected".into() });
                    }
                    continue;
                }
                let Some(username) = owner else { continue };
                let reason = state
                    .get_network_config(&conn_id, &username)
                    .await
                    .map(|cfg| crate::quit_reason_for(&cfg).to_string())
                    .unwrap_or_else(|| crate::DEFAULT_QUIT_MESSAGE.to_string());
                let _ = out_tx.send(IpcMessage::Drop { conn_id: conn_id.clone(), reason: crate::strip_crlf(&reason) });
            }
            // r5 (srv-b, codex P2 main.rs:8428): a fresh claim whose Connecting never reached
            // this process can't be recovered from the replay — dial it again.
            crate::redial_quarantined_claims(state, out_tx).await;
            let pending_dials: Vec<String> = state.pending_dials.iter().map(|e| e.key().clone()).collect();
            for conn_id in pending_dials {
                // A Disconnect/RemoveNetwork that landed after this dial was queued
                // wins — otherwise a Connect/Disconnect race while IPC was down
                // could re-dial a network the user just asked to drop. Mirrors the
                // same guard the reconciliation loop above already has.
                if state.disconnect_requested(&conn_id) {
                    state.clear_pending_dial(&conn_id);
                    continue;
                }
                if state.connections.contains_key(&conn_id) {
                    state.clear_pending_dial(&conn_id);
                    continue;
                }
                let Some(username) = state.conn_owners.get(&conn_id).map(|r| r.clone()) else {
                    state.clear_pending_dial(&conn_id);
                    continue;
                };
                // Same lock + re-check as the reconciliation loop above (codex P2 :410).
                let cfg_lock = crate::network_config_lock(&username, &conn_id);
                let _cfg_guard = cfg_lock.lock().await;
                if !state.pending_dials.contains(&conn_id) || state.disconnect_requested(&conn_id)
                    || state.connections.contains_key(&conn_id)
                    || state.conn_owners.get(&conn_id).map_or(true, |o| o.as_str() != username) {
                    state.clear_pending_dial(&conn_id);
                    continue;
                }
                let Some(cfg) = state.get_network_config(&conn_id, &username).await else {
                    state.clear_pending_dial(&conn_id);
                    continue;
                };
                state.clear_pending_dial(&conn_id);
                // r3 A2-3 (srv-b): the vault was locked while this dial waited for the
                // daemon — dialing now would connect without the encrypted credentials and
                // then make reconnect_for_user skip it. Defer to the next unlock instead.
                if state.dial_deferred_for_locked_vault(&username, &cfg).await {
                    state.send_to_user(&username, ServerEvent::Disconnected {
                        conn_id: conn_id.clone(),
                        reason: crate::VAULT_LOCKED_CONNECT_REASON.into(),
                    });
                    continue;
                }
                dial(state, &username, cfg, out_tx).await;
            }
            let mut ghost_candidates = seen.clone();
            settle_noncanonical_sessions(state, seen, noncanonical_seen, &mut ghost_candidates, out_tx).await;
            drop_ghost_sessions(state, &ghost_candidates, colocated, out_tx).await;
            // r5: held lines of earlier links the replay did not bring back (see irc::AckCtx).
            crate::irc::settle_stale_held(state).await;
        }

        // Daemon → web version handshake. Logged so a mismatch between a frozen
        // daemon and a newer web binary is visible in the journal; behavior stays
        // additive/tolerant either way (see the ipc.rs SCHEMA LAW comment).
        IpcMessage::Hello { proto_version, features } => {
            DAEMON_CM_KEYS.store(features.iter().any(|f| f == "cm_keys"), std::sync::atomic::Ordering::Release);
            DAEMON_HOLD_ACK.store(features.iter().any(|f| f == "hold_ack"), std::sync::atomic::Ordering::Release);
            if proto_version != cryptirc::ipc::IPC_PROTO_VERSION {
                warn!("daemon IPC proto v{} != web v{} — running in compatibility mode", proto_version, cryptirc::ipc::IPC_PROTO_VERSION);
            } else {
                info!("daemon IPC proto v{} negotiated", proto_version);
            }
        }

        // r4 (codex P1 main.rs:5882): irc-core dropped an outgoing line of ours AFTER this
        // process had handed it over (and echoed it as sent): send queue full while the
        // IRC socket is stalled, over the tag limit, or no such session. Tell the user.
        IpcMessage::SendDropped { conn_id, reason } => {
            let Some(username) = state.conn_owners.get(&conn_id).map(|r| r.clone()) else { return };
            let reason: String = crate::strip_crlf(&reason).chars().filter(|c| !c.is_control()).take(200).collect();
            state.send_to_user(&username, ServerEvent::IrcMessage {
                replayed: false, conn_id, from: "*".into(), target: "status".into(),
                text: format!("⚠ irc-core did not send an outgoing line on this network ({}) — a message you just sent may not have reached IRC.", reason),
                ts: chrono::Utc::now().timestamp(), kind: crate::MessageKind::Notice, msg_id: 0, prefix: None,
            });
        }

        // Web → daemon variants; the client never receives its own outbound
        // messages. `DaemonControl` is web-originated too. `Unknown` is the
        // forward-compat catch-all for a variant a future peer added — ignore
        // rather than ever tear the connection down over it.
        IpcMessage::Attach { .. } | IpcMessage::Dial { .. } | IpcMessage::RawSend { .. }
        | IpcMessage::Drop { .. } | IpcMessage::DaemonControl { .. } | IpcMessage::Processed { .. }
        | IpcMessage::Held { .. } | IpcMessage::Released { .. } | IpcMessage::Unknown => {}
    }
}

/// v-irc I1: re-cased-id sessions kept alive because they are their network's only
/// session — canonical id → the live re-cased id. Dropped the moment the canonical id is
/// dialled (`dial`) or the network is disconnected / removed (`send_drop`).
static NONCANON_ALIAS: std::sync::OnceLock<dashmap::DashMap<String, String>> = std::sync::OnceLock::new();
fn noncanon_alias() -> &'static dashmap::DashMap<String, String> {
    NONCANON_ALIAS.get_or_init(dashmap::DashMap::new)
}
/// Alias sessions whose network was disconnected / removed while the IPC link was down
/// (send_drop could not reach the daemon): dropped on the next Attach if still reported.
fn alias_drops_pending() -> &'static dashmap::DashMap<String, ()> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, ()>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}

/// An alias may live on only while its canonical network still has an owner, a config
/// on disk, and was neither disconnected by the user nor has a disconnect pending.
async fn alias_still_wanted(state: &AppState, canon: &str) -> bool {
    let Some(owner) = state.conn_owners.get(canon).map(|r| r.clone()) else { return false };
    if state.disconnect_requested(canon) || crate::user_disconnected(canon) { return false; }
    state.get_network_config(canon, &owner).await.is_some()
}

/// AttachComplete: decide every re-cased session reported in this cycle.
///  - The canonical id is live too (reported, live web entry, or a dial pending): a
///    duplicate minted through the old ownership bypass → Drop it (the F2 cleanup).
///  - The canonical network has an owner: keep the session (the user stays on IRC) as an
///    alias until the canonical id is dialled — right now when the owner's vault is
///    unlocked (and Auto-Reconnect is on, and they didn't disconnect it), otherwise on
///    their unlock (reconnect_for_user) or Connect. `dial` drops the alias first.
///  - No owner: hand it to the ghost backstop's conservative rules.
async fn settle_noncanonical_sessions(
    state: &AppState, seen: &HashSet<String>, noncanonical: &mut HashSet<String>,
    ghost_candidates: &mut HashSet<String>, out_tx: &mpsc::UnboundedSender<IpcMessage>,
) {
    // Re-validate every existing alias (the daemon may no longer hold it, or its network
    // may have been removed / disconnected — possibly while the IPC link was down, when
    // send_drop could only forget the entry).
    // Drops that were requested while the link was down.
    let pending: Vec<String> = alias_drops_pending().iter().map(|e| e.key().clone()).collect();
    for alias in pending {
        alias_drops_pending().remove(&alias);
        if noncanonical.remove(&alias) {
            warn!("[{}] re-cased session of a network disconnected/removed while irc-core was unreachable — sending Drop", alias);
            let _ = out_tx.send(IpcMessage::Drop { conn_id: alias, reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
        }
    }
    let aliases: Vec<(String, String)> = noncanon_alias().iter().map(|e| (e.key().clone(), e.value().clone())).collect();
    for (canon, alias) in aliases {
        // The daemon no longer reports it (it restarted / the session ended): forget it.
        if !noncanonical.contains(&alias) {
            noncanon_alias().remove_if(&canon, |_, v| v == &alias);
            continue;
        }
        if !alias_still_wanted(state, &canon).await {
            noncanonical.remove(&alias);
            noncanon_alias().remove_if(&canon, |_, v| v == &alias);
            warn!("[{}] re-cased alias session is no longer wanted (network gone or disconnected) — sending Drop", alias);
            let _ = out_tx.send(IpcMessage::Drop { conn_id: alias, reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
        }
    }
    for id in std::mem::take(noncanonical) {
        let canon = id.to_ascii_lowercase();
        if seen.contains(&canon) || state.connections.contains_key(&canon) || state.pending_dials.contains(&canon) {
            warn!("[{}] dropping duplicate session with a non-canonical network id", id);
            let _ = out_tx.send(IpcMessage::Drop { conn_id: id.clone(), reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
            continue;
        }
        let Some(username) = state.conn_owners.get(&canon).map(|r| r.clone()) else {
            ghost_candidates.insert(id);
            continue;
        };
        // The user disconnected (or is removing) this network: they want it offline.
        if state.disconnect_requested(&canon) || crate::user_disconnected(&canon)
            || state.get_network_config(&canon, &username).await.is_none() {
            warn!("[{}] re-cased session of a disconnected/removed network — sending Drop", id);
            let _ = out_tx.send(IpcMessage::Drop { conn_id: id.clone(), reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
            continue;
        }
        // An older alias for the same network (two re-cased copies): keep one.
        if let Some(prev) = noncanon_alias().insert(canon.clone(), id.clone()) {
            if prev != id {
                let _ = out_tx.send(IpcMessage::Drop { conn_id: prev, reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
            }
        }
        info!("[{}] the only session of network {} uses a re-cased id — keeping it until the canonical id is dialled", id, canon);
        let cfg_lock = crate::network_config_lock(&username, &canon);
        let _cfg_guard = cfg_lock.lock().await;
        if state.connections.contains_key(&canon)
            || state.conn_owners.get(&canon).map_or(true, |o| o.as_str() != username) { continue; }
        if !state.crypto.is_unlocked(&username).await { continue; }
        let Some(cfg) = state.get_network_config(&canon, &username).await else { continue };
        if !cfg.auto_reconnect { continue; }
        info!("[{}] re-dialling under the canonical id", canon);
        dial(state, &username, cfg, out_tx).await;
    }
}

/// Backstop for GHOST daemon sessions: an IRC connection the daemon still holds although
/// its account/network is gone — deleted while the IPC link was down, or left behind by an
/// older web binary's account deletion (prod's long-lived irc_core may still hold some).
/// Nobody can see or stop such a session from the web. Deliberately conservative, because
/// a false positive disconnects a real user. A reported session is dropped only if ALL of:
///  - its conn_id is a UUID (every web-created network id is; anything else was not made
///    by this web and is left alone);
///  - it has no owner (conn_owners, seeded from disk at startup), no pending dial, and no
///    live web entry;
///  - no file named `<conn_id>.*` exists under ANY user's `networks/` dir, from a scan in
///    which every directory read succeeded (any error: act on nothing);
///  - the daemon is THIS data dir's own: we reached it through `<data_dir>/irc-core.sock`
///    (`colocated`). v-srv-b NEW 2: the old proof ("at least one other reported session
///    has a config here") was satisfied by a stale or partial COPY of the data dir pointed
///    at the live daemon with CRYPTIRC_IPC_SOCK, which then dropped every real session
///    added after the copy; and it could never clean up when the ghost was the daemon's
///    only session (agy P2 ipc_client.rs:465 / v-srv-b NEW 4). With an explicitly
///    redirected socket nothing is dropped.
/// Each drop is logged at warn.
async fn drop_ghost_sessions(state: &AppState, seen: &HashSet<String>, colocated: bool, out_tx: &mpsc::UnboundedSender<IpcMessage>) {
    let candidates: Vec<&String> = seen.iter()
        .filter(|id| crate::auth::validate_uuid(id).is_some())
        .filter(|id| !state.conn_owners.contains_key(id.as_str()) && !state.pending_dials.contains(id.as_str()))
        .collect();
    if candidates.is_empty() { return; }
    if !colocated {
        warn!("{} ownerless irc-core session(s) reported, but irc-core was reached through a socket outside this data dir — leaving them alone", candidates.len());
        return;
    }
    let Some(on_disk) = conn_ids_on_disk(&state.data_dir).await else {
        warn!("{} ownerless irc-core session(s) reported, but the networks dir could not be fully read — leaving them alone", candidates.len());
        return;
    };
    for id in candidates {
        if on_disk.contains(&id.to_ascii_lowercase()) { continue; }
        // Re-check right before acting (a concurrent AddNetwork/Connect wins).
        if state.conn_owners.contains_key(id.as_str()) || state.pending_dials.contains(id.as_str())
            || state.connections.contains_key(id.as_str()) { continue; }
        warn!("[{}] irc-core session has no owner and no network config on disk (account or network deleted while it ran) — sending Drop", id);
        let _ = out_tx.send(IpcMessage::Drop { conn_id: id.clone(), reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
    }
}

/// Every conn_id with ANY file `<conn_id>.*` (config, or a `.json.tmp` mid-save) under
/// `{data_dir}/networks/<user>/`, or None if any directory read fails — never judge
/// ownership from a partial view.
async fn conn_ids_on_disk(data_dir: &str) -> Option<HashSet<String>> {
    let root = format!("{}/networks", data_dir.trim_end_matches('/'));
    let mut users = tokio::fs::read_dir(&root).await.ok()?;
    let mut out = HashSet::new();
    loop {
        let entry = match users.next_entry().await { Ok(Some(e)) => e, Ok(None) => break, Err(_) => return None };
        if !entry.file_type().await.ok()?.is_dir() { continue; }
        let mut confs = tokio::fs::read_dir(entry.path()).await.ok()?;
        loop {
            match confs.next_entry().await {
                Ok(Some(c)) => {
                    if let Some(name) = c.file_name().to_str() {
                        if let Some(id) = name.split('.').next().filter(|s| !s.is_empty()) {
                            // Lower-cased: a re-cased file name still counts as a config.
                            out.insert(id.to_ascii_lowercase());
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => return None,
            }
        }
    }
    Some(out)
}

/// Get the existing `IrcConnection` for `conn_id`, or create one on first
/// sight (a fresh Dial's first reply, or an Attach-triggered rehydration).
/// Returns `None` only if `conn_id` has no known owner at all (shouldn't
/// happen — the daemon only ever tracks conn_ids the web side itself Dialed).
async fn ensure_connection_entry(state: &AppState, conn_id: &str) -> Option<(String, Arc<Mutex<irc::IrcConnection>>)> {
    if let Some(conn) = state.connections.get(conn_id) {
        let username = state.conn_owners.get(conn_id)?.clone();
        return Some((username, conn.clone()));
    }
    let username = state.conn_owners.get(conn_id)?.clone();
    let cfg_lock = crate::network_config_lock(&username, conn_id);
    let _cfg_guard = cfg_lock.lock().await;
    if !state.owns_conn(&username, conn_id) { return None; }
    let cfg = state.get_network_config(conn_id, &username).await?;
    // What this process dialed; else (a reattached session) the config as first seen —
    // until the daemon's SessionSync reports the real endpoint.
    // r4 C2-6: a session no record covers (dialed by a pre-r4 web) is recorded as first
    // seen, so a later edit of the saved server cannot re-attribute it on the next restart.
    let recorded = dialed_endpoints().get(conn_id).map(|e| e.value().clone());
    let dial_endpoint = Some(match recorded {
        Some(ep) => ep,
        None => {
            let ep = (cfg.server.clone(), cfg.port);
            dialed_endpoints().insert(conn_id.to_string(), ep.clone());
            persist_dialed_endpoints();
            ep
        }
    });
    let conn = Arc::new(Mutex::new(irc::IrcConnection {
        conn_id: conn_id.to_string(),
        nick: cfg.nick.clone(),
        connected: false,
        lag_ms: None,
        channels: HashMap::new(),
        ipc_out: state.ipc_out.clone(),
        // Placeholder only — a real Dial's CAP negotiation, or (on reattach)
        // the very next SessionSync, corrects this before any PRIVMSG can
        // arrive. See SessionSync's field doc comment in ipc.rs.
        message_tags: false,
        e2e_bridge: Default::default(),
        reactions: Default::default(), recent_encrypted_targets: Default::default(), recent_plain_targets: Default::default(),
        signal_deliveries: Default::default(), signal_reply_batches: Default::default(), signal_expiry_running: false,
        keepnick_retry: Default::default(),
        self_userhost: String::new(),
        registered: false,
        list_request: None,
        echo_message_enabled: false,
        names_buf: HashMap::new(),
        who_pending: HashSet::new(),
        who_away: HashMap::new(),
        resync_busy: false,
        resync_gen: 0,
        resync_recent: HashMap::new(),
        casemapping: Default::default(),
        server_casemapping: crate::irc::known_casemapping(conn_id),
        dial_endpoint,
        statusmsg: None,
        daemon_channels: Vec::new(),
        user_joins: std::collections::HashSet::new(),
        chanmodes: cryptirc::ircproto::ChanModes::default(),
        whois_seen: Default::default(), seen_userhosts: Default::default(), synced_link: 0, cap_ls_done: false, behind_bouncer: false, daemon_registration: false, registration_epoch: 0, live_registration_link: None, replay_view: None, avx: Default::default(),
        cfg,
    }));
    state.connections.insert(conn_id.to_string(), conn.clone());
    Some((username, conn))
}

/// Resolve a `NetworkConfig` into fully-decrypted `DialParams` and send `Dial`.
/// Shared by the `Connect`/`RemoveNetwork`-then-reconnect handlers and the
/// Attach-time reconciliation above — the single place that knows how to turn
/// a stored config into what the daemon needs to actually open a socket.
pub async fn dial(state: &AppState, username: &str, cfg: NetworkConfig, out_tx: &mpsc::UnboundedSender<IpcMessage>) {
    let conn_id = cfg.id.clone();
    // Avatars: a Dial starts a new session; its classification comes from its own negotiation.
    state.avatars.forget_session(&conn_id);
    // v-irc I1: the re-cased session that kept this network online goes now.
    if let Some((_, alias)) = noncanon_alias().remove(&conn_id) {
        info!("[{}] dropping the re-cased session {} it replaces", conn_id, alias);
        let _ = out_tx.send(IpcMessage::Drop { conn_id: alias, reason: crate::DEFAULT_QUIT_MESSAGE.to_string() });
    }
    let params = build_dial_params(state, username, &cfg).await;
    let endpoint = (params.server.clone(), params.port);
    let msg = IpcMessage::Dial { conn_id: conn_id.clone(), params: Box::new(params) };
    // write_frame silently drops any frame over MAX_FRAME_LEN, so an oversized Dial
    // (huge perform / auto-join / key lists) used to vanish: no connect, no error.
    // Tell the user instead. (Measured in memory only; nothing is logged.)
    let size = serde_json::to_vec(&msg).map(|b| b.len()).unwrap_or(0);
    if size > cryptirc::ipc_framing::MAX_FRAME_LEN as usize {
        warn!("[{}] Dial not sent: {} bytes exceeds the {}-byte IPC frame limit", conn_id, size, cryptirc::ipc_framing::MAX_FRAME_LEN);
        state.send_to_user(username, ServerEvent::Disconnected {
            conn_id,
            reason: "Network settings too large to connect (shorten the perform commands / auto-join list)".into(),
        });
        return;
    }
    dialed_endpoints().insert(conn_id.clone(), endpoint.clone());
    persist_dialed_endpoints();
    daemon_stopped().remove(&conn_id);
    let live = state.connections.get(&conn_id).map(|c| c.clone());
    if let Some(conn) = live {
        let mut c = conn.lock().await;
        c.dial_endpoint = Some(endpoint);
        c.avx.reset();
    }
    let _ = out_tx.send(msg);
}

/// Send `Drop` for `conn_id` through whatever IPC connection is currently up.
/// Best-effort, matching `send_raw`'s philosophy — if the daemon link happens
/// to be down right when the user disconnects, the daemon will simply have
/// nothing to tear down (there's no live socket for it to hold open either).
pub async fn send_drop(state: &AppState, conn_id: &str, reason: String) {
    let live = state.connections.get(conn_id).map(|c| c.clone());
    if let Some(conn) = live { conn.lock().await.avx.reset(); }
    forget_dialed_endpoint(conn_id);
    daemon_stopped().remove(conn_id);
    // A re-cased alias session of this network (v-irc I1) goes with it. The entry is
    // forgotten even with the IPC link down: on the next Attach that session is then just
    // an unaliased re-cased one, and settle_noncanonical_sessions / the ghost backstop
    // drop it (its network is disconnected or gone by then).
    let alias = noncanon_alias().remove(conn_id).map(|(_, a)| a);
    match state.ipc_out.lock().await.as_ref() {
        Some(tx) => {
            if let Some(alias) = alias {
                let _ = tx.send(IpcMessage::Drop { conn_id: alias, reason: reason.clone() });
            }
            let _ = tx.send(IpcMessage::Drop { conn_id: conn_id.to_string(), reason });
        }
        None => { if let Some(alias) = alias { alias_drops_pending().insert(alias, ()); } }
    }
}

/// Same as `dial`, but sends through whatever IPC connection is CURRENTLY
/// installed on `state.ipc_out` — for call sites (ClientMessage handlers) that
/// don't have a specific `out_tx` in hand. Best-effort: if the daemon link is
/// briefly down, this silently no-ops (matches `send_raw`'s existing
/// best-effort philosophy) — the user can just press Connect again, and if
/// this was actually `reconnect_for_user`, the same network will surface via
/// the daemon-restart reconciliation path once the link comes back anyway.
pub async fn dial_current(state: &AppState, username: &str, cfg: NetworkConfig) {
    let out_tx = state.ipc_out.lock().await.clone();
    match out_tx {
        Some(tx) => {
            state.clear_pending_dial(&cfg.id);
            dial(state, username, cfg, &tx).await
        }
        None => {
            warn!("[{}] Dial requested but no irc-core connection is up yet — queueing for later", cfg.id);
            state.queue_pending_dial(&cfg.id);
        }
    }
}

/// Keys are stored under `to_lowercase()` but an irc_core from before the fold-tolerant
/// lookup (still running in production — it is not restarted on updates) looks them up
/// by `irc_lower()`, so `#Key[X]` rejoined without its key. For such a daemon also send
/// each key under its irc_lower spelling when that differs. Not for a daemon announcing
/// `cm_keys` (codex P2 irc.rs:206): on an ascii-casemapping server the alias handed the
/// key of `#x[y]` to the distinct channel `#x{y}`.
fn channel_keys_for_dial(keys: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = keys.clone();
    for (k, v) in keys {
        let folded = cryptirc::ircproto::irc_lower(k);
        if folded != *k {
            out.entry(folded).or_insert_with(|| v.clone());
        }
    }
    out
}

/// Do two configs differ in a setting that only takes effect when dialling (the parts of
/// a `DialParams` that a user edits in the network dialog — not the channel lists, which
/// change as the user joins/parts, nor the label/quit message/channel order)?
pub(crate) fn dial_settings_differ(a: &NetworkConfig, b: &NetworkConfig) -> bool {
    fn key(c: &NetworkConfig) -> serde_json::Value {
        serde_json::json!([
            c.server, c.port, c.tls, c.tls_accept_invalid_certs, c.nick, c.username, c.realname,
            c.password, c.sasl_plain.as_ref().map(|s| (&s.account, &s.password)), c.sasl_external,
            c.client_cert_id, c.oper_login, c.oper_pass, c.nickserv_pass, c.auto_identify,
            c.perform_commands, c.disabled_caps, c.auto_reconnect,
        ])
    }
    key(a) != key(b)
}

async fn build_dial_params(state: &AppState, username: &str, cfg: &NetworkConfig) -> DialParams {
    let client_identity = match &cfg.client_cert_id {
        Some(cert_id) if state.certs.exists(cert_id).await => {
            // r4 F1-3 / V3S-3 (srv-b): the pair is read under the cert dir's lock, so a
            // concurrent regenerate can't hand this dial the new key with the old cert.
            match state.certs.read_pair(cert_id).await {
                Ok((cert_bytes, key_enc)) => match state.crypto.decrypt(username, key_enc.trim()).await {
                    Ok(key_bytes) => Some(ClientIdentity {
                        cert_pem: String::from_utf8_lossy(&cert_bytes).into_owned(),
                        key_pem: String::from_utf8_lossy(&key_bytes).into_owned(),
                    }),
                    Err(e) => {
                        warn!("[{}] client cert key decrypt failed (vault locked?): {}", cfg.id, e);
                        None
                    }
                },
                Err(_) => {
                    warn!("[{}] client cert files unreadable for cert_id {}", cfg.id, cert_id);
                    None
                }
            }
        }
        Some(_) => {
            warn!("[{}] client_cert_id configured but cert files not found", cfg.id);
            None
        }
        None => None,
    };

    // I2 defense-in-depth: NEVER forward an `enc:`-wrapped secret to the IRC server.
    // `get_network_config` leaves secrets `enc:`-wrapped when the vault is locked
    // (undecryptable); sending that ciphertext as PASS / SASL / oper / nickserv would
    // leak an AEAD blob to the server operator and break auth. Drop each such field to
    // None (+ warn), exactly like the client-cert branch degrades on decrypt failure.
    // codex P2 ipc_client.rs:857 / agy P2: judged with the validated blob check
    // (AppState::is_enc_blob, the same one save_network uses), not a bare "enc:" prefix —
    // a real password such as "enc:hunter2" decrypts back to exactly that and must go out.
    let is_blob = crate::AppState::is_enc_blob;
    let deny_enc = |v: &Option<String>, what: &str| -> Option<String> {
        match v {
            Some(s) if is_blob(s) => {
                warn!("[{}] {} still encrypted (vault locked) — omitting from dial", cfg.id, what);
                None
            }
            other => other.clone(),
        }
    };
    let password = deny_enc(&cfg.password, "server password");
    let oper_pass = deny_enc(&cfg.oper_pass, "oper password");
    let nickserv_pass = deny_enc(&cfg.nickserv_pass, "nickserv password");
    // Channel keys and perform commands are encrypted at rest too (codex P1): with a
    // locked vault they come back as "enc:" blobs — never send those as a JOIN key or as
    // a raw IRC line. The rest of the list still goes out.
    let channel_keys: HashMap<String, String> = cfg.channel_keys.iter()
        .filter(|(_, v)| !is_blob(v))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    if channel_keys.len() != cfg.channel_keys.len() {
        warn!("[{}] {} channel key(s) still encrypted (vault locked) — omitting them from dial", cfg.id, cfg.channel_keys.len() - channel_keys.len());
    }
    let perform_commands: Vec<String> = cfg.perform_commands.iter()
        .filter(|c| !is_blob(c))
        .cloned()
        .collect();
    if perform_commands.len() != cfg.perform_commands.len() {
        warn!("[{}] {} perform command(s) still encrypted (vault locked) — omitting them from dial", cfg.id, cfg.perform_commands.len() - perform_commands.len());
    }
    let sasl_plain = cfg.sasl_plain.as_ref().and_then(|s: &SaslConfig| {
        if is_blob(&s.password) {
            warn!("[{}] SASL password still encrypted (vault locked) — omitting SASL PLAIN from dial", cfg.id);
            None
        } else {
            Some(SaslParams { account: s.account.clone(), password: s.password.clone() })
        }
    });

    DialParams {
        server: cfg.server.clone(),
        port: cfg.port,
        tls: cfg.tls,
        tls_accept_invalid_certs: cfg.tls_accept_invalid_certs,
        nick: cfg.nick.clone(),
        username: cfg.username.clone(),
        realname: cfg.realname.clone(),
        password,
        sasl_plain,
        sasl_external: cfg.sasl_external,
        client_identity,
        oper_login: cfg.oper_login.clone(),
        oper_pass,
        nickserv_pass,
        auto_identify: cfg.auto_identify,
        auto_join: cfg.auto_join.clone(),
        channel_keys: if DAEMON_CM_KEYS.load(std::sync::atomic::Ordering::Acquire) { channel_keys }
                      else { channel_keys_for_dial(&channel_keys) },
        perform_commands,
        disabled_caps: cfg.disabled_caps.clone(),
        label: cfg.label.clone(),
        auto_reconnect: cfg.auto_reconnect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reattached_reaction_labels_follow_enabled_capabilities() {
        use cryptirc::ipc::RegistrationFacts;
        let mut facts = RegistrationFacts {
            cap_ls_done: true, caps: vec![crate::reactions::CAP.into(), "labeled-response".into()],
            enabled_caps: vec!["message-tags".into()], ..Default::default()
        };
        assert_eq!(enabled_reaction_label(&facts), Some(false));
        facts.enabled_caps.push("labeled-response".into());
        assert_eq!(enabled_reaction_label(&facts), Some(true));
        facts.enabled_caps.clear();
        assert_eq!(enabled_reaction_label(&facts), None);
        facts.caps.pop();
        assert_eq!(enabled_reaction_label(&facts), Some(false));
    }

    #[test]
    fn dial_settings_change_detection() {
        let a = NetworkConfig { server: "irc.example.org".into(), port: 6697, nick: "me".into(), ..Default::default() };
        let mut b = a.clone();
        b.label = "renamed".into();
        b.auto_join = vec!["#new".into()];
        b.quit_message = Some("bye".into());
        assert!(!dial_settings_differ(&a, &b), "label / channel lists / quit message apply without a re-dial");
        b.server = "irc.other.org".into();
        assert!(dial_settings_differ(&a, &b));
        let mut c = a.clone();
        c.sasl_plain = Some(SaslConfig { account: "x".into(), password: "y".into() });
        assert!(dial_settings_differ(&a, &c));
        let mut d = a.clone();
        d.perform_commands = vec!["/msg x y".into()];
        assert!(dial_settings_differ(&a, &d));
    }

    /// r4 C2-6 (codex P2 ipc_client.rs:784): the dial records survive a web restart (the
    /// file round-trips, is 0600, and junk / a missing file reads as empty).
    #[tokio::test]
    async fn dial_endpoints_round_trip_through_the_data_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cryptirc-r4-dial-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dial_endpoints_file(dir.to_str().unwrap());
        assert!(read_dial_endpoints(&path).await.is_empty());
        let mut m = HashMap::new();
        m.insert("6f1c8a52-2d47-4d4e-9a39-0c1d2e3f4a5b".to_string(), ("irc.network-a.example".to_string(), 6697u16));
        write_dial_endpoints(&path, &m).await.unwrap();
        assert_eq!(read_dial_endpoints(&path).await, m);
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        std::fs::write(&path, b"{not json").unwrap();
        assert!(read_dial_endpoints(&path).await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
