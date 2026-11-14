//! ipc_server.rs — the daemon side of the IPC boundary. Listens on a Unix
//! domain socket, accepts exactly one web-process client at a time (a fresh
//! `Attach` supersedes any prior connection), and routes `Dial`/`RawSend`/
//! `Drop`/`Attach` into per-conn_id `irc_daemon::run_connection` tasks.
//!
//! Each conn_id also gets a small cache (last known `SessionSync` snapshot +
//! a bounded ring buffer of recent `RawLine`s) so a freshly-attached client
//! can be caught up immediately without waiting for new server traffic.

use crate::ipc::{ConnLifecycle, DialParams, IpcMessage, WebVersionCell, DAEMON_FEATURES, IPC_PROTO_VERSION};
use crate::ipc_framing::{read_frame, write_frame};
use crate::irc_daemon::{cap_outbound_line, run_connection, DaemonCmd, QueuedLine};
use anyhow::Result;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

/// Bounded per-connection replay buffer. Sized so a normal few-second web
/// restart replays with zero loss; an extended outage just ages out older
/// lines rather than growing memory without bound (deliberately not
/// ZNC-style persistent chathistory — that's out of scope for the "thin
/// socket-keeper" design).
const RING_CAP: usize = 2000;
/// ...and by BYTES. A line-count cap alone let one connection pin ~18.6 MB (2000 lines
/// × up to MAX_IRC_LINE_LEN 8 KiB), so one tenant with 20 networks fed 8 KiB lines by
/// their own server could OOM the shared daemon (MemoryMax=512M) and drop EVERY user's
/// IRC. Normal traffic (a few hundred bytes per tagged line) stays line-capped well
/// below this; only abusive line sizes hit it. Each entry is weighed as its length plus
/// RING_ENTRY_OVERHEAD (String header, timestamp, the shared delivery flag + allocator
/// slack) so many tiny lines count too.
const RING_BYTE_CAP: usize = 1536 * 1024;
const RING_ENTRY_OVERHEAD: usize = 80;
/// Daemon-wide budget across every connection's ring. While the total is over it, a
/// ring that grows trims itself down to RING_PRESSURE_FLOOR, so the busiest
/// (most-pushing) rings shed first and the total converges back under the budget.
const RING_GLOBAL_BYTE_BUDGET: usize = 192 * 1024 * 1024;
const RING_PRESSURE_FLOOR: usize = 128 * 1024;
/// Live total of every ConnCache's `ring_bytes` (see push_line / Drop).
static RING_BYTES_TOTAL: AtomicUsize = AtomicUsize::new(0);
/// While a client's Attach replay owns the out-queue, live frames that don't fit are
/// parked per client (in order) instead of dropping the client; this bounds that park.
/// Over it, the old policy applies (drop the client; it replays on re-Attach).
const REPLAY_PARK_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Bound on the live out-queue to the currently-attached web client. A client
/// that stops reading (crashed mid-frame, SIGSTOP'd, kernel buffer full) must
/// never let this grow without bound and OOM the un-restartable daemon. On
/// overflow we DROP THE CLIENT — the ring buffer replays everything on the next
/// Attach, which is the intended recovery path. An Attach replay (one SessionSync +
/// up to RING_CAP lines PER connection) can be far larger than this queue; it is sent
/// with a blocking send and live frames that would overflow meanwhile are parked
/// (see CurrentClient::replaying), so a healthy-but-busy client is never dropped
/// just because a live line arrived during its replay.
const OUT_QUEUE_CAP: usize = 4096;
/// r4 V3I-N6 (w3-irc INFO): ...and by BYTES for live frames. OUT_QUEUE_CAP counts frames
/// whatever their size, so a slow-but-alive web plus a server toggling self-JOIN/PART on
/// a 512-channel connection (a ~60 KiB snapshot per change) could pin ~240 MiB here.
/// Over this many queued bytes the client is dropped exactly like on a full queue (it
/// replays from the ring on re-Attach). Normal traffic (4096 × a few hundred bytes) never
/// gets near it. Daemon-internal: no IPC change.
const OUT_QUEUE_MAX_BYTES: usize = 32 * 1024 * 1024;
/// r4 (C2-4): at most this many written-but-unacknowledged ring lines are remembered per
/// `proc_ack` client; past it the oldest counts as delivered (the pre-r4 rule).
const ACK_WAIT_CAP: usize = 1 << 17;
/// r4 (C1-9): at most one SendDropped notice per connection per this many milliseconds.
const SEND_DROPPED_EVERY_MS: i64 = 10_000;
/// r5 (codex P2 ipc_server.rs:100): an ENDED connection whose ring still holds lines no web
/// has had (acknowledged) is kept this long, at most ENDED_KEEP_MAX of them, so a web that
/// attaches within that time still gets them (as backlog) — a brief web outage no longer
/// loses the last lines of, e.g., an Auto-Reconnect=No network the server closed.
const ENDED_KEEP_TTL: Duration = Duration::from_secs(30 * 60);
const ENDED_KEEP_MAX: usize = 64;
/// Per-connection emit queue (run_connection → cache/forward consumer) and the
/// web→conn command queue. A line/command flood can't grow these unbounded;
/// on overflow we shed with a warning (a flooding peer is a bug, and the IRC
/// read-timeout / flood defenses are the real fix upstream).
const EMIT_QUEUE_CAP: usize = 4096;
const CMD_QUEUE_CAP: usize = 1024;

/// Monotonic per-connection generation token. A connection task removes its own
/// `conns` entry on exit ONLY if the entry still carries its token — so a
/// Dial-replace that spawned a NEW task for the same conn_id isn't clobbered by
/// the OLD task's cleanup. See `ConnGuard`.
static CONN_SEQ: AtomicU64 = AtomicU64::new(1);

/// Removes a connection's `conns` entry (only if it's still THIS generation) and
/// emits a Disconnected status when a connection task exits — on the normal
/// return path AND on an unwinding panic (panic=unwind). Without this, a panic
/// in `run_connection` would orphan the entry: the conn_id becomes un-redialable
/// ("already owned") and un-droppable (RawSend/Drop route to a dead channel).
struct ConnGuard {
    daemon: Arc<Daemon>,
    conn_id: String,
    token: u64,
    /// Set by the emit closure when run_connection emits a terminal Disconnected.
    terminal_sent: Arc<AtomicBool>,
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        // Remove only if the current entry is still ours (not a Dial-replace's new task).
        let removed_handle = self.daemon.conns.remove_if(&self.conn_id, |_, h| h.token == self.token);
        let removed = removed_handle.is_some();
        // r5 (codex P2 ipc_server.rs:100): its ring may still hold lines no web has had —
        // keep it for the next Attach (pruned once delivered / expired).
        if let Some((_, h)) = removed_handle { self.daemon.keep_ended(&self.conn_id, h.cache); }
        // run_connection already emitted its own terminal Disconnected (with the real
        // reason) on every normal return; a second, generic one raced it to the web out
        // of order. Only a task that ended WITHOUT one (a panic) needs this notice.
        if removed && self.terminal_sent.load(Ordering::Acquire) {
            tracing::info!(target: "irc_core", conn_id = %self.conn_id, "connection task ended — removed from daemon");
        } else if removed {
            tracing::warn!(target: "irc_core", event = "conn_permanently_dead", conn_id = %self.conn_id, "connection task ended — removed from daemon");
            // Best-effort notify the web that this conn is gone (Drop is sync).
            let d = self.daemon.clone();
            let id = self.conn_id.clone();
            tokio::spawn(async move {
                d.forward_live(OutFrame::plain(IpcMessage::ConnStatus {
                    conn_id: id,
                    state: ConnLifecycle::Disconnected { reason: "connection task ended".into() },
                })).await;
            });
        }
    }
}

/// Aborts a held `JoinHandle` when dropped. Used to bind the emit-consumer's
/// lifetime to `run_connection`: if the consumer ever exits (channel closed OR
/// its own panic), it tears down `run_connection` too, so a "socket alive but
/// deaf/blind" half-dead connection can't persist.
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) { self.0.abort(); }
}

// ── systemd sd_notify (self-contained; avoids an external crate for a frozen
// binary). Sends READY/WATCHDOG/STATUS datagrams to $NOTIFY_SOCKET. No-op when
// not run under a Type=notify unit. ─────────────────────────────────────────
fn sd_notify(state: &str) {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    if path.is_empty() { return; }
    let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() else { return };
    if let Some(stripped) = path.strip_prefix('@') {
        // Abstract namespace socket (leading NUL). Build the sockaddr by hand.
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
            addr.sun_family = libc::AF_UNIX as _;
            let bytes = stripped.as_bytes();
            let cap = addr.sun_path.len() - 1;
            let n = bytes.len().min(cap);
            for i in 0..n { addr.sun_path[i + 1] = bytes[i] as libc::c_char; }
            let len = (std::mem::size_of::<libc::sa_family_t>() + 1 + n) as libc::socklen_t;
            let _ = unsafe {
                libc::sendto(sock.as_raw_fd(), state.as_ptr() as *const _, state.len(),
                    libc::MSG_NOSIGNAL, &addr as *const _ as *const libc::sockaddr, len)
            };
        }
        return;
    }
    let _ = sock.send_to(state.as_bytes(), &path);
}

/// The peer's effective UID via SO_PEERCRED (Linux). `None` if unavailable.
fn peer_euid(stream: &UnixStream) -> Option<u32> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void, &mut len)
        };
        if r == 0 { return Some(cred.uid); }
    }
    None
}

/// One buffered line. A line is DELIVERED once the IPC writer has actually written it to
/// a web client's socket (`delivered`, set by the writer); a line that never was is
/// replayed with `backlog` so the web logs it (codex P2 irc.rs:359 — lines received while
/// no web was attached used to be replayed as already-processed and never reached
/// history). codex P2 ipc_server.rs:979: it used to count as delivered as soon as it was
/// QUEUED for the writer, so frames still queued when a slow client was dropped (or its
/// writer timed out) were lost from history for good.
struct RingEntry {
    line: String,
    recv_ts: i64,
    /// Shared with every frame carrying this line; the writer sets it once one is written.
    /// (A per-line flag, not a watermark: a line that reached no client — none attached —
    /// can precede one written live to a client whose Attach replay has not run yet.)
    delivered: Arc<AtomicBool>,
}

/// One frame for the IPC writer. `ack`, for a ring line: its `delivered` flag, which the
/// writer sets once the frame is written (see RingEntry) — or, for a `proc_ack` client
/// (r4 C2-4), once the client acknowledges having processed it (see ClientAcks).
/// `weight`: bytes charged to the client's live out-queue budget (OUT_QUEUE_MAX_BYTES),
/// released by the writer; 0 = not charged (replay and parked frames).
pub(crate) struct OutFrame {
    msg: IpcMessage,
    ack: Option<Arc<AtomicBool>>,
    weight: usize,
}

impl OutFrame {
    fn plain(msg: IpcMessage) -> Self { Self { msg, ack: None, weight: 0 } }
}

/// r4: what one attached web client announced in its Attach (`ipc::WEB_FEATURES`) and,
/// with `proc_ack` (codex P2 ipc_server.rs:681), the ring lines written to it that it has
/// not yet acknowledged as processed. Shared by the client's writer (which numbers each
/// ring line it writes, `RawLine.seq`) and its reader (which applies `Processed`). A line
/// counts as delivered only once acknowledged, so a line still in the socket buffer — or
/// read but not yet handled — when the web process dies is replayed as backlog (and
/// logged) after it restarts, instead of being lost from history.
#[derive(Default)]
pub(crate) struct ClientAcks {
    proc_ack: AtomicBool,
    send_dropped: AtomicBool,
    waiting: std::sync::Mutex<VecDeque<(u64, Arc<AtomicBool>)>>,
    /// r5 (hold_ack): seqs the web declared `Held` that are not acknowledged yet …
    held: std::sync::Mutex<HashSet<u64>>,
    /// … and held lines already acknowledged: kept undelivered until `Released`.
    parked: std::sync::Mutex<HashMap<u64, Arc<AtomicBool>>>,
}

/// r5: bound on held / parked seqs per client (past it the old rule applies: delivered).
const HOLD_TRACK_MAX: usize = 1 << 16;

impl ClientAcks {
    fn set_features(&self, features: &[String]) {
        self.proc_ack.store(features.iter().any(|f| f == "proc_ack"), Ordering::Release);
        self.send_dropped.store(features.iter().any(|f| f == "send_dropped"), Ordering::Release);
    }
    /// Writer: ring line `seq` was written; it is delivered once acknowledged.
    fn written(&self, seq: u64, delivered: Arc<AtomicBool>) {
        let mut w = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
        w.push_back((seq, delivered));
        while w.len() > ACK_WAIT_CAP {
            if let Some((_, d)) = w.pop_front() { d.store(true, Ordering::Release); }
        }
    }
    /// Reader: the client processed every line up to and including `upto` — a line it
    /// declared held stays undelivered (parked) until released.
    fn processed(&self, upto: u64) {
        let mut w = self.waiting.lock().unwrap_or_else(|e| e.into_inner());
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let mut parked = self.parked.lock().unwrap_or_else(|e| e.into_inner());
        while w.front().map_or(false, |(s, _)| *s <= upto) {
            if let Some((s, d)) = w.pop_front() {
                if held.remove(&s) && parked.len() < HOLD_TRACK_MAX { parked.insert(s, d); }
                else { d.store(true, Ordering::Release); }
            }
        }
    }
    /// Reader (r5): these lines are processed but not durable yet (see IpcMessage::Held).
    fn hold(&self, seqs: &[u64]) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        for s in seqs { if held.len() < HOLD_TRACK_MAX { held.insert(*s); } }
    }
    /// Reader (r5): these held lines are durable now (see IpcMessage::Released).
    fn release(&self, seqs: &[u64]) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let mut parked = self.parked.lock().unwrap_or_else(|e| e.into_inner());
        for s in seqs {
            held.remove(s);
            if let Some(d) = parked.remove(s) { d.store(true, Ordering::Release); }
        }
    }
}

/// r4 (C1-9): last SendDropped notice per conn_id (unix ms), for SEND_DROPPED_EVERY_MS.
fn send_dropped_notices() -> &'static DashMap<String, i64> {
    static M: std::sync::OnceLock<DashMap<String, i64>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}

/// The target of an outgoing PRIVMSG/NOTICE line (after optional `@tags` / `:source`).
fn chat_line_target(line: &str) -> Option<&str> {
    let mut rest = line.trim_start_matches(' ');
    if rest.starts_with('@') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    if rest.starts_with(':') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    let mut parts = rest.split(' ').filter(|t| !t.is_empty());
    let verb = parts.next()?;
    if !(verb.eq_ignore_ascii_case("PRIVMSG") || verb.eq_ignore_ascii_case("NOTICE")) { return None; }
    parts.next().map(|t| t.trim_end_matches(['\r', '\n']))
}

/// r4 (codex P1 main.rs:5882): tell a `send_dropped` web that a chat line (PRIVMSG /
/// NOTICE — what the web echoes as sent) of `conn_id` was not sent. Other lines (WHO,
/// NAMES, MODE, … the web also sends on its own) are not reported. Rate-limited per
/// connection; never blocks (skipped when the out-queue is full, which drops that
/// client anyway).
fn report_send_dropped(acks: &ClientAcks, out_tx: &mpsc::Sender<OutFrame>, conn_id: &str, line: &str, why: &str) {
    if !acks.send_dropped.load(Ordering::Acquire) { return; }
    let Some(target) = chat_line_target(line) else { return };
    let reason = format!("{}; message to {}", why, target.chars().take(64).collect::<String>());
    let now = chrono::Utc::now().timestamp_millis();
    let m = send_dropped_notices();
    if m.get(conn_id).map_or(false, |t| now - *t < SEND_DROPPED_EVERY_MS) { return; }
    if m.len() > 1024 { m.retain(|_, t| now - *t < 3_600_000); }
    m.insert(conn_id.to_string(), now);
    let _ = out_tx.try_send(OutFrame::plain(IpcMessage::SendDropped { conn_id: conn_id.to_string(), reason }));
}

/// Cap on lifecycle events held for a connection whose Attach replay is still pending.
const PENDING_STATUS_CAP: usize = 64;

#[derive(Default)]
struct ConnCache {
    ring: VecDeque<RingEntry>,
    /// Weighed size of `ring` (see RING_BYTE_CAP); mirrored into RING_BYTES_TOTAL.
    ring_bytes: usize,
    /// The dialed endpoint (see IpcMessage::SessionSync::dial_server).
    dial_server: String,
    dial_port: u16,
    /// r8: the latest SessionSync's CHANMODES/PREFIX tokens (see IpcMessage::SessionSync).
    chanmodes: Option<String>,
    nick: String,
    channels: Vec<String>,
    registered: bool,
    connected: bool,
    lag_ms: Option<u64>,
    message_tags: bool,
    echo_message_enabled: bool,
    self_userhost: String,
    /// Last CASEMAPPING token a SessionSync carried ("" = never told).
    casemapping: String,
    /// r5: the reason of the connection's terminal Disconnected (replayed after its
    /// retained history, see Daemon::ended).
    last_disconnect: String,
}

impl ConnCache {
    #[cfg(test)]
    fn push_line(&mut self, line: String) {
        self.push_line_at(line, chrono::Utc::now().timestamp());
    }

    /// Push a line; returns its delivery flag (for the frame that forwards it live).
    fn push_line_at(&mut self, line: String, recv_ts: i64) -> Arc<AtomicBool> {
        let w = line.len() + RING_ENTRY_OVERHEAD;
        let delivered = Arc::new(AtomicBool::new(false));
        self.ring.push_back(RingEntry { line, recv_ts, delivered: delivered.clone() });
        self.ring_bytes += w;
        RING_BYTES_TOTAL.fetch_add(w, Ordering::Relaxed);
        let byte_cap = ring_byte_cap(RING_BYTES_TOTAL.load(Ordering::Relaxed));
        // Oldest-first eviction; always keep the newest line.
        while self.ring.len() > RING_CAP || (self.ring_bytes > byte_cap && self.ring.len() > 1) {
            if let Some(old) = self.ring.pop_front() {
                let ow = old.line.len() + RING_ENTRY_OVERHEAD;
                self.ring_bytes -= ow;
                RING_BYTES_TOTAL.fetch_sub(ow, Ordering::Relaxed);
            }
        }
        delivered
    }

    fn is_delivered(&self, e: &RingEntry) -> bool {
        e.delivered.load(Ordering::Acquire)
    }

    /// The current `SessionSync` snapshot of this connection.
    fn snapshot(&self, conn_id: &str) -> IpcMessage {
        IpcMessage::SessionSync {
            conn_id: conn_id.to_string(),
            nick: self.nick.clone(),
            channels: self.channels.clone(),
            registered: self.registered,
            connected: self.connected,
            lag_ms: self.lag_ms,
            message_tags: self.message_tags,
            echo_message_enabled: self.echo_message_enabled,
            self_userhost: self.self_userhost.clone(),
            casemapping: self.casemapping.clone(),
            dial_server: self.dial_server.clone(),
            dial_port: self.dial_port,
            chanmodes: self.chanmodes.clone(),
        }
    }

    /// Rebuild the replay frames (a `SessionSync` snapshot + the buffered `RawLine`s, each
    /// carrying its delivery ack) sent to a client on a fresh `Attach`.
    fn replay_frames(&self, conn_id: &str) -> Vec<OutFrame> {
        let mut out = Vec::with_capacity(self.ring.len() + 1);
        out.push(OutFrame::plain(self.snapshot(conn_id)));
        for e in &self.ring {
            out.push(OutFrame {
                msg: IpcMessage::RawLine {
                    conn_id: conn_id.to_string(), line: e.line.clone(), replayed: true,
                    backlog: !self.is_delivered(e), recv_ts: e.recv_ts, seq: 0,
                },
                ack: Some(e.delivered.clone()),
                weight: 0,
            });
        }
        out
    }
}

/// The conn_id a daemon→web message is about (None for connection-less messages).
fn msg_conn_id(msg: &IpcMessage) -> Option<&str> {
    match msg {
        IpcMessage::RawLine { conn_id, .. } | IpcMessage::ConnStatus { conn_id, .. }
        | IpcMessage::SessionSync { conn_id, .. } => Some(conn_id.as_str()),
        _ => None,
    }
}

/// Per-ring byte cap given the daemon-wide ring total (see RING_GLOBAL_BYTE_BUDGET).
fn ring_byte_cap(total: usize) -> usize {
    if total > RING_GLOBAL_BYTE_BUDGET { RING_PRESSURE_FLOOR } else { RING_BYTE_CAP }
}

impl Drop for ConnCache {
    fn drop(&mut self) {
        RING_BYTES_TOTAL.fetch_sub(self.ring_bytes, Ordering::Relaxed);
    }
}

/// Rough in-memory weight of a parked live frame (REPLAY_PARK_MAX_BYTES accounting).
/// codex P2 ipc_server.rs:274: a SessionSync used to be charged a flat 512 bytes although
/// a 512-channel snapshot holds ~60 KiB, so parked snapshots blew far past the budget.
fn frame_weight(msg: &IpcMessage) -> usize {
    match msg {
        IpcMessage::RawLine { conn_id, line, .. } => line.len() + conn_id.len() + 64,
        IpcMessage::SessionSync { conn_id, nick, channels, self_userhost, casemapping, dial_server, .. } =>
            256 + conn_id.len() + nick.len() + self_userhost.len() + casemapping.len() + dial_server.len()
                + channels.iter().map(|c| c.len() + 32).sum::<usize>(),
        IpcMessage::ConnStatus { conn_id, state } => 128 + conn_id.len() + match state {
            ConnLifecycle::Disconnected { reason } | ConnLifecycle::Reconnecting { reason, .. } => reason.len(),
            ConnLifecycle::Connecting => 0,
        },
        _ => 128,
    }
}

struct ConnHandle {
    cmd_tx: mpsc::Sender<DaemonCmd>,
    cache: Arc<Mutex<ConnCache>>,
    /// Bytes of web RawSend lines queued for this connection (codex P2 ipc_server.rs:745).
    raw_bytes: Arc<AtomicUsize>,
    /// Generation token — the connection task's `ConnGuard` only reaps this
    /// entry if the token still matches (survives a Dial-replace).
    token: u64,
}

struct CurrentClient {
    /// Identifies this accepted socket, so its own reader can tell whether it is still
    /// the installed client (vs. superseded) when it finishes an Attach or exits.
    id: u64,
    out_tx: mpsc::Sender<OutFrame>,
    /// r4 V3I-N6: bytes of live frames queued in `out_tx` (see OUT_QUEUE_MAX_BYTES).
    live_bytes: Arc<AtomicUsize>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
    /// True while this client's Attach replay is being pushed into `out_tx`.
    replaying: bool,
    /// Once a live frame failed to fit during the replay, EVERY later live frame is
    /// parked (not try_sent) until the park is flushed, so live frames stay in order.
    parking: bool,
    parked: VecDeque<OutFrame>,
    parked_bytes: usize,
    /// codex P2 ipc_server.rs:299: connections whose Attach replay has not been queued
    /// yet. Their live lines/snapshots are already in the cache the replay is built from
    /// (same cache lock), so they are NOT also forwarded live — that delivered them twice
    /// and, worse, ahead of their own history (a live KICK before the replayed self-JOIN
    /// it undoes left a ghost channel). Lifecycle events, which the cache doesn't replay,
    /// are held in `pending_status` and sent right before that connection's replay.
    pending: HashSet<String>,
    pending_status: HashMap<String, Vec<IpcMessage>>,
    /// codex P2 ipc_server.rs:803 / w-srv INFO: connections whose replay frames are being
    /// queued right now. The replay no longer holds the connection's cache lock while it
    /// waits on the (bounded) out-queue — that stalled the connection's live consumer
    /// behind a slow web and let its emit queue grow — so their live frames are parked
    /// instead, behind the replay, and flushed in order with the rest of the park.
    inflight: HashSet<String>,
}

static CLIENT_SEQ: AtomicU64 = AtomicU64::new(1);

pub struct Daemon {
    conns: DashMap<String, ConnHandle>,
    current_client: Mutex<Option<CurrentClient>>,
    /// Latest web-Attach-announced `(version, build)` — see `WebVersionCell`.
    /// `Arc`-wrapped (rather than a bare field) so `spawn_connection` can hand
    /// `run_connection` its own cheap handle without threading the whole
    /// `Daemon` type into `irc_daemon` (which would create a dependency cycle).
    web_version: Arc<WebVersionCell>,
    /// r5 (codex P2 ipc_server.rs:100): connections that ENDED, kept with their cache (ring)
    /// until every line in it was delivered to a web, or ENDED_KEEP_TTL — replayed on Attach
    /// like a live connection, followed by their terminal Disconnected.
    ended: DashMap<String, EndedConn>,
    /// r9 (astra P2 ipc_server.rs:1386): the token of the NEWEST connection task started for
    /// each conn_id. A task whose token is older has been superseded for good: it never
    /// forwards again — not even after its replacement exited and left no `conns` entry
    /// (the live owner of that conn_id may be another account by then). One entry per conn_id
    /// ever dialed; never removed (a removal would make the old task look current again).
    latest_token: DashMap<String, u64>,
}

struct EndedConn {
    cache: Arc<Mutex<ConnCache>>,
    since: std::time::Instant,
}

impl Daemon {
    fn new() -> Self {
        Self { conns: DashMap::new(), current_client: Mutex::new(None), web_version: Arc::new(WebVersionCell::default()), ended: DashMap::new(), latest_token: DashMap::new() }
    }

    /// r5: keep an ended connection's cache for the next Attach (see `ended`). Bounded:
    /// expired entries go first, then the oldest.
    fn keep_ended(&self, conn_id: &str, cache: Arc<Mutex<ConnCache>>) {
        self.ended.retain(|_, e| e.since.elapsed() < ENDED_KEEP_TTL);
        while self.ended.len() >= ENDED_KEEP_MAX {
            let oldest = self.ended.iter().min_by_key(|e| e.value().since).map(|e| e.key().clone());
            match oldest { Some(k) => { self.ended.remove(&k); } None => break }
        }
        self.ended.insert(conn_id.to_string(), EndedConn { cache, since: std::time::Instant::now() });
    }

    /// r5: before an Attach replay, forget ended connections that expired.
    /// r6 (agy P2 ipc_server.rs:528): NOT because all their lines were delivered — a web
    /// that restarts after a connection ended (SASL given up, K-line, Auto-Reconnect off) learns
    /// that it ended, and why, only from this replay: pruned, it never got the terminal state
    /// and AttachComplete re-dialed it (an auto-reconnect network) or reported "Daemon
    /// restarted". Bounded by ENDED_KEEP_TTL and ENDED_KEEP_MAX; kept rings still count
    /// against the global ring byte budget; a Dial for the id removes it.
    async fn prune_ended(&self) {
        self.ended.retain(|_, e| e.since.elapsed() < ENDED_KEEP_TTL);
    }

    /// Best-effort forward to whichever client is CURRENTLY attached (looked
    /// up fresh on every call, since the attached client can change over a
    /// connection's lifetime). Silently drops if nobody is attached — the
    /// cache (updated by the caller before this) is what a future Attach
    /// replays from, so nothing is lost, just not delivered live.
    /// A ring line counts as delivered only once the writer has written it (its
    /// `frame.ack`), never merely because it was queued or parked here. A frame of a
    /// connection whose replay is still pending is not sent at all: it is already in the
    /// cache that replay is built from.
    async fn forward_live(&self, frame: OutFrame) {
        let mut guard = self.current_client.lock().await;
        // Non-blocking send into the BOUNDED out-queue. If it's full, the client is
        // reading too slowly (or is wedged) — never block the caller (a per-conn cache/
        // forward task) waiting on it. Drop the client instead: the ring buffer replays
        // everything on its next Attach, which is the designed recovery path. Also drops
        // on Closed (writer task already gone).
        //
        // EXCEPT mid-replay: an Attach replay legitimately fills the queue (it can hold
        // many connections' full rings), so a full queue then says nothing about the
        // client's health. Park the frame instead (bounded); the Attach handler flushes
        // the park, in order, before AttachComplete. Dropping here used to abort every
        // busy reattach (the web then reconnected and replayed again, in a loop).
        let drop_why: Option<&str> = match guard.as_mut() {
            Some(c) if c.replaying && msg_conn_id(&frame.msg).map_or(false, |id| c.pending.contains(id)) => {
                if matches!(frame.msg, IpcMessage::ConnStatus { .. }) {
                    let id = msg_conn_id(&frame.msg).unwrap_or_default().to_string();
                    let held = c.pending_status.entry(id).or_default();
                    if held.len() >= PENDING_STATUS_CAP { held.remove(0); }
                    held.push(frame.msg);
                }
                // RawLine / SessionSync: already in the cache this connection's replay is
                // about to be built from — nothing to send now.
                None
            }
            Some(c) if c.replaying => {
                // A connection whose replay frames are being queued right now: behind them.
                let behind_replay = msg_conn_id(&frame.msg).map_or(false, |id| c.inflight.contains(id));
                let to_park = if c.parking || behind_replay {
                    c.parking = true;
                    Ok(Some(frame))
                } else {
                    match c.out_tx.try_send(frame) {
                        Ok(()) => Ok(None),
                        Err(mpsc::error::TrySendError::Full(f)) => { c.parking = true; Ok(Some(f)) }
                        Err(mpsc::error::TrySendError::Closed(_)) => Err("writer gone"),
                    }
                };
                match to_park {
                    Err(why) => Some(why),
                    Ok(None) => None,
                    Ok(Some(f)) => {
                        let w = frame_weight(&f.msg);
                        if c.parked_bytes + w > REPLAY_PARK_MAX_BYTES {
                            Some("replay park full")
                        } else {
                            c.parked_bytes += w;
                            c.parked.push_back(f);
                            None
                        }
                    }
                }
            }
            // v-irc I3: say which — a closed writer is a gone client, not a slow one.
            // r4 V3I-N6: charged to the live byte budget before it is queued (the writer
            // releases it after the write, so the counter can never underflow).
            Some(c) => {
                let w = frame_weight(&frame.msg);
                if c.live_bytes.load(Ordering::Acquire) + w > OUT_QUEUE_MAX_BYTES {
                    Some("out-queue byte cap")
                } else {
                    let mut frame = frame;
                    frame.weight = w;
                    c.live_bytes.fetch_add(w, Ordering::AcqRel);
                    match c.out_tx.try_send(frame) {
                        Ok(()) => None,
                        Err(mpsc::error::TrySendError::Full(_)) => { c.live_bytes.fetch_sub(w, Ordering::AcqRel); Some("out-queue full") }
                        Err(mpsc::error::TrySendError::Closed(_)) => { c.live_bytes.fetch_sub(w, Ordering::AcqRel); Some("writer gone") }
                    }
                }
            }
            None => None,
        };
        if let Some(why) = drop_why {
            self.drop_current(&mut guard, why);
        }
    }

    /// Start client `id`'s Attach replay: mark it replaying and every currently owned
    /// connection as pending, atomically with respect to forward_live. Returns the
    /// connections (and the cache each had at this moment) to replay, or None if `id`
    /// is no longer the installed client.
    async fn begin_replay(&self, id: u64) -> Option<Vec<(String, Arc<Mutex<ConnCache>>)>> {
        let mut g = self.current_client.lock().await;
        let c = g.as_mut().filter(|c| c.id == id)?;
        let mut list: Vec<(String, Arc<Mutex<ConnCache>>)> = self.conns.iter()
            .map(|e| (e.key().clone(), e.value().cache.clone()))
            .collect();
        // r5: plus ended connections that still have undelivered history (see `ended`).
        for e in self.ended.iter() {
            if !self.conns.contains_key(e.key()) { list.push((e.key().clone(), e.value().cache.clone())); }
        }
        c.replaying = true;
        c.pending = list.iter().map(|(k, _)| k.clone()).collect();
        c.pending_status.clear();
        c.inflight.clear();
        Some(list)
    }

    /// `conn_id`'s replay is being taken now (caller holds its cache lock): it stops being
    /// pending and is in flight until `end_conn_replay`. Hands back the lifecycle events
    /// held for it meanwhile (in order).
    async fn begin_conn_replay(&self, id: u64, conn_id: &str) -> Vec<IpcMessage> {
        let mut g = self.current_client.lock().await;
        let Some(c) = g.as_mut().filter(|c| c.id == id) else { return Vec::new() };
        c.pending.remove(conn_id);
        c.inflight.insert(conn_id.to_string());
        c.pending_status.remove(conn_id).unwrap_or_default()
    }

    /// `conn_id`'s replay frames are all queued (or the client is gone).
    async fn end_conn_replay(&self, id: u64, conn_id: &str) {
        let mut g = self.current_client.lock().await;
        if let Some(c) = g.as_mut().filter(|c| c.id == id) { c.inflight.remove(conn_id); }
    }

    fn drop_current(&self, guard: &mut Option<CurrentClient>, why: &str) {
        if let Some(prev) = guard.take() {
            warn!("dropping a slow/wedged IPC client ({}) — it will replay from the ring on re-Attach", why);
            prev.reader_task.abort();
            prev.writer_task.abort();
        }
    }

    /// Mark client `id` (if it is still the installed one) as mid-replay or not.
    async fn set_replaying(&self, id: u64, on: bool) {
        let mut g = self.current_client.lock().await;
        if let Some(c) = g.as_mut().filter(|c| c.id == id) {
            c.replaying = on;
            if !on { c.parking = false; c.pending.clear(); c.pending_status.clear(); c.inflight.clear(); }
        }
    }

    /// Take the frames parked for client `id` during its replay. When none are left,
    /// atomically (same lock hold) end the replay so later frames go straight to the
    /// queue again. `None` = nothing more to flush (or the client is gone/superseded).
    async fn take_parked(&self, id: u64) -> Option<VecDeque<OutFrame>> {
        let mut g = self.current_client.lock().await;
        let c = g.as_mut().filter(|c| c.id == id)?;
        if c.parked.is_empty() {
            c.replaying = false;
            c.parking = false;
            c.pending.clear();
            c.pending_status.clear();
            c.inflight.clear();
            return None;
        }
        c.parked_bytes = 0;
        Some(std::mem::take(&mut c.parked))
    }

    /// The reader of client `id` stopped (EOF, read error, oversized/garbled frame,
    /// stalled prefix/body). If that client is still installed, uninstall it and stop
    /// its writer so the socket closes: the web sees EOF and reconnects + re-Attaches.
    /// Leaving it installed (the old behaviour) kept streaming events to a web whose
    /// every later Send/Dial/Drop went unread — a silent black hole.
    async fn detach_client(&self, id: u64) {
        let mut g = self.current_client.lock().await;
        if g.as_ref().map_or(false, |c| c.id == id) {
            if let Some(c) = g.take() {
                info!("IPC client reader ended — closing that client");
                c.writer_task.abort();
                // reader_task is the caller itself (already finishing); just detach it.
            }
        }
    }
}

/// Run the daemon's IPC listener forever. `sock_path` is unlinked first (a
/// stale socket file left behind by an unclean prior exit would otherwise
/// make `bind()` fail) and the resulting socket is chmod'd 0600 — both
/// processes run as the same user, so this is a lifecycle boundary, not a
/// privilege one, but the socket still shouldn't be reachable by any other
/// local user on the box.
/// r5 (codex P4 update.sh:1859, daemon side): a custom socket directory (e.g. one under /run,
/// a tmpfs) is gone after a reboot, and binding then failed forever. Create a MISSING parent
/// directory (and missing ancestors) with mode 0700 — this process's own euid, which the web
/// shares (SO_PEERCRED). An existing directory is used as it is: never chmod'ed or chown'ed
/// (it may be a system or operator-managed directory). Where the parent cannot be created
/// (no write access to its parent, e.g. /run as an unprivileged user) the unit has to provide
/// it (RuntimeDirectory / tmpfiles.d) — the bind error then says why.
fn ensure_socket_parent(sock_path: &str) -> Result<()> {
    let Some(parent) = std::path::Path::new(sock_path).parent() else { return Ok(()) };
    if parent.as_os_str().is_empty() || std::fs::symlink_metadata(parent).is_ok() { return Ok(()); }
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(parent)
        .map_err(|e| anyhow::anyhow!("cannot create the socket directory {}: {}", parent.display(), e))?;
    info!("created the missing socket directory {} (mode 0700)", parent.display());
    Ok(())
}

pub async fn run(sock_path: &str) -> Result<()> {
    // Only unlink a leftover socket — never blindly `remove_file` an arbitrary path
    // (a symlink or a real file at the socket path could be a hijack). If something
    // that ISN'T a socket sits there, refuse rather than delete it.
    match std::fs::symlink_metadata(sock_path) {
        Ok(md) => {
            use std::os::unix::fs::FileTypeExt;
            if md.file_type().is_socket() {
                let _ = std::fs::remove_file(sock_path);
            } else {
                anyhow::bail!("refusing to start: {} exists and is not a socket", sock_path);
            }
        }
        Err(_) => { /* nothing there — fine */ }
    }
    ensure_socket_parent(sock_path)?;
    let listener = UnixListener::bind(sock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    info!("irc-core IPC listening on {}", sock_path);

    let daemon = Arc::new(Daemon::new());

    // Tell systemd we're up (Type=notify), then start the watchdog heartbeat.
    sd_notify("READY=1\nSTATUS=listening");
    spawn_watchdog(daemon.clone());

    // Graceful shutdown on SIGTERM/SIGINT: QUIT every connection, unlink the socket.
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|e| anyhow::anyhow!("SIGTERM handler: {e}"))?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|e| anyhow::anyhow!("SIGINT handler: {e}"))?;

    loop {
        tokio::select! {
            res = listener.accept() => {
                match res {
                    Ok((stream, _addr)) => {
                        // Enforce the trust boundary in code, not just on the socket's
                        // 0600 mode bits: only the daemon's own euid may drive IRC.
                        let our_euid = unsafe { libc::geteuid() };
                        match peer_euid(&stream) {
                            Some(uid) if uid == our_euid => {
                                info!("New IPC client connected");
                                let daemon = daemon.clone();
                                tokio::spawn(async move { accept_client(stream, daemon).await; });
                            }
                            Some(uid) => warn!("rejecting IPC client: peer euid {} != {}", uid, our_euid),
                            None => warn!("rejecting IPC client: could not read peer credentials"),
                        }
                    }
                    // The accept loop must be INFINITE and error-swallowing. A transient
                    // EMFILE/ECONNABORTED/EINTR must never propagate to process exit — that
                    // would tear down every held TLS socket. Log, brief backoff, keep going.
                    Err(e) => {
                        warn!("IPC accept error (continuing): {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
            _ = sigterm.recv() => { graceful_shutdown(&daemon, sock_path).await; return Ok(()); }
            _ = sigint.recv()  => { graceful_shutdown(&daemon, sock_path).await; return Ok(()); }
        }
    }
}

/// Send QUIT to every owned connection, give the QUITs a moment to flush, then
/// unlink the socket. Bounded well within the unit's TimeoutStopSec.
async fn graceful_shutdown(daemon: &Arc<Daemon>, sock_path: &str) {
    info!("shutdown signal — QUITing {} connection(s)", daemon.conns.len());
    for e in daemon.conns.iter() {
        let _ = e.value().cmd_tx.try_send(DaemonCmd::Drop("Server shutting down".into()));
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _ = std::fs::remove_file(sock_path);
}

/// systemd watchdog heartbeat. Emits `WATCHDOG=1` only while the tokio RUNTIME is
/// demonstrably alive: this task's timer fires AND it can acquire the central
/// `current_client` lock within a 5s bound. That catches the catastrophic hang class
/// for an async daemon — a wedged executor, all worker threads blocked on a syscall,
/// a deadlock that permanently holds `current_client` — after which systemd
/// (`WatchdogSec`) kills + restarts. It is the ONLY backstop for a hung-but-alive
/// daemon and cannot be added after the binary is frozen.
///
/// It deliberately does NOT gate on a per-connection / accept-loop progress COUNTER.
/// A counter can't advance on a legitimately IDLE daemon (no IRC traffic, no web
/// activity), so gating on it would starve the keepalive and make systemd restart a
/// perfectly healthy idle daemon — the exact unwanted restart this whole deployment
/// exists to avoid. Logic-level per-loop hangs are instead designed out upstream with
/// hard timeouts on every await that could block (READ/CONNECT/REG/WRITE/PONG). So
/// the guarantee here is precisely "runtime responsive," not "every loop progressing."
fn spawn_watchdog(daemon: Arc<Daemon>) {
    // WATCHDOG_USEC is exported by systemd when WatchdogSec is set. Heartbeat at ~1/3
    // of it. Absent (local run) → a harmless default; sd_notify no-ops with no socket.
    let interval = std::env::var("WATCHDOG_USEC").ok().and_then(|s| s.parse::<u64>().ok())
        .map(|usec| Duration::from_micros((usec / 3).max(1_000_000)))
        .unwrap_or(Duration::from_secs(20));
    tokio::spawn(async move {
        let mut tick: u64 = 0;
        loop {
            tokio::time::sleep(interval).await;
            let progress = tokio::time::timeout(Duration::from_secs(5), async {
                let _g = daemon.current_client.lock().await;
            }).await.is_ok();
            let conns = daemon.conns.len();
            if progress {
                sd_notify(&format!("WATCHDOG=1\nSTATUS=ok — {conns} connection(s) owned"));
            } else {
                warn!(target: "irc_core", event = "watchdog_stall", "central lock stalled — withholding keepalive (systemd will restart)");
            }
            tick = tick.wrapping_add(1);
            if tick % 10 == 0 {
                info!(target: "irc_core", event = "health", conns = conns, progress = progress, "daemon health");
            }
        }
    });
}

/// Install `stream` as the current client, superseding (aborting) any prior
/// one, then run its reader loop inline (so this task's lifetime IS the
/// reader's — aborting from the NEXT `accept_client` call cleanly tears down
/// both halves).
async fn accept_client(stream: UnixStream, daemon: Arc<Daemon>) {
    let (mut read_half, write_half) = stream.into_split();
    // BOUNDED — a client that stops reading can't make this grow without bound.
    let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(OUT_QUEUE_CAP);
    let live_bytes = Arc::new(AtomicUsize::new(0));
    let acks = Arc::new(ClientAcks::default());

    let mut write_half = write_half;
    let live_for_writer = live_bytes.clone();
    let acks_for_writer = acks.clone();
    let writer_task = tokio::spawn(async move {
        // r4 C2-4: numbers the ring lines written to a `proc_ack` client (RawLine.seq).
        let mut seq: u64 = 0;
        while let Some(mut frame) = out_rx.recv().await {
            let tracked = frame.ack.is_some() && acks_for_writer.proc_ack.load(Ordering::Acquire);
            if tracked {
                seq += 1;
                if let IpcMessage::RawLine { seq: s, .. } = &mut frame.msg { *s = seq; }
            }
            // write_frame is bounded by WRITE_TIMEOUT, so a stuck peer can't wedge this
            // writer forever; an error (timeout or dead socket) ends the writer, which
            // drops out_rx → the next forward_live sees the channel Closed and drops the
            // client (closing #14: forward_live no longer buffers into a dead client).
            let res = write_frame(&mut write_half, &frame.msg).await;
            if frame.weight > 0 { live_for_writer.fetch_sub(frame.weight, Ordering::AcqRel); }
            if res.is_err() {
                break;
            }
            // Written: the line now counts as delivered (see RingEntry) — for a proc_ack
            // client once it acknowledges it. Frames still queued (or unacknowledged) when
            // this client goes away are not, and replay as backlog next time.
            if let Some(delivered) = frame.ack {
                if tracked { acks_for_writer.written(seq, delivered); } else { delivered.store(true, Ordering::Release); }
            }
        }
        // Half-close the write side promptly so the peer sees EOF.
        use tokio::io::AsyncWriteExt;
        let _ = write_half.shutdown().await;
    });

    // Gate the reader behind a oneshot so it cannot process even its very
    // first frame (this client's own `Attach`) until AFTER this client has
    // been installed as `current_client` below. Without this gate, a
    // `tokio::spawn`'d reader can get scheduled and start running before the
    // current_client swap section below runs — a live event racing that
    // window would resolve `current_client` to the OLD (about-to-be-
    // superseded) client instead of this one, either misdelivering or
    // losing it. See `update_cache_and_forward`'s doc comment for the
    // matching fix on the cache-write side of this same race.
    let (start_tx, start_rx) = tokio::sync::oneshot::channel::<()>();
    let client_id = CLIENT_SEQ.fetch_add(1, Ordering::Relaxed);
    let daemon_for_reader = daemon.clone();
    let out_tx_for_reader = out_tx.clone();
    let acks_for_reader = acks.clone();
    let reader_task = tokio::spawn(async move {
        if start_rx.await.is_err() { return; } // accept_client gave up before releasing us
        loop {
            match read_frame(&mut read_half).await {
                Ok(Some(msg)) => handle_message(msg, &daemon_for_reader, &out_tx_for_reader, client_id, &acks_for_reader).await,
                Ok(None) => { info!("IPC client disconnected (clean EOF)"); break; }
                Err(e) => { warn!("IPC client read error: {}", e); break; }
            }
        }
        daemon_for_reader.detach_client(client_id).await;
    });

    // Supersede any prior client — abort its tasks (closing its socket
    // halves) before installing this one. Held only long enough to swap.
    {
        let mut current = daemon.current_client.lock().await;
        if let Some(prev) = current.take() {
            prev.reader_task.abort();
            prev.writer_task.abort();
        }
        *current = Some(CurrentClient {
            id: client_id, out_tx, live_bytes, reader_task, writer_task,
            replaying: false, parking: false, parked: VecDeque::new(), parked_bytes: 0,
            pending: HashSet::new(), pending_status: HashMap::new(), inflight: HashSet::new(),
        });
    }
    // Only now release the reader — current_client already correctly points
    // at this client, so its first frame (Attach) and any live event racing
    // it resolve unambiguously instead of racing the swap above.
    let _ = start_tx.send(());
}

async fn handle_message(msg: IpcMessage, daemon: &Arc<Daemon>, out_tx: &mpsc::Sender<OutFrame>, client_id: u64, acks: &ClientAcks) {
    match msg {
        IpcMessage::Attach { version, build, features } => {
            info!("Attach received — replaying {} known connection(s)", daemon.conns.len());
            // r4: what this web supports — before any replay frame is written, so the
            // whole replay is numbered for a proc_ack client (C2-4).
            acks.set_features(&features);
            // Cache the announcing web binary's version/build for future CTCP VERSION
            // replies (a no-op if both are empty — a pre-fix web binary's Attach; see
            // `WebVersionCell::set`).
            daemon.web_version.set(version, build);
            // From here until the park is flushed, a full out-queue means "replay in
            // progress", not "wedged client" — see forward_live. Every connection owned
            // right now is "pending" until its own replay is queued (codex P2 :299).
            daemon.prune_ended().await;
            let snapshots = daemon.begin_replay(client_id).await.unwrap_or_default();
            // Version handshake first, so a newer web binary can learn what this
            // (possibly frozen) daemon supports.
            let _ = out_tx.send(OutFrame::plain(IpcMessage::Hello {
                proto_version: IPC_PROTO_VERSION,
                features: DAEMON_FEATURES.iter().map(|f| f.to_string()).collect(),
            })).await;
            // M6: the (conn_id, cache) list was collected OUT of the DashMap iterator (in
            // begin_replay); no shard lock is held across the awaits below.
            for (conn_id, snap_cache) in snapshots {
                replay_conn(daemon, client_id, out_tx, &conn_id, snap_cache).await;
            }
            // Flush live frames parked while the replay owned the queue, in arrival
            // order, then (inside take_parked, under the lock) resume direct forwarding.
            // Frames parked during a flush are picked up by the next round. Before each
            // round, let the web consume most of what is queued: right after the last
            // replay frame is enqueued the queue is still FULL of replay, and going back
            // to drop-on-full then would drop a perfectly healthy client on the very next
            // live line. (A wedged web can't pin this: its writer times out after
            // WRITE_TIMEOUT, which closes the channel.)
            'flush: loop {
                while out_tx.capacity() < out_tx.max_capacity() / 2 && !out_tx.is_closed() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                let Some(batch) = daemon.take_parked(client_id).await else { break };
                for m in batch {
                    if out_tx.send(m).await.is_err() {
                        // Writer gone: nothing more can reach this client.
                        daemon.set_replaying(client_id, false).await;
                        break 'flush;
                    }
                }
            }
            // Marks "that's everything" so the client can safely diff against
            // what it expected and re-Dial anything missing.
            let _ = out_tx.send(OutFrame::plain(IpcMessage::AttachComplete {})).await;
        }

        IpcMessage::Dial { conn_id, params } => {
            // G8: a Dial for an already-owned conn_id REPLACES it (drop old, dial new)
            // rather than being a hard no-op. This is the ONLY in-band path for a frozen
            // daemon to pick up a renewed client certificate before the old one expires
            // (the cert is captured in DialParams at Dial time), and it also resolves the
            // Drop-then-Dial race. The old task's ConnGuard won't clobber the new entry
            // (generation token).
            if let Some(h) = daemon.conns.get(&conn_id) {
                warn!("[{}] Dial for an owned conn_id — replacing (drop old, dial new)", conn_id);
                let _ = h.cmd_tx.try_send(DaemonCmd::Drop("Replaced by new dial".into()));
                drop(h);
                daemon.conns.remove(&conn_id);
            }
            daemon.ended.remove(&conn_id);   // r5: a new session replaces the ended one
            spawn_connection(daemon.clone(), conn_id, *params).await;
        }

        IpcMessage::RawSend { conn_id, line } => {
            match daemon.conns.get(&conn_id) {
                // F2: if the bounded cmd queue is full (a long write-stall backing up
                // >CMD_QUEUE_CAP lines), the line is dropped — log it rather than dropping
                // silently, so the loss is observable (the web-side connected-check surfaces
                // the reconnect case to the user; this covers the queue-full case).
                // codex P2 ipc_server.rs:745: the queue was bounded by COUNT only, and a line
                // by nothing but the 64 KiB IPC frame — 1,024 × ~60 KiB per connection. Lines
                // are now cut to the IRC limits (what the server keeps anyway) and the queued
                // bytes are budgeted per connection and daemon-wide.
                // r4 (codex P1 main.rs:5882): every drop is also reported to a web that
                // understands SendDropped — it already echoed the line as sent.
                Some(h) => {
                    let dropped = match cap_outbound_line(&line) {
                        None => {
                            warn!("[{}] dropping web RawSend — tag section over the IRC limit", conn_id);
                            Some("its IRCv3 tag section is over the IRC limit")
                        }
                        Some(capped) => match QueuedLine::charge(capped, h.raw_bytes.clone()) {
                            None => {
                                warn!("[{}] dropping web RawSend — queued-bytes budget exhausted (peer write stalled?)", conn_id);
                                Some("the network's send queue is full (the IRC server is not reading)")
                            }
                            Some(q) => {
                                if h.cmd_tx.try_send(DaemonCmd::RawSend(q)).is_err() {
                                    warn!("[{}] dropping web RawSend — command queue full (peer write stalled?)", conn_id);
                                    Some("the network's send queue is full (the IRC server is not reading)")
                                } else { None }
                            }
                        },
                    };
                    drop(h);
                    if let Some(why) = dropped { report_send_dropped(acks, out_tx, &conn_id, &line, why); }
                }
                None => {
                    warn!("[{}] RawSend for unknown conn_id — dropped", conn_id);
                    report_send_dropped(acks, out_tx, &conn_id, &line, "irc-core has no live connection for this network");
                }
            }
        }

        // r4 C2-4: the client processed every ring line up to `upto`.
        IpcMessage::Processed { upto } => acks.processed(upto),
        // r5: hold-aware acknowledgements (codex P2 ipc_client.rs:293).
        IpcMessage::Held { seqs } => acks.hold(&seqs),
        IpcMessage::Released { seqs } => acks.release(&seqs),

        IpcMessage::Drop { conn_id, reason } => {
            // Send QUIT AND synchronously drop the entry so an immediately-following Dial
            // (disconnect-then-reconnect) isn't rejected as "already owned" (the old task
            // finishes its QUIT independently; its ConnGuard's token-gated remove is a
            // no-op once we've removed here).
            if let Some(h) = daemon.conns.get(&conn_id) {
                let _ = h.cmd_tx.try_send(DaemonCmd::Drop(reason));
                drop(h);
                daemon.conns.remove(&conn_id);
            } else {
                warn!("[{}] Drop for unknown conn_id — nothing to do", conn_id);
            }
        }

        IpcMessage::DaemonControl { conn_id, verb, args } => {
            // Reserved control channel. Handle known verbs; IGNORE (log) unknown ones so
            // a newer web binary can issue a verb this frozen daemon predates.
            match verb.as_str() {
                "reconnect"  => { if let Some(h) = daemon.conns.get(&conn_id) { let _ = h.cmd_tx.try_send(DaemonCmd::Reconnect); } }
                "rearm_sasl" => { if let Some(h) = daemon.conns.get(&conn_id) { let _ = h.cmd_tx.try_send(DaemonCmd::RearmSasl); } }
                other => info!("[{}] DaemonControl: ignoring unknown verb {:?} args={:?}", conn_id, other, args),
            }
        }

        // Version handshake from the web side — informational.
        IpcMessage::Hello { proto_version, .. } => {
            info!("web client Hello: proto_version={}", proto_version);
        }

        // A message type this frozen daemon doesn't know (added by a newer web binary).
        IpcMessage::Unknown => { /* ignore — never tear down the connection over it */ }

        // Daemon never receives its own outbound variants.
        IpcMessage::RawLine { .. } | IpcMessage::ConnStatus { .. } | IpcMessage::SessionSync { .. }
        | IpcMessage::AttachComplete {} | IpcMessage::SendDropped { .. } => {}
    }
}

/// Queue one connection's Attach replay for client `client_id` (see the Attach handler).
async fn replay_conn(daemon: &Arc<Daemon>, client_id: u64, out_tx: &mpsc::Sender<OutFrame>, conn_id: &str, snap_cache: Arc<Mutex<ConnCache>>) {
    // The connection's CURRENT cache: a Dial-replace during the replay swapped in a new
    // one (its lines went there); an ended connection has none left, so its last
    // history is still replayed from the snapshot's cache.
    let current = daemon.conns.get(conn_id).map(|h| h.cache.clone());
    let ended = current.is_none();
    // r5: an ended connection retained in `ended` (it ended before this Attach): after its
    // history comes its terminal Disconnected, so the web logs the lines and then drops it.
    let retained = ended && daemon.ended.contains_key(conn_id);
    let cache = current.unwrap_or(snap_cache);
    // Take the replay under the connection's cache lock and, in the SAME hold, move the
    // connection from "pending" to "in flight": its live consumer (update_cache_and_forward)
    // pushes + forwards under that lock, so every line is either in this replay or newer
    // and then parked behind it — nothing of this connection can overtake or interleave
    // with its own history. The lock is released before the frames are queued (codex P2
    // ipc_server.rs:803): holding it across the blocking sends stalled the consumer behind
    // a slow web, and its emit queue grew meanwhile.
    let (mut held, frames) = {
        let c = cache.lock().await;
        let held = daemon.begin_conn_replay(client_id, conn_id).await;
        (held, c.replay_frames(conn_id))
    };
    if retained && !held.iter().any(|m| matches!(m, IpcMessage::ConnStatus { state: ConnLifecycle::Disconnected { .. }, .. })) {
        let reason = cache.lock().await.last_disconnect.clone();
        let reason = if reason.is_empty() { "connection ended".to_string() } else { reason };
        held.push(IpcMessage::ConnStatus { conn_id: conn_id.to_string(), state: ConnLifecycle::Disconnected { reason } });
    }
    // A live connection: its held lifecycle events first — the snapshot below already
    // reflects them. One that ENDED meanwhile: history first, then its terminal
    // Disconnected, so the web doesn't take the snapshot as "alive".
    'send: {
        if !ended {
            for m in &held { if out_tx.send(OutFrame::plain(m.clone())).await.is_err() { break 'send; } }
        }
        for f in frames {
            if out_tx.send(f).await.is_err() { break 'send; }
        }
        if ended {
            for m in &held { if out_tx.send(OutFrame::plain(m.clone())).await.is_err() { break 'send; } }
        }
    }
    daemon.end_conn_replay(client_id, conn_id).await;
}

/// Atomically claim `conn_id` (via `DashMap::entry`, so two near-simultaneous
/// `Dial`s for the same conn_id can never both spawn a task) and start its
/// `run_connection` loop. The spawned task removes its own entry from
/// `conns` when `run_connection` returns (Drop-requested or
/// auto_reconnect=false) — self-cleanup, no separate reaper needed.
async fn spawn_connection(daemon: Arc<Daemon>, conn_id: String, params: DialParams) {
    use dashmap::mapref::entry::Entry;
    let token = CONN_SEQ.fetch_add(1, Ordering::Relaxed);
    let (cmd_tx, cmd_rx) = mpsc::channel(CMD_QUEUE_CAP); // bounded (web→conn command flood guard)
    // (Field-assign, not `..Default::default()`: ConnCache has a Drop impl.)
    let mut fresh = ConnCache::default();
    fresh.nick = params.nick.clone();
    fresh.dial_server = crate::irc_daemon::clean_dial_server(&params.server);
    fresh.dial_port = if fresh.dial_server.is_empty() { 0 } else { params.port };
    let cache = Arc::new(Mutex::new(fresh));

    match daemon.conns.entry(conn_id.clone()) {
        Entry::Occupied(_) => {
            warn!("[{}] Dial raced with an existing entry — ignoring (already owned)", conn_id);
            return;
        }
        Entry::Vacant(v) => {
            v.insert(ConnHandle { cmd_tx, cache: cache.clone(), raw_bytes: Arc::new(AtomicUsize::new(0)), token });
            daemon.latest_token.insert(conn_id.clone(), token);
        }
    }

    // IRC wire order matters (a JOIN must be visible before the NAMES/MODE
    // that follow it) — `emit` must therefore preserve strict FIFO order.
    // A naive `tokio::spawn` per call does NOT: tokio gives no ordering
    // guarantee between independently spawned tasks, so a burst of lines
    // (registration/MOTD/join, all read back-to-back with ~zero inter-line
    // delay) would scramble on delivery — caught live: a channel PART
    // arrived before its own JOIN in a real test run. Fix: `emit` only ever
    // does a synchronous, ordering-preserving `send` onto a channel; ONE
    // dedicated consumer task drains it and does the async cache-update +
    // live-forward work strictly in enqueue order.
    // ONE strictly-FIFO emit queue (codex P2 ipc_server.rs:796). There used to be two —
    // a bounded one for RawLine and an unbounded one for SessionSync/ConnStatus — with a
    // `biased` consumer that served the control queue first. That reordered events (a
    // SessionSync emitted AFTER its JOIN line overtook it, re-creating the placeholder +
    // resync burst the JOIN-first emit order exists to avoid) and, when the connection
    // ended, the consumer exited as soon as the control queue closed, discarding the
    // final lines still queued (a last PRIVMSG before the server closed).
    // The shed policy is kept with a counter: `emit` is a SYNC closure called from
    // run_connection's read loop and can't block, so a RawLine is shed (with a warn)
    // while EMIT_QUEUE_CAP lines are already waiting; lifecycle messages are never shed
    // (they are the reattach cache's only writers) and are low-volume.
    // SessionSync (codex P2 ipc_server.rs:862): a full snapshot (up to ~60 KiB) that used
    // to be queued unbounded, one per membership change — a server alternating self-JOIN/
    // PART while the consumer waited could pile up unbounded memory. A snapshot supersedes
    // every older one, so only the NEWEST is kept (in `slot`) and the queue carries small
    // position markers: the marker that is current when the consumer reaches it delivers
    // the snapshot at exactly the queue position it was emitted at (after the lines that
    // preceded it); older, superseded markers are skipped.
    let (emit_tx, mut emit_rx) = mpsc::unbounded_channel::<EmitItem>();
    let slot = Arc::new(SyncSlot::default());
    let slot_for_emit = slot.clone();
    let queued_lines = Arc::new(AtomicUsize::new(0));
    let queued_for_emit = queued_lines.clone();
    let emit_conn = conn_id.clone();
    let terminal_sent = Arc::new(AtomicBool::new(false));
    let terminal_for_emit = terminal_sent.clone();
    let emit = move |msg: IpcMessage| {
        if matches!(msg, IpcMessage::ConnStatus { state: ConnLifecycle::Disconnected { .. }, .. }) {
            terminal_for_emit.store(true, Ordering::Release);
        }
        if matches!(msg, IpcMessage::SessionSync { .. }) {
            slot_for_emit.put(msg, &emit_tx);
            return;
        }
        if matches!(msg, IpcMessage::RawLine { .. }) {
            if queued_for_emit.fetch_add(1, Ordering::AcqRel) >= EMIT_QUEUE_CAP {
                queued_for_emit.fetch_sub(1, Ordering::AcqRel);
                // Shedding one line under extreme backpressure (the consumer stalled on
                // the cache lock while a flood arrived — the inbound token bucket makes
                // that nearly impossible) beats growing without bound; the ring stays in
                // order because only the consumer writes it. Logged, never silent.
                warn!(target: "irc_core", event = "emit_shed", conn_id = %emit_conn, "emit live-forward queue full — dropping a line (ring stays in-order)");
                return;
            }
        }
        let _ = emit_tx.send(EmitItem::Msg(msg));
    };

    // run_connection task, wrapped in a ConnGuard so a panic (or normal return) always
    // removes the (token-matched) entry and notifies the web — no orphaned zombie conn.
    let run_daemon = daemon.clone();
    let run_conn_id = conn_id.clone();
    let web_version = daemon.web_version.clone();
    let run_handle = tokio::spawn(async move {
        let _guard = ConnGuard { daemon: run_daemon, conn_id: run_conn_id.clone(), token, terminal_sent };
        run_connection(run_conn_id, params, emit, cmd_rx, web_version).await;
    });

    // Emit consumer. Holds AbortOnDrop(run_handle): if this consumer ever exits — the
    // queue closed (run_connection ended and every queued message was processed, in
    // order) OR the consumer itself panics — it tears down run_connection too, so a
    // "socket alive but web deaf/blind" half-dead connection can never persist.
    let daemon_for_consumer = daemon.clone();
    let cache_for_consumer = cache.clone();
    let consumer_conn_id = conn_id.clone();
    tokio::spawn(async move {
        let _abort = AbortOnDrop(run_handle);
        while let Some(item) = emit_rx.recv().await {
            let msg = match item {
                EmitItem::Msg(msg) => {
                    if matches!(msg, IpcMessage::RawLine { .. }) {
                        queued_lines.fetch_sub(1, Ordering::AcqRel);
                    }
                    msg
                }
                EmitItem::Sync(seq) => match slot.take_for(seq) {
                    Some(msg) => msg,
                    None => continue, // superseded by a newer snapshot further down the queue
                },
            };
            update_cache_and_forward(&cache_for_consumer, &daemon_for_consumer, &consumer_conn_id, token, msg).await;
        }
    });
}

/// One entry of a connection's emit queue: a message, or the position marker of a
/// coalesced SessionSync (see SyncSlot).
enum EmitItem {
    Msg(IpcMessage),
    Sync(u64),
}

/// Bound on queued snapshot markers (each a few bytes); past it the newest snapshot is
/// still kept and delivered at the last queued marker.
const SYNC_MARKER_CAP: usize = EMIT_QUEUE_CAP;

/// The newest not-yet-consumed SessionSync of a connection plus the count of its
/// position markers in the emit queue. Only the run_connection task puts, only the
/// consumer takes.
#[derive(Default)]
struct SyncSlot {
    latest: std::sync::Mutex<Option<(u64, IpcMessage)>>,
    markers: AtomicUsize,
    seq: AtomicU64,
}

impl SyncSlot {
    /// Emitter side: make `msg` the newest snapshot and queue its position marker. The
    /// marker count is raised BEFORE the slot is replaced, so a consumer that sees a newer
    /// snapshot than its own marker always also sees that newer marker counted (and skips).
    fn put(&self, msg: IpcMessage, tx: &mpsc::UnboundedSender<EmitItem>) {
        let seq = self.seq.fetch_add(1, Ordering::AcqRel) + 1;
        let queue_marker = self.markers.load(Ordering::Acquire) < SYNC_MARKER_CAP;
        if queue_marker { self.markers.fetch_add(1, Ordering::AcqRel); }
        *self.latest.lock().unwrap_or_else(|e| e.into_inner()) = Some((seq, msg));
        if queue_marker && tx.send(EmitItem::Sync(seq)).is_err() {
            self.markers.fetch_sub(1, Ordering::AcqRel);
        }
    }

    /// Consumer side, at marker `seq`: the snapshot to deliver here, if this marker is the
    /// newest one (or the last one queued — past SYNC_MARKER_CAP); None = superseded.
    fn take_for(&self, seq: u64) -> Option<IpcMessage> {
        let remaining = self.markers.fetch_sub(1, Ordering::AcqRel).saturating_sub(1);
        let mut latest = self.latest.lock().unwrap_or_else(|e| e.into_inner());
        match latest.as_ref() {
            Some((s, _)) if *s == seq || remaining == 0 => latest.take().map(|(_, m)| m),
            _ => None,
        }
    }
}

/// Keep the conn_id's cache in sync with everything the connection task
/// emits (ring-buffer the forwarded lines, track the last known nick/channel/
/// lag snapshot, downgrade connected/registered on any lifecycle event that
/// means the socket isn't currently up), THEN forward the message live —
/// all under the SAME cache-lock hold.
///
/// This used to be two separate calls (`update_cache(...).await` then
/// `daemon.forward_live(msg).await`), each independently locking/unlocking.
/// That left a window where a concurrent `Attach`'s replay (which also locks
/// this same cache to build its snapshot, see `replay_messages`) could run
/// between the two: the line would already be in the ring (so the replay
/// includes it) AND then also get delivered live — a double delivery to
/// whichever client the Attach just installed as current. Holding the cache
/// lock across both steps makes "this line is in the ring" and "this line
/// was (or wasn't) live-forwarded" a single atomic fact from a concurrent
/// Attach's point of view: either the whole push-then-forward already
/// happened before the Attach's replay snapshot (line is in the ring, was
/// forwarded to whoever was current AT THAT MOMENT — not necessarily this
/// Attach's new client) or it happens after (line isn't in the replay
/// snapshot, forward_live's `current_client` lookup — by then already
/// updated to the new client, since `accept_client` installs it before its
/// reader can process the `Attach` that triggers this replay — delivers it
/// live exactly once). Either way, the newly-attached client sees it once.
async fn update_cache_and_forward(cache: &Arc<Mutex<ConnCache>>, daemon: &Arc<Daemon>, conn_id: &str, token: u64, msg: IpcMessage) {
    let mut c = cache.lock().await;
    let mut ack: Option<Arc<AtomicBool>> = None;
    match &msg {
        IpcMessage::RawLine { line, recv_ts, .. } => {
            let ts = if *recv_ts > 0 { *recv_ts } else { chrono::Utc::now().timestamp() };
            ack = Some(c.push_line_at(line.clone(), ts));
        }
        IpcMessage::SessionSync { nick, channels, registered, connected, lag_ms, message_tags, echo_message_enabled, self_userhost, casemapping, dial_server, dial_port, chanmodes, .. } => {
            c.nick = nick.clone();
            c.channels = channels.clone();
            c.registered = *registered;
            c.connected = *connected;
            c.lag_ms = *lag_ms;
            c.message_tags = *message_tags;
            c.echo_message_enabled = *echo_message_enabled;
            if !self_userhost.is_empty() { c.self_userhost = self_userhost.clone(); }
            if !casemapping.is_empty() { c.casemapping = casemapping.clone(); }
            if !dial_server.is_empty() { c.dial_server = dial_server.clone(); c.dial_port = *dial_port; }
            if chanmodes.is_some() { c.chanmodes = chanmodes.clone(); }
        }
        IpcMessage::ConnStatus { state, .. } => match state {
            ConnLifecycle::Connecting => { c.connected = false; }
            ConnLifecycle::Reconnecting { .. } => {
                c.connected = false;
                c.registered = false;
            }
            ConnLifecycle::Disconnected { reason } => {
                c.connected = false;
                c.registered = false;
                c.last_disconnect = reason.clone();
            }
        },
        _ => {}
    }
    // Suppress the live-forward if THIS task's generation has been SUPERSEDED: after a
    // Dial-replace (cert renewal) or Drop-then-Dial, a newer connection owns this
    // conn_id under a different token. Forwarding this old task's messages — above all
    // its terminal `Disconnected` — would desync the web into showing the live
    // REPLACEMENT as disconnected until the next SessionSync (the generation token
    // protects the `conns` map entry, but NOT outbound status). A plain Drop leaves NO
    // entry (`None`), so its legitimate Disconnected still forwards. The cache is still
    // updated above either way (harmless for a superseded, now-orphaned cache).
    //
    // Deliberately still holding `c` (the cache lock) across this send — see the
    // function doc comment for why that's what closes the concurrent-Attach race. The
    // `conns.get` here is a brief DashMap read released within the guard; no lock-order
    // inversion (nothing holds a conns shard while awaiting this cache lock).
    // r9 (astra P2 ipc_server.rs:1386): also once a newer task was started for this conn_id at
    // all (latest_token) — the `conns` check alone let the old task forward again as soon as
    // its replacement exited and removed its entry.
    let superseded = matches!(daemon.conns.get(conn_id), Some(h) if h.token != token)
        || daemon.latest_token.get(conn_id).is_some_and(|t| *t != token);
    if !superseded {
        daemon.forward_live(OutFrame { msg, ack, weight: 0 }).await;
    }
    drop(c);
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    fn live(i: usize) -> OutFrame {
        OutFrame::plain(IpcMessage::RawLine { conn_id: "c".into(), line: format!("live {i}"), replayed: false, backlog: false, recv_ts: 0, seq: 0 })
    }

    fn test_client(id: u64, cap: usize) -> (CurrentClient, mpsc::Receiver<OutFrame>) {
        let (out_tx, rx) = mpsc::channel(cap);
        (CurrentClient {
            id, out_tx, live_bytes: Arc::new(AtomicUsize::new(0)), reader_task: tokio::spawn(async {}), writer_task: tokio::spawn(async {}),
            replaying: false, parking: false, parked: VecDeque::new(), parked_bytes: 0,
            pending: HashSet::new(), pending_status: HashMap::new(), inflight: HashSet::new(),
        }, rx)
    }

    fn handle(cmd_tx: mpsc::Sender<DaemonCmd>, cache: Arc<Mutex<ConnCache>>, token: u64) -> ConnHandle {
        ConnHandle { cmd_tx, cache, raw_bytes: Arc::new(AtomicUsize::new(0)), token }
    }

    /// What the real writer does after writing a frame.
    fn written(f: OutFrame) -> IpcMessage {
        if let Some(delivered) = f.ack { delivered.store(true, Ordering::Release); }
        f.msg
    }

    fn line_of(f: &OutFrame) -> String {
        match &f.msg { IpcMessage::RawLine { line, .. } => line.clone(), other => format!("{:?}", other) }
    }

    #[test]
    fn ring_is_capped_by_lines_and_bytes() {
        let mut small = ConnCache::default();
        for i in 0..(RING_CAP + 50) { small.push_line(format!(":n!u@h PRIVMSG #c :small {i}")); }
        assert_eq!(small.ring.len(), RING_CAP, "normal-size lines stay line-capped (unchanged)");
        assert_eq!(small.ring.back().unwrap().line, format!(":n!u@h PRIVMSG #c :small {}", RING_CAP + 49));

        // The audit's t_mem pattern: 8 KiB lines used to pin 2000 x 8 KiB per connection.
        let mut big = ConnCache::default();
        let line = "x".repeat(crate::ircproto::MAX_IRC_LINE_LEN);
        for _ in 0..RING_CAP { big.push_line(line.clone()); }
        assert!(big.ring_bytes <= RING_BYTE_CAP, "ring_bytes {} > cap {}", big.ring_bytes, RING_BYTE_CAP);
        assert!(big.ring.len() < RING_CAP / 10);
        let sum: usize = big.ring.iter().map(|l| l.line.len() + RING_ENTRY_OVERHEAD).sum();
        assert_eq!(sum, big.ring_bytes, "byte accounting must stay exact");

        // A single line bigger than any cap is still kept (newest line always kept).
        let mut one = ConnCache::default();
        one.push_line("y".repeat(RING_BYTE_CAP + 10));
        assert_eq!(one.ring.len(), 1);
    }

    fn status(id: &str) -> IpcMessage {
        IpcMessage::ConnStatus { conn_id: id.into(), state: ConnLifecycle::Reconnecting { attempt: 1, delay_secs: 5, reason: "t".into() } }
    }
    fn raw(id: &str, line: &str) -> IpcMessage {
        IpcMessage::RawLine { conn_id: id.into(), line: line.into(), replayed: false, backlog: false, recv_ts: 1_700_000_000, seq: 0 }
    }

    /// codex P2 ipc_server.rs:299 + irc.rs:359: a connection's live frames never go out
    /// ahead of (or duplicated with) its own Attach replay; lines no web ever received
    /// are replayed as backlog (and only once).
    #[tokio::test]
    async fn pending_replay_orders_live_frames_and_marks_backlog() {
        let d = Arc::new(Daemon::new());
        let mut cache = ConnCache::default();
        // old 1/2 were written to an earlier web; missed 3 arrived while none was attached.
        cache.push_line_at("old 1".into(), 1).store(true, Ordering::Release);
        cache.push_line_at("old 2".into(), 2).store(true, Ordering::Release);
        cache.push_line("missed 3".into());
        let cache = Arc::new(Mutex::new(cache));
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        d.conns.insert("c0".into(), handle(cmd_tx, cache.clone(), 1));
        let (cl, mut rx) = test_client(9, 64);
        let out_tx = cl.out_tx.clone();
        *d.current_client.lock().await = Some(cl);
        let snaps = d.begin_replay(9).await.unwrap();
        // Live traffic for c0 while its replay is still pending (the real cache path).
        update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "live KICK 4")).await;
        d.forward_live(OutFrame::plain(status("c0"))).await;
        assert_eq!(d.current_client.lock().await.as_ref().unwrap().pending_status.get("c0").map(Vec::len), Some(1),
            "a lifecycle event is held, not lost");
        assert!(rx.try_recv().is_err(), "nothing of c0 may go out ahead of its replay");
        for (id, c) in snaps { replay_conn(&d, 9, &out_tx, &id, c).await; }
        let mut got = Vec::new();
        while let Ok(f) = rx.try_recv() { got.push(written(f)); }
        let shape: Vec<String> = got.iter().map(|m| match m {
            IpcMessage::ConnStatus { .. } => "status".to_string(),
            IpcMessage::SessionSync { .. } => "sync".to_string(),
            IpcMessage::RawLine { line, backlog, replayed, .. } => format!("{line}|r={replayed}|b={backlog}"),
            o => format!("{o:?}"),
        }).collect();
        assert_eq!(shape, vec![
            "status", "sync",
            "old 1|r=true|b=false", "old 2|r=true|b=false",
            "missed 3|r=true|b=true", "live KICK 4|r=true|b=true",
        ]);
        // After its replay c0 is live again: in order, delivered, never backlog again.
        update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "live 5")).await;
        let f = rx.try_recv().expect("live 5 forwarded");
        assert!(matches!(written(f), IpcMessage::RawLine { ref line, replayed: false, .. } if line == "live 5"));
        let c = cache.lock().await;
        assert!(c.ring.iter().all(|e| c.is_delivered(e)));
        assert_eq!(c.replay_frames("c0").iter()
            .filter(|f| matches!(f.msg, IpcMessage::RawLine { backlog: true, .. })).count(), 0);
    }

    /// r9 (astra P2 ipc_server.rs:1386): a superseded task stays silent after its replacement
    /// exited (no `conns` entry left); a task never replaced still forwards its own end.
    #[tokio::test]
    async fn a_superseded_task_never_forwards_again() {
        let d = Arc::new(Daemon::new());
        let (cl, mut rx) = test_client(1, 8);
        *d.current_client.lock().await = Some(cl);
        let old_cache = Arc::new(Mutex::new(ConnCache::default()));
        // Task 1 owned c0, then a Dial replaced it with task 2, which has exited since.
        d.latest_token.insert("c0".into(), 2);
        assert!(d.conns.get("c0").is_none());
        update_cache_and_forward(&old_cache, &d, "c0", 1, raw("c0", "late line of task 1")).await;
        assert!(rx.try_recv().is_err(), "the superseded task forwarded after its replacement exited");
        // The current task (and one never replaced) still forwards.
        update_cache_and_forward(&old_cache, &d, "c0", 2, raw("c0", "task 2")).await;
        assert!(matches!(written(rx.try_recv().unwrap()), IpcMessage::RawLine { ref line, .. } if line == "task 2"));
        update_cache_and_forward(&old_cache, &d, "c9", 7, raw("c9", "never replaced")).await;
        assert!(matches!(written(rx.try_recv().unwrap()), IpcMessage::RawLine { ref line, .. } if line == "never replaced"));
    }

    /// Lines forwarded while no web client is attached are undelivered (→ backlog later),
    /// and so is a line that was queued but never WRITTEN (codex P2 ipc_server.rs:979).
    #[tokio::test]
    async fn lines_count_as_delivered_only_once_written() {
        let d = Arc::new(Daemon::new());
        let cache = Arc::new(Mutex::new(ConnCache::default()));
        update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "x")).await;
        let (cl, mut rx) = test_client(1, 8);
        *d.current_client.lock().await = Some(cl);
        update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "y")).await;
        update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "z")).await;
        let flags = |c: &ConnCache| -> Vec<(String, bool, i64)> {
            c.ring.iter().map(|e| (e.line.clone(), c.is_delivered(e), e.recv_ts)).collect()
        };
        // y and z are queued, nothing written yet.
        assert_eq!(flags(&*cache.lock().await), vec![
            ("x".into(), false, 1_700_000_000), ("y".into(), false, 1_700_000_000), ("z".into(), false, 1_700_000_000)]);
        // The writer writes y, then the client is dropped with z still queued.
        let _ = written(rx.try_recv().unwrap());
        drop(rx);
        assert_eq!(flags(&*cache.lock().await), vec![
            ("x".into(), false, 1_700_000_000), ("y".into(), true, 1_700_000_000), ("z".into(), false, 1_700_000_000)]);
        // ...so a later replay hands z (and x) to the web as backlog, y as already seen.
        let backlog: Vec<(String, bool)> = cache.lock().await.replay_frames("c0").into_iter().filter_map(|f| match f.msg {
            IpcMessage::RawLine { line, backlog, .. } => Some((line, backlog)), _ => None }).collect();
        assert_eq!(backlog, vec![("x".into(), true), ("y".into(), false), ("z".into(), true)]);
    }

    fn snap(conn_id: &str, nick: &str, nchan: usize) -> IpcMessage {
        IpcMessage::SessionSync {
            conn_id: conn_id.into(), nick: nick.into(),
            channels: (0..nchan).map(|i| format!("#{:0>99}", i)).collect(),
            registered: true, connected: true, lag_ms: None, message_tags: false, echo_message_enabled: false,
            self_userhost: String::new(), casemapping: String::new(), dial_server: String::new(), dial_port: 0,
            chanmodes: None,
        }
    }

    /// codex P2 ipc_server.rs:862: snapshots no longer pile up in the emit queue. Only the
    /// newest is held; it is delivered at the position of the newest marker (after the
    /// lines emitted before it), superseded ones are skipped, and none overtakes a line.
    #[test]
    fn session_snapshots_coalesce_in_order() {
        let (tx, mut rx) = mpsc::unbounded_channel::<EmitItem>();
        let slot = SyncSlot::default();
        slot.put(snap("c", "s1", 512), &tx);
        tx.send(EmitItem::Msg(raw("c", "L1"))).unwrap();
        slot.put(snap("c", "s2", 512), &tx);
        slot.put(snap("c", "s3", 512), &tx);
        tx.send(EmitItem::Msg(raw("c", "L2"))).unwrap();
        slot.put(snap("c", "s4", 512), &tx);
        // Each marker is a few bytes; only ONE ~60 KiB snapshot payload is held.
        assert!(slot.latest.lock().unwrap().is_some());
        let mut out = Vec::new();
        while let Ok(item) = rx.try_recv() {
            match item {
                EmitItem::Msg(m) => out.push(line_of(&OutFrame::plain(m))),
                EmitItem::Sync(seq) => if let Some(IpcMessage::SessionSync { nick, .. }) = slot.take_for(seq) { out.push(nick) },
            }
        }
        assert_eq!(out, vec!["L1", "L2", "s4"]);
        // A consumer that keeps up sees every snapshot, in place.
        slot.put(snap("c", "s5", 1), &tx);
        let EmitItem::Sync(seq) = rx.try_recv().unwrap() else { panic!() };
        assert!(matches!(slot.take_for(seq), Some(IpcMessage::SessionSync { ref nick, .. }) if nick == "s5"));
        tx.send(EmitItem::Msg(raw("c", "L3"))).unwrap();
        slot.put(snap("c", "s6", 1), &tx);
        assert!(matches!(rx.try_recv(), Ok(EmitItem::Msg(_))));
        let EmitItem::Sync(seq) = rx.try_recv().unwrap() else { panic!() };
        assert!(matches!(slot.take_for(seq), Some(IpcMessage::SessionSync { ref nick, .. }) if nick == "s6"));
        assert_eq!(slot.markers.load(Ordering::Acquire), 0);
    }

    /// A parked snapshot is weighed by its real size (it used to count as 512 bytes).
    #[test]
    fn parked_snapshot_weight_is_real() {
        assert!(frame_weight(&snap("c", "n", 512)) > 60 * 1024);
        assert!(frame_weight(&snap("c", "n", 0)) < 1024);
    }

    /// codex P2 ipc_server.rs:745: RawSend lines are cut to the IRC limit and the bytes
    /// queued per connection are budgeted (a stalled socket used to let 1,024 lines of up
    /// to ~60 KiB each pile up per connection).
    #[tokio::test]
    async fn rawsend_is_capped_and_budgeted() {
        let d = Arc::new(Daemon::new());
        let (cmd_tx, mut cmd_rx) = mpsc::channel(CMD_QUEUE_CAP);
        let h = handle(cmd_tx, Arc::new(Mutex::new(ConnCache::default())), 1);
        let raw_bytes = h.raw_bytes.clone();
        d.conns.insert("c0".into(), h);
        let (out_tx, _out_rx) = mpsc::channel::<OutFrame>(4);
        let big = format!("PING :{}", "z".repeat(60 * 1024));
        for _ in 0..CMD_QUEUE_CAP {
            handle_message(IpcMessage::RawSend { conn_id: "c0".into(), line: big.clone() }, &d, &out_tx, 1, &ClientAcks::default()).await;
        }
        assert!(raw_bytes.load(Ordering::Acquire) <= crate::irc_daemon::RAWSEND_CONN_BYTE_CAP);
        let mut n = 0usize;
        while let Ok(cmd) = cmd_rx.try_recv() {
            let DaemonCmd::RawSend(q) = cmd else { panic!("unexpected command") };
            assert_eq!(q.line().len(), crate::irc_daemon::OUT_MSG_MAX);
            n += 1;
        }
        assert!(n > 0 && n < CMD_QUEUE_CAP, "{n} lines queued");
        assert_eq!(raw_bytes.load(Ordering::Acquire), 0, "drained lines release their budget");
    }

    /// codex P2 ipc_server.rs:803 / w-srv INFO: while a slow web drains a connection's
    /// replay, that connection's live consumer is NOT blocked (the replay no longer holds
    /// the cache lock across its blocking sends); its live line is parked and arrives once,
    /// after the whole history, before AttachComplete.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replay_does_not_block_the_live_consumer() {
        let d = Arc::new(Daemon::new());
        let mut cache = ConnCache::default();
        for i in 0..RING_CAP { cache.push_line(format!("hist {i}")); }
        let cache = Arc::new(Mutex::new(cache));
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        d.conns.insert("c0".into(), handle(cmd_tx, cache.clone(), 1));
        let (cl, mut rx) = test_client(7, 16);
        let out_tx = cl.out_tx.clone();
        *d.current_client.lock().await = Some(cl);
        let d2 = d.clone();
        let attach = tokio::spawn(async move {
            handle_message(IpcMessage::Attach { version: String::new(), build: String::new(), features: vec![] }, &d2, &out_tx, 7, &ClientAcks::default()).await;
        });
        // The replay is now blocked on the full 16-slot queue.
        timeout(Duration::from_secs(5), async { while rx.len() < 16 { tokio::task::yield_now().await; } }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        timeout(Duration::from_secs(2), update_cache_and_forward(&cache, &d, "c0", 1, raw("c0", "LIVE")))
            .await.expect("the live consumer must not wait for the replay to drain");
        let mut got: Vec<String> = Vec::new();
        loop {
            let f = timeout(Duration::from_secs(10), rx.recv()).await.expect("stalled").expect("closed");
            if matches!(f.msg, IpcMessage::AttachComplete {}) { break; }
            if let IpcMessage::RawLine { line, .. } = written(f) { got.push(line); }
        }
        attach.await.unwrap();
        assert_eq!(got.len(), RING_CAP + 1);
        assert_eq!(got.last().map(String::as_str), Some("LIVE"));
        assert_eq!(got.iter().filter(|l| *l == "LIVE").count(), 1);
    }

    #[test]
    fn global_budget_shrinks_the_per_ring_cap() {
        assert_eq!(ring_byte_cap(0), RING_BYTE_CAP);
        assert_eq!(ring_byte_cap(RING_GLOBAL_BYTE_BUDGET), RING_BYTE_CAP);
        assert_eq!(ring_byte_cap(RING_GLOBAL_BYTE_BUDGET + 1), RING_PRESSURE_FLOOR);
    }

    #[tokio::test]
    async fn live_frames_during_replay_are_parked_in_order_not_dropped() {
        let d = Daemon::new();
        let (cl, mut rx) = test_client(7, 2);
        *d.current_client.lock().await = Some(cl);
        d.set_replaying(7, true).await;
        for i in 0..10 { d.forward_live(live(i)).await; }
        {
            let g = d.current_client.lock().await;
            let c = g.as_ref().expect("a client must not be dropped because its replay filled the queue");
            assert_eq!(c.parked.len(), 8);
            assert!(c.parking);
        }
        assert_eq!(line_of(&rx.recv().await.unwrap()), "live 0");
        assert_eq!(line_of(&rx.recv().await.unwrap()), "live 1");
        let batch: Vec<String> = d.take_parked(7).await.unwrap().iter().map(line_of).collect();
        assert_eq!(batch, (2..10).map(|i| format!("live {i}")).collect::<Vec<_>>());
        // Still flushing: a new frame must queue BEHIND the parked ones, even though the
        // out-queue has room again.
        d.forward_live(live(10)).await;
        assert!(rx.try_recv().is_err(), "a live frame jumped ahead of the parked ones");
        let batch2: Vec<String> = d.take_parked(7).await.unwrap().iter().map(line_of).collect();
        assert_eq!(batch2, vec!["live 10".to_string()]);
        assert!(d.take_parked(7).await.is_none());
        // Replay over: the normal wedged-client policy is back.
        d.forward_live(live(11)).await;
        d.forward_live(live(12)).await;
        assert!(d.current_client.lock().await.is_some());
        d.forward_live(live(13)).await;
        assert!(d.current_client.lock().await.is_none(), "a full queue outside a replay still drops the client");
    }

    #[tokio::test]
    async fn replay_park_is_bounded() {
        let d = Daemon::new();
        let (cl, _rx) = test_client(3, 1);
        *d.current_client.lock().await = Some(cl);
        d.set_replaying(3, true).await;
        let big = "z".repeat(1024 * 1024);
        for _ in 0..40 {
            d.forward_live(OutFrame::plain(IpcMessage::RawLine { conn_id: "c".into(), line: big.clone(), replayed: false, backlog: false, recv_ts: 0, seq: 0 })).await;
        }
        assert!(d.current_client.lock().await.is_none(), "an over-budget park falls back to dropping the client");
    }

    #[tokio::test]
    async fn reader_exit_detaches_only_its_own_client() {
        let d = Daemon::new();
        let (cl, _rx) = test_client(1, 4);
        *d.current_client.lock().await = Some(cl);
        d.detach_client(2).await;
        assert!(d.current_client.lock().await.is_some());
        d.detach_client(1).await;
        assert!(d.current_client.lock().await.is_none());
    }

    /// LOW (ipc_server.rs:395-403): a malformed frame used to leave the client installed
    /// but deaf. Now the daemon closes the socket so the web reconnects.
    #[tokio::test]
    async fn malformed_frame_closes_the_ipc_socket() {
        use tokio::io::AsyncWriteExt;
        let d = Arc::new(Daemon::new());
        let (web, core) = UnixStream::pair().unwrap();
        accept_client(core, d.clone()).await;
        let (mut wr, mut ww) = web.into_split();
        write_frame(&mut ww, &IpcMessage::Attach { version: String::new(), build: String::new(), features: vec![] }).await.unwrap();
        assert!(matches!(read_frame(&mut wr).await.unwrap(), Some(IpcMessage::Hello { .. })));
        assert!(matches!(read_frame(&mut wr).await.unwrap(), Some(IpcMessage::AttachComplete {})));
        let body = b"{not json";
        ww.write_all(&(body.len() as u32).to_be_bytes()).await.unwrap();
        ww.write_all(body).await.unwrap();
        let r = timeout(Duration::from_secs(3), read_frame(&mut wr)).await
            .expect("daemon must close the socket, not leave a half-dead client installed");
        assert!(matches!(r, Ok(None)), "expected EOF, got {:?}", r.map(|m| m.map(|m| format!("{:?}", m))));
        assert!(d.current_client.lock().await.is_none());
    }

    /// MEDIUM (ipc_server.rs:36/210-228/442-451): an Attach replay bigger than the
    /// 4096-slot out-queue (3 connections x full 2000-line rings) while live lines keep
    /// arriving and the web reads slowly. The client must get the WHOLE replay plus
    /// AttachComplete, and every live line exactly once, in order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn attach_replay_larger_than_queue_survives_live_traffic() {
        let d = Arc::new(Daemon::new());
        let nconns = 3usize;
        for n in 0..nconns {
            let (cmd_tx, _cmd_rx) = mpsc::channel(1);
            let mut cache = ConnCache::default();
            for i in 0..RING_CAP { cache.push_line(format!("hist {n} {i}")); }
            d.conns.insert(format!("c{n}"), handle(cmd_tx, Arc::new(Mutex::new(cache)), 1000 + n as u64));
        }
        let (web, core) = UnixStream::pair().unwrap();
        accept_client(core, d.clone()).await;
        let (mut wr, mut ww) = web.into_split();
        write_frame(&mut ww, &IpcMessage::Attach { version: "t".into(), build: "t".into(), features: vec![] }).await.unwrap();
        let nlive = 600usize;
        let d2 = d.clone();
        let producer = tokio::spawn(async move {
            for i in 0..nlive {
                d2.forward_live(live(i)).await;
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let (mut replayed, mut frames, mut complete) = (0usize, 0usize, false);
        let mut live_seen: Vec<String> = Vec::new();
        while !complete || live_seen.len() < nlive {
            let m = timeout(Duration::from_secs(30), read_frame(&mut wr)).await.expect("stalled");
            match m {
                Ok(Some(IpcMessage::RawLine { replayed: true, .. })) => replayed += 1,
                Ok(Some(IpcMessage::RawLine { line, replayed: false, .. })) => live_seen.push(line),
                Ok(Some(IpcMessage::AttachComplete {})) => complete = true,
                Ok(Some(_)) => {}
                Ok(None) => panic!("daemon dropped the client mid-replay (after {replayed} replayed, {} live)", live_seen.len()),
                Err(e) => panic!("read error: {e}"),
            }
            frames += 1;
            // A slow web: ~1 ms per 10 frames, so the replay outlasts the 4096-slot queue
            // while the producer is running.
            if frames % 10 == 0 { tokio::time::sleep(Duration::from_millis(1)).await; }
        }
        producer.await.unwrap();
        assert_eq!(replayed, nconns * RING_CAP);
        assert_eq!(live_seen, (0..nlive).map(|i| format!("live {i}")).collect::<Vec<_>>());
        assert!(d.current_client.lock().await.is_some());
    }

    /// codex P2 ipc_server.rs:796: a server that sends its last lines and closes (an
    /// auto_reconnect=false network) — every line reaches the web, in order, BEFORE the
    /// terminal Disconnected. The old two-queue consumer served control first and quit
    /// as soon as the control queue closed, losing whatever lines were still queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn final_lines_before_close_are_not_lost_or_reordered() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let d = Arc::new(Daemon::new());
        let (cl, mut rx) = test_client(5, 4096);
        *d.current_client.lock().await = Some(cl);
        let params: DialParams = serde_json::from_value(serde_json::json!({
            "server":"127.0.0.1","port":port,"tls":false,"tls_accept_invalid_certs":false,
            "nick":"me","username":"u","realname":"r","password":null,"sasl_plain":null,
            "sasl_external":false,"client_identity":null,"oper_login":null,"oper_pass":null,
            "nickserv_pass":null,"auto_identify":false,"auto_join":[],"channel_keys":{},
            "perform_commands":[],"disabled_caps":[],"label":"efnet-test","auto_reconnect":false
        })).unwrap();
        spawn_connection(d.clone(), "c1".into(), params).await;
        // Stall the consumer (it needs the cache lock) so everything below is queued
        // behind it at once — the interleaving that used to lose the tail.
        let cache = d.conns.get("c1").unwrap().cache.clone();
        let hold = cache.lock().await;
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 512];
        let _ = timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
        let mut burst = String::from(":srv 001 me :welcome\r\n");
        for i in 0..20 { burst.push_str(&format!(":peer!u@h PRIVMSG me :line {i}\r\n")); }
        sock.write_all(burst.as_bytes()).await.unwrap();
        sock.shutdown().await.unwrap();
        drop(sock);
        tokio::time::sleep(Duration::from_millis(300)).await;
        drop(hold);
        let mut seen: Vec<String> = Vec::new();
        loop {
            match timeout(Duration::from_secs(5), rx.recv()).await.expect("no terminal event").map(|f| f.msg) {
                Some(IpcMessage::RawLine { line, .. }) => seen.push(line),
                Some(IpcMessage::ConnStatus { state: ConnLifecycle::Disconnected { .. }, .. }) => break,
                Some(_) => {}
                None => panic!("client channel closed"),
            }
        }
        let lines: Vec<String> = seen.into_iter().filter(|l| l.contains("PRIVMSG")).collect();
        assert_eq!(lines, (0..20).map(|i| format!(":peer!u@h PRIVMSG me :line {i}")).collect::<Vec<_>>());
    }

    /// codex P2 ipc_server.rs:299: a live frame of a connection that arrives while that
    /// connection's Attach replay is being queued must come AFTER its whole history,
    /// exactly once (it used to be try_sent straight into the middle of the replay).
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn live_frame_never_overtakes_its_own_replay() {
        let mut bad = 0;
        for round in 0..20 {
            let d = Arc::new(Daemon::new());
            let mut cache = ConnCache::default();
            for i in 0..RING_CAP { cache.push_line(format!("hist {i}")); }
            let cache = Arc::new(Mutex::new(cache));
            let (cmd_tx, _cmd_rx) = mpsc::channel(1);
            d.conns.insert("c0".into(), handle(cmd_tx, cache.clone(), 1));
            let (cl, mut rx) = test_client(7, OUT_QUEUE_CAP);
            let out_tx = cl.out_tx.clone();
            *d.current_client.lock().await = Some(cl);
            let d2 = d.clone();
            let attach = tokio::spawn(async move {
                handle_message(IpcMessage::Attach { version: String::new(), build: String::new(), features: vec![] }, &d2, &out_tx, 7, &ClientAcks::default()).await;
            });
            // The live line arrives while the replay is being queued.
            while rx.len() < 50 { tokio::task::yield_now().await; }
            let live = serde_json::from_value::<IpcMessage>(serde_json::json!(
                {"type": "raw_line", "conn_id": "c0", "line": "LIVE KICK", "replayed": false})).unwrap();
            let (d3, c3) = (d.clone(), cache.clone());
            let inj = tokio::spawn(async move { update_cache_and_forward(&c3, &d3, "c0", 1, live).await; });
            let mut got: Vec<String> = Vec::new();
            loop {
                let m = timeout(Duration::from_secs(10), rx.recv()).await.expect("stalled").expect("closed").msg;
                if matches!(m, IpcMessage::AttachComplete {}) { break; }
                if let IpcMessage::RawLine { line, .. } = &m { got.push(line.clone()); }
            }
            attach.await.unwrap(); inj.await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            while let Ok(f) = rx.try_recv() { if let IpcMessage::RawLine { line, .. } = &f.msg { got.push(line.clone()); } }
            let n = got.iter().filter(|l| *l == "LIVE KICK").count();
            let pos = got.iter().position(|l| l == "LIVE KICK");
            let last_hist = got.iter().rposition(|l| l.starts_with("hist "));
            if n != 1 || pos < last_hist {
                bad += 1;
                println!("R2 live-vs-replay round {round}: live x{n} at {:?}, last history at {:?}", pos, last_hist);
            }
        }
        println!("R2 live-vs-replay: {bad}/20 rounds out of order or duplicated");
        assert_eq!(bad, 0);
    }

    /// r5 (codex P4 update.sh:1859): a missing socket directory is created 0700; an existing
    /// one is left exactly as it is.
    #[test]
    fn missing_socket_parent_is_created_existing_one_untouched() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!("r5-sockdir-{}-{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let sock = base.join("run/cryptirc/irc-core.sock");
        ensure_socket_parent(sock.to_str().unwrap()).unwrap();
        let dir = base.join("run/cryptirc");
        assert!(dir.is_dir());
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_socket_parent(sock.to_str().unwrap()).unwrap();
        assert_eq!(std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o755, "existing dir not chmod'ed");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// r5 (codex P2 ipc_client.rs:293): a line declared held stays undelivered when it is
    /// acknowledged, until it is released; the others are delivered as before.
    #[test]
    fn held_lines_stay_undelivered_until_released() {
        let a = ClientAcks::default();
        let f: Vec<Arc<AtomicBool>> = (0..4).map(|_| Arc::new(AtomicBool::new(false))).collect();
        for (i, x) in f.iter().enumerate() { a.written(i as u64 + 1, x.clone()); }
        a.hold(&[2, 3]);
        a.processed(4);
        assert_eq!(f.iter().map(|x| x.load(Ordering::Acquire)).collect::<Vec<_>>(), vec![true, false, false, true]);
        a.release(&[2]);
        assert!(f[1].load(Ordering::Acquire) && !f[2].load(Ordering::Acquire));
        a.release(&[3, 99]);
        assert!(f[2].load(Ordering::Acquire));
        // Released before acknowledged: delivered normally on the ack.
        let g = Arc::new(AtomicBool::new(false));
        a.written(5, g.clone()); a.hold(&[5]); a.release(&[5]); a.processed(5);
        assert!(g.load(Ordering::Acquire));
    }

    /// r4 C2-4: acknowledgement bookkeeping — in order, up to `upto`, bounded.
    #[test]
    fn client_acks_mark_delivered_up_to_the_acknowledged_seq() {
        let a = ClientAcks::default();
        let flags: Vec<Arc<AtomicBool>> = (0..5).map(|_| Arc::new(AtomicBool::new(false))).collect();
        for (i, f) in flags.iter().enumerate() { a.written(i as u64 + 1, f.clone()); }
        a.processed(2);
        assert_eq!(flags.iter().map(|f| f.load(Ordering::Acquire)).collect::<Vec<_>>(), vec![true, true, false, false, false]);
        a.processed(2); // repeated / stale ack: nothing changes
        a.processed(9);
        assert!(flags.iter().all(|f| f.load(Ordering::Acquire)));
        let first = Arc::new(AtomicBool::new(false));
        a.written(10, first.clone());
        for i in 0..ACK_WAIT_CAP as u64 { a.written(11 + i, Arc::new(AtomicBool::new(false))); }
        assert!(first.load(Ordering::Acquire), "past the cap the oldest counts as delivered (old rule)");
        assert_eq!(a.waiting.lock().unwrap().len(), ACK_WAIT_CAP);
    }

    async fn read_replay(wr: &mut tokio::net::unix::OwnedReadHalf) -> Vec<(String, bool, u64)> {
        let mut got = Vec::new();
        loop {
            match timeout(Duration::from_secs(5), read_frame(wr)).await.expect("stalled").expect("read") {
                Some(IpcMessage::RawLine { line, backlog, seq, .. }) => got.push((line, backlog, seq)),
                Some(IpcMessage::AttachComplete {}) => return got,
                Some(_) => {}
                None => panic!("daemon closed the socket"),
            }
        }
    }

    /// r4 C2-4 (codex P2 ipc_server.rs:681): for a `proc_ack` web a ring line is delivered
    /// only once acknowledged — lines it read but did not process when it went away replay
    /// as backlog to the next web. A web without the feature keeps the old rule.
    #[tokio::test]
    async fn proc_ack_client_lines_count_only_once_processed() {
        let d = Arc::new(Daemon::new());
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        let mut cache = ConnCache::default();
        for i in 0..10 { cache.push_line(format!("hist {i}")); }
        d.conns.insert("c0".into(), handle(cmd_tx, Arc::new(Mutex::new(cache)), 1));
        // Web A (proc_ack) reads the whole replay but acknowledges only the first 4 lines.
        let (web, core) = UnixStream::pair().unwrap();
        accept_client(core, d.clone()).await;
        let (mut wr, mut ww) = web.into_split();
        write_frame(&mut ww, &IpcMessage::Attach { version: "t".into(), build: "t".into(), features: vec!["proc_ack".into()] }).await.unwrap();
        let a = read_replay(&mut wr).await;
        assert_eq!(a.iter().map(|(_, _, s)| *s).collect::<Vec<_>>(), (1..=10).collect::<Vec<u64>>());
        assert!(a.iter().all(|(_, b, _)| *b), "nothing was delivered before");
        write_frame(&mut ww, &IpcMessage::Processed { upto: 4 }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop((wr, ww));
        // Web B (an older web: no features): 0-3 delivered, 4-9 still backlog; no seq.
        let (web2, core2) = UnixStream::pair().unwrap();
        accept_client(core2, d.clone()).await;
        let (mut wr2, mut ww2) = web2.into_split();
        write_frame(&mut ww2, &IpcMessage::Attach { version: "t".into(), build: "t".into(), features: vec![] }).await.unwrap();
        let b = read_replay(&mut wr2).await;
        assert_eq!(b.iter().map(|(_, b, _)| *b).collect::<Vec<_>>(), [vec![false; 4], vec![true; 6]].concat());
        assert!(b.iter().all(|(_, _, s)| *s == 0));
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop((wr2, ww2));
        // B's writes counted (old rule): a third web sees no backlog.
        let (web3, core3) = UnixStream::pair().unwrap();
        accept_client(core3, d.clone()).await;
        let (mut wr3, mut ww3) = web3.into_split();
        write_frame(&mut ww3, &IpcMessage::Attach { version: "t".into(), build: "t".into(), features: vec![] }).await.unwrap();
        assert!(read_replay(&mut wr3).await.iter().all(|(_, b, _)| !*b));
        drop(ww3);
    }

    /// r5 (codex P2 ipc_server.rs:100): an ended connection's undelivered lines reach the next
    /// web that attaches (as backlog, then its terminal Disconnected); once delivered, a later
    /// Attach no longer replays it.
    #[tokio::test]
    async fn ended_connection_history_waits_for_a_web() {
        let d = Arc::new(Daemon::new());
        let mut cache = ConnCache::default();
        for i in 0..5 { cache.push_line(format!("last {i}")); }
        cache.last_disconnect = "Clean disconnect".into();
        d.keep_ended("c-ended", Arc::new(Mutex::new(cache)));
        async fn attach(d: &Arc<Daemon>) -> (Vec<(String, bool)>, Option<String>) {
            let (web, core) = UnixStream::pair().unwrap();
            accept_client(core, d.clone()).await;
            let (mut wr, mut ww) = web.into_split();
            write_frame(&mut ww, &IpcMessage::Attach { version: "t".into(), build: "t".into(), features: vec![] }).await.unwrap();
            let (mut lines, mut disc) = (Vec::new(), None);
            loop {
                match timeout(Duration::from_secs(5), read_frame(&mut wr)).await.expect("stalled").expect("read") {
                    Some(IpcMessage::RawLine { conn_id, line, backlog, .. }) if conn_id == "c-ended" => lines.push((line, backlog)),
                    Some(IpcMessage::ConnStatus { conn_id, state: ConnLifecycle::Disconnected { reason } }) if conn_id == "c-ended" => disc = Some(reason),
                    Some(IpcMessage::AttachComplete {}) => break,
                    Some(_) => {}
                    None => panic!("closed"),
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop((wr, ww));
            tokio::time::sleep(Duration::from_millis(200)).await;
            (lines, disc)
        }
        let (lines, disc) = attach(&d).await;
        assert_eq!(lines.len(), 5);
        assert!(lines.iter().all(|(_, b)| *b), "never delivered before → backlog");
        assert_eq!(disc.as_deref(), Some("Clean disconnect"), "then its terminal Disconnected");
        // r6 (agy P2 ipc_server.rs:528): a web that attaches after that one still learns that
        // the connection ended (its lines were delivered: not backlog again).
        let (lines2, disc2) = attach(&d).await;
        assert!(lines2.iter().all(|(_, b)| !*b), "delivered → not backlog again: {lines2:?}");
        assert_eq!(disc2.as_deref(), Some("Clean disconnect"), "the terminal state is replayed again");
        assert!(d.ended.contains_key("c-ended"));
        // ... until it expires.
        if let Some(mut e) = d.ended.get_mut("c-ended") {
            e.since = std::time::Instant::now().checked_sub(ENDED_KEEP_TTL + Duration::from_secs(1)).unwrap();
        }
        let (lines3, disc3) = attach(&d).await;
        assert!(lines3.is_empty() && disc3.is_none(), "expired → pruned: {lines3:?} {disc3:?}");
        assert!(d.ended.is_empty());
        // Bounded.
        for i in 0..(ENDED_KEEP_MAX + 10) { d.keep_ended(&format!("e{i}"), Arc::new(Mutex::new(ConnCache::default()))); }
        assert!(d.ended.len() <= ENDED_KEEP_MAX);
    }

    /// r4 V3I-N6: the live out-queue is bounded by bytes too (snapshot floods).
    #[tokio::test]
    async fn live_out_queue_is_bounded_by_bytes() {
        let d = Daemon::new();
        let (cl, mut rx) = test_client(1, OUT_QUEUE_CAP);
        let lb = cl.live_bytes.clone();
        *d.current_client.lock().await = Some(cl);
        let w = frame_weight(&snap("c", "n", 512));
        let mut sent = 0usize;
        while d.current_client.lock().await.is_some() && sent < OUT_QUEUE_CAP {
            d.forward_live(OutFrame::plain(snap("c", "n", 512))).await;
            sent += 1;
        }
        assert!(d.current_client.lock().await.is_none(), "the byte cap drops the slow client");
        assert!(sent < OUT_QUEUE_CAP && (sent - 1) * w <= OUT_QUEUE_MAX_BYTES, "{sent} frames of {w} bytes");
        let queued: usize = std::iter::from_fn(|| rx.try_recv().ok()).map(|f| f.weight).sum();
        assert_eq!(queued, lb.load(Ordering::Acquire), "every queued frame carries its charge");
        // Small frames never get near it.
        let (cl2, _rx2) = test_client(2, OUT_QUEUE_CAP);
        *d.current_client.lock().await = Some(cl2);
        for i in 0..(OUT_QUEUE_CAP - 1) { d.forward_live(live(i)).await; }
        assert!(d.current_client.lock().await.is_some());
    }

    /// r4 C1-9: a dropped RawSend is reported to a web that announced `send_dropped`
    /// (rate-limited per connection), never to an older web.
    #[tokio::test]
    async fn dropped_rawsend_is_reported_to_a_web_that_asked() {
        let d = Arc::new(Daemon::new());
        let (out_tx, mut out_rx) = mpsc::channel::<OutFrame>(8);
        let raw = |id: &str, l: &str| IpcMessage::RawSend { conn_id: id.into(), line: l.into() };
        handle_message(raw("r4sd-old", "PRIVMSG #a :x"), &d, &out_tx, 1, &ClientAcks::default()).await;
        assert!(out_rx.try_recv().is_err(), "an older web never gets SendDropped");
        let acks = ClientAcks::default();
        acks.set_features(&["send_dropped".to_string()]);
        handle_message(raw("r4sd-gone", "PRIVMSG #a :x"), &d, &out_tx, 1, &acks).await;
        assert!(matches!(out_rx.try_recv().unwrap().msg, IpcMessage::SendDropped { ref conn_id, .. } if conn_id == "r4sd-gone"));
        handle_message(raw("r4sd-gone", "PRIVMSG #a :y"), &d, &out_tx, 1, &acks).await;
        assert!(out_rx.try_recv().is_err(), "rate-limited per connection");
        // Lines the web sends on its own (WHO, NAMES, …) are never reported.
        handle_message(raw("r4sd-who", "WHO #a"), &d, &out_tx, 1, &acks).await;
        assert!(out_rx.try_recv().is_err(), "not a chat line");
        assert_eq!(chat_line_target("@t=1 :me NOTICE  bob :hi\r\n"), Some("bob"));
        assert_eq!(chat_line_target("PRIVMSG"), None);
        // A full send queue (stalled socket) on a live connection.
        let (cmd_tx, _cmd_rx) = mpsc::channel(1);
        d.conns.insert("r4sd-c1".into(), handle(cmd_tx, Arc::new(Mutex::new(ConnCache::default())), 1));
        handle_message(raw("r4sd-c1", "PRIVMSG #a :1"), &d, &out_tx, 1, &acks).await;
        assert!(out_rx.try_recv().is_err(), "queued: nothing to report");
        handle_message(raw("r4sd-c1", "PRIVMSG #a :2"), &d, &out_tx, 1, &acks).await;
        assert!(matches!(out_rx.try_recv().unwrap().msg, IpcMessage::SendDropped { ref conn_id, .. } if conn_id == "r4sd-c1"));
    }
}
