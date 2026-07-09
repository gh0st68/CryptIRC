//! ipc_server.rs — the daemon side of the IPC boundary. Listens on a Unix
//! domain socket, accepts exactly one web-process client at a time (a fresh
//! `Attach` supersedes any prior connection), and routes `Dial`/`RawSend`/
//! `Drop`/`Attach` into per-conn_id `irc_daemon::run_connection` tasks.
//!
//! Each conn_id also gets a small cache (last known `SessionSync` snapshot +
//! a bounded ring buffer of recent `RawLine`s) so a freshly-attached client
//! can be caught up immediately without waiting for new server traffic.

use crate::ipc::{ConnLifecycle, DialParams, IpcMessage, IPC_PROTO_VERSION};
use crate::ipc_framing::{read_frame, write_frame};
use crate::irc_daemon::{run_connection, DaemonCmd};
use anyhow::Result;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Bound on the live out-queue to the currently-attached web client. A client
/// that stops reading (crashed mid-frame, SIGSTOP'd, kernel buffer full) must
/// never let this grow without bound and OOM the un-restartable daemon. On
/// overflow we DROP THE CLIENT — the ring buffer replays everything on the next
/// Attach, which is the intended recovery path. Kept >= RING_CAP so a full ring
/// replay to a healthy client never trips the bound.
const OUT_QUEUE_CAP: usize = 4096;
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
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        // Remove only if the current entry is still ours (not a Dial-replace's new task).
        let removed = self.daemon.conns.remove_if(&self.conn_id, |_, h| h.token == self.token).is_some();
        if removed {
            tracing::warn!(target: "irc_core", event = "conn_permanently_dead", conn_id = %self.conn_id, "connection task ended — removed from daemon");
            // Best-effort notify the web that this conn is gone (Drop is sync).
            let d = self.daemon.clone();
            let id = self.conn_id.clone();
            tokio::spawn(async move {
                d.forward_live(IpcMessage::ConnStatus {
                    conn_id: id,
                    state: ConnLifecycle::Disconnected { reason: "connection task ended".into() },
                }).await;
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

#[derive(Clone, Default)]
struct ConnCache {
    ring: VecDeque<String>,
    nick: String,
    channels: Vec<String>,
    registered: bool,
    connected: bool,
    lag_ms: Option<u64>,
    message_tags: bool,
    echo_message_enabled: bool,
    self_userhost: String,
}

impl ConnCache {
    fn push_line(&mut self, line: String) {
        if self.ring.len() >= RING_CAP {
            self.ring.pop_front();
        }
        self.ring.push_back(line);
    }

    /// Rebuild the two replay messages (a `SessionSync` snapshot + the
    /// buffered `RawLine`s) sent to a client on a fresh `Attach`.
    fn replay_messages(&self, conn_id: &str) -> Vec<IpcMessage> {
        let mut out = Vec::with_capacity(self.ring.len() + 1);
        out.push(IpcMessage::SessionSync {
            conn_id: conn_id.to_string(),
            nick: self.nick.clone(),
            channels: self.channels.clone(),
            registered: self.registered,
            connected: self.connected,
            lag_ms: self.lag_ms,
            message_tags: self.message_tags,
            echo_message_enabled: self.echo_message_enabled,
            self_userhost: self.self_userhost.clone(),
        });
        for line in &self.ring {
            out.push(IpcMessage::RawLine { conn_id: conn_id.to_string(), line: line.clone(), replayed: true });
        }
        out
    }
}

struct ConnHandle {
    cmd_tx: mpsc::Sender<DaemonCmd>,
    cache: Arc<Mutex<ConnCache>>,
    /// Generation token — the connection task's `ConnGuard` only reaps this
    /// entry if the token still matches (survives a Dial-replace).
    token: u64,
}

struct CurrentClient {
    out_tx: mpsc::Sender<IpcMessage>,
    reader_task: tokio::task::JoinHandle<()>,
    writer_task: tokio::task::JoinHandle<()>,
}

pub struct Daemon {
    conns: DashMap<String, ConnHandle>,
    current_client: Mutex<Option<CurrentClient>>,
}

impl Daemon {
    fn new() -> Self {
        Self { conns: DashMap::new(), current_client: Mutex::new(None) }
    }

    /// Best-effort forward to whichever client is CURRENTLY attached (looked
    /// up fresh on every call, since the attached client can change over a
    /// connection's lifetime). Silently drops if nobody is attached — the
    /// cache (updated by the caller before this) is what a future Attach
    /// replays from, so nothing is lost, just not delivered live.
    async fn forward_live(&self, msg: IpcMessage) {
        let mut guard = self.current_client.lock().await;
        // Non-blocking send into the BOUNDED out-queue. If it's full, the client is
        // reading too slowly (or is wedged) — never block the caller (a per-conn cache/
        // forward task) waiting on it. Drop the client instead: the ring buffer replays
        // everything on its next Attach, which is the designed recovery path. Also drops
        // on Closed (writer task already gone).
        let drop_client = match guard.as_ref() {
            Some(c) => c.out_tx.try_send(msg).is_err(),
            None => false,
        };
        if drop_client {
            if let Some(prev) = guard.take() {
                warn!("dropping a slow/wedged IPC client (out-queue full) — it will replay from the ring on re-Attach");
                prev.reader_task.abort();
                prev.writer_task.abort();
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
    let (out_tx, mut out_rx) = mpsc::channel::<IpcMessage>(OUT_QUEUE_CAP);

    let mut write_half = write_half;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            // write_frame is bounded by WRITE_TIMEOUT, so a stuck peer can't wedge this
            // writer forever; an error (timeout or dead socket) ends the writer, which
            // drops out_rx → the next forward_live sees the channel Closed and drops the
            // client (closing #14: forward_live no longer buffers into a dead client).
            if write_frame(&mut write_half, &msg).await.is_err() {
                break;
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
    let daemon_for_reader = daemon.clone();
    let out_tx_for_reader = out_tx.clone();
    let reader_task = tokio::spawn(async move {
        if start_rx.await.is_err() { return; } // accept_client gave up before releasing us
        loop {
            match read_frame(&mut read_half).await {
                Ok(Some(msg)) => handle_message(msg, &daemon_for_reader, &out_tx_for_reader).await,
                Ok(None) => { info!("IPC client disconnected (clean EOF)"); break; }
                Err(e) => { warn!("IPC client read error: {}", e); break; }
            }
        }
    });

    // Supersede any prior client — abort its tasks (closing its socket
    // halves) before installing this one. Held only long enough to swap.
    {
        let mut current = daemon.current_client.lock().await;
        if let Some(prev) = current.take() {
            prev.reader_task.abort();
            prev.writer_task.abort();
        }
        *current = Some(CurrentClient { out_tx, reader_task, writer_task });
    }
    // Only now release the reader — current_client already correctly points
    // at this client, so its first frame (Attach) and any live event racing
    // it resolve unambiguously instead of racing the swap above.
    let _ = start_tx.send(());
}

async fn handle_message(msg: IpcMessage, daemon: &Arc<Daemon>, out_tx: &mpsc::Sender<IpcMessage>) {
    match msg {
        IpcMessage::Attach {} => {
            info!("Attach received — replaying {} known connection(s)", daemon.conns.len());
            // Version handshake first, so a newer web binary can learn what this
            // (possibly frozen) daemon supports.
            let _ = out_tx.send(IpcMessage::Hello { proto_version: IPC_PROTO_VERSION }).await;
            // M6: collect (conn_id, cache Arc) OUT of the DashMap iterator FIRST, then
            // drop the iterator, THEN lock each cache. Holding a DashMap shard read-lock
            // (which `conns.iter()` does) across an `.await` (`cache.lock().await` /
            // `out_tx.send().await`) is a documented deadlock footgun — a concurrent
            // entry()/remove() on the same shard can block. This is the hottest path
            // (every web reconnect Attaches).
            let snapshots: Vec<(String, Arc<Mutex<ConnCache>>)> = daemon.conns.iter()
                .map(|e| (e.key().clone(), e.value().cache.clone()))
                .collect();
            for (conn_id, cache) in snapshots {
                // Build the replay messages under the lock, release it, THEN send.
                let msgs = { cache.lock().await.replay_messages(&conn_id) };
                for replay in msgs {
                    let _ = out_tx.send(replay).await;
                }
            }
            // Marks "that's everything" so the client can safely diff against
            // what it expected and re-Dial anything missing.
            let _ = out_tx.send(IpcMessage::AttachComplete {}).await;
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
            spawn_connection(daemon.clone(), conn_id, *params).await;
        }

        IpcMessage::RawSend { conn_id, line } => {
            match daemon.conns.get(&conn_id) {
                // F2: if the bounded cmd queue is full (a long write-stall backing up
                // >CMD_QUEUE_CAP lines), the line is dropped — log it rather than dropping
                // silently, so the loss is observable (the web-side connected-check surfaces
                // the reconnect case to the user; this covers the queue-full case).
                Some(h) => {
                    if h.cmd_tx.try_send(DaemonCmd::RawSend(line)).is_err() {
                        warn!("[{}] dropping web RawSend — command queue full (peer write stalled?)", conn_id);
                    }
                }
                None => warn!("[{}] RawSend for unknown conn_id — dropped", conn_id),
            }
        }

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
        IpcMessage::Hello { proto_version } => {
            info!("web client Hello: proto_version={}", proto_version);
        }

        // A message type this frozen daemon doesn't know (added by a newer web binary).
        IpcMessage::Unknown => { /* ignore — never tear down the connection over it */ }

        // Daemon never receives its own outbound variants.
        IpcMessage::RawLine { .. } | IpcMessage::ConnStatus { .. } | IpcMessage::SessionSync { .. }
        | IpcMessage::AttachComplete {} => {}
    }
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
    let cache = Arc::new(Mutex::new(ConnCache { nick: params.nick.clone(), ..Default::default() }));

    match daemon.conns.entry(conn_id.clone()) {
        Entry::Occupied(_) => {
            warn!("[{}] Dial raced with an existing entry — ignoring (already owned)", conn_id);
            return;
        }
        Entry::Vacant(v) => {
            v.insert(ConnHandle { cmd_tx, cache: cache.clone(), token });
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
    // Two emit channels with DIFFERENT shed policies. `emit` is a SYNC closure called
    // from run_connection's read loop, so it can't block/await:
    //  • `emit_tx` (bounded): RawLine history only. On a genuine line-flood that
    //    outpaces the consumer it sheds with a warn rather than growing memory
    //    unbounded — safe because the ring buffer is the source of truth on reattach,
    //    and the inbound token bucket already rate-limits the upstream.
    //  • `ctrl_tx` (unbounded): SessionSync / ConnStatus (and any future non-line
    //    message). These are the ONLY writers of the reattach cache's
    //    nick/channels/registered/connected/… snapshot, so shedding one would make a
    //    later Attach replay a STALE snapshot as truth (a dead conn shown alive, wrong
    //    membership, a mis-armed spoof guard) with no self-correction. They are
    //    low-volume — one per membership/lifecycle change — so unbounded can't blow up.
    let (emit_tx, mut emit_rx) = mpsc::channel::<IpcMessage>(EMIT_QUEUE_CAP);
    let (ctrl_tx, mut ctrl_rx) = mpsc::unbounded_channel::<IpcMessage>();
    let emit_conn = conn_id.clone();
    let emit = move |msg: IpcMessage| {
        match msg {
            IpcMessage::RawLine { .. } => {
                if emit_tx.try_send(msg).is_err() {
                    // Drop the line. We deliberately do NOT push it straight into the ring
                    // here: the ring is written ONLY by the consumer, in strict FIFO order.
                    // A producer-side push would land this line AHEAD of the up-to-
                    // EMIT_QUEUE_CAP earlier lines still sitting in the queue (the consumer
                    // rings those later), reordering the ring — a later Attach would then
                    // replay JOIN-before-353 / PART-before-reJOIN out of order (the exact
                    // hazard the two-channel split exists to prevent). Losing a single line
                    // under extreme backpressure — only reachable if the consumer stalls on
                    // the cache lock for tens of seconds while a flood arrives, which the
                    // inbound token bucket makes nearly impossible — is strictly better than
                    // a reordered history. The shed is logged, never silent.
                    warn!(target: "irc_core", event = "emit_shed", conn_id = %emit_conn, "emit live-forward queue full — dropping a line (ring stays in-order)");
                }
            }
            // Never shed — the reattach cache depends on every one of these.
            _ => { let _ = ctrl_tx.send(msg); }
        }
    };

    // run_connection task, wrapped in a ConnGuard so a panic (or normal return) always
    // removes the (token-matched) entry and notifies the web — no orphaned zombie conn.
    let run_daemon = daemon.clone();
    let run_conn_id = conn_id.clone();
    let run_handle = tokio::spawn(async move {
        let _guard = ConnGuard { daemon: run_daemon, conn_id: run_conn_id.clone(), token };
        run_connection(run_conn_id, params, emit, cmd_rx).await;
    });

    // Emit consumer. Holds AbortOnDrop(run_handle): if this consumer ever exits — both
    // channels closed (run_connection ended) OR the consumer itself panics — it tears
    // down run_connection too, so a "socket alive but web deaf/blind" half-dead
    // connection can never persist. `biased` polls the control channel FIRST so a
    // RawLine flood on emit_rx can never starve a pending SessionSync/ConnStatus.
    let daemon_for_consumer = daemon.clone();
    let cache_for_consumer = cache.clone();
    let consumer_conn_id = conn_id.clone();
    tokio::spawn(async move {
        let _abort = AbortOnDrop(run_handle);
        loop {
            tokio::select! {
                biased;
                ctrl = ctrl_rx.recv() => match ctrl {
                    Some(msg) => update_cache_and_forward(&cache_for_consumer, &daemon_for_consumer, &consumer_conn_id, token, msg).await,
                    None => break,
                },
                line = emit_rx.recv() => match line {
                    Some(msg) => update_cache_and_forward(&cache_for_consumer, &daemon_for_consumer, &consumer_conn_id, token, msg).await,
                    None => break,
                },
            }
        }
    });
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
    match &msg {
        IpcMessage::RawLine { line, .. } => c.push_line(line.clone()),
        IpcMessage::SessionSync { nick, channels, registered, connected, lag_ms, message_tags, echo_message_enabled, self_userhost, .. } => {
            c.nick = nick.clone();
            c.channels = channels.clone();
            c.registered = *registered;
            c.connected = *connected;
            c.lag_ms = *lag_ms;
            c.message_tags = *message_tags;
            c.echo_message_enabled = *echo_message_enabled;
            if !self_userhost.is_empty() { c.self_userhost = self_userhost.clone(); }
        }
        IpcMessage::ConnStatus { state, .. } => match state {
            ConnLifecycle::Connecting => { c.connected = false; }
            ConnLifecycle::Reconnecting { .. } | ConnLifecycle::Disconnected { .. } => {
                c.connected = false;
                c.registered = false;
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
    let superseded = matches!(daemon.conns.get(conn_id), Some(h) if h.token != token);
    if !superseded {
        daemon.forward_live(msg).await;
    }
    drop(c);
}
