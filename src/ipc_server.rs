//! ipc_server.rs — the daemon side of the IPC boundary. Listens on a Unix
//! domain socket, accepts exactly one web-process client at a time (a fresh
//! `Attach` supersedes any prior connection), and routes `Dial`/`RawSend`/
//! `Drop`/`Attach` into per-conn_id `irc_daemon::run_connection` tasks.
//!
//! Each conn_id also gets a small cache (last known `SessionSync` snapshot +
//! a bounded ring buffer of recent `RawLine`s) so a freshly-attached client
//! can be caught up immediately without waiting for new server traffic.

use crate::ipc::{ConnLifecycle, DialParams, IpcMessage};
use crate::ipc_framing::{read_frame, write_frame};
use crate::irc_daemon::{run_connection, DaemonCmd};
use anyhow::Result;
use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

/// Bounded per-connection replay buffer. Sized so a normal few-second web
/// restart replays with zero loss; an extended outage just ages out older
/// lines rather than growing memory without bound (deliberately not
/// ZNC-style persistent chathistory — that's out of scope for the "thin
/// socket-keeper" design).
const RING_CAP: usize = 2000;

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
        });
        for line in &self.ring {
            out.push(IpcMessage::RawLine { conn_id: conn_id.to_string(), line: line.clone(), replayed: true });
        }
        out
    }
}

struct ConnHandle {
    cmd_tx: mpsc::UnboundedSender<DaemonCmd>,
    cache: Arc<Mutex<ConnCache>>,
}

struct CurrentClient {
    out_tx: mpsc::UnboundedSender<IpcMessage>,
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
        if let Some(c) = self.current_client.lock().await.as_ref() {
            let _ = c.out_tx.send(msg);
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
    let _ = std::fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(sock_path, std::fs::Permissions::from_mode(0o600))?;
    }
    info!("irc-core IPC listening on {}", sock_path);

    let daemon = Arc::new(Daemon::new());
    loop {
        let (stream, _addr) = listener.accept().await?;
        info!("New IPC client connected");
        let daemon = daemon.clone();
        tokio::spawn(async move {
            accept_client(stream, daemon).await;
        });
    }
}

/// Install `stream` as the current client, superseding (aborting) any prior
/// one, then run its reader loop inline (so this task's lifetime IS the
/// reader's — aborting from the NEXT `accept_client` call cleanly tears down
/// both halves).
async fn accept_client(stream: UnixStream, daemon: Arc<Daemon>) {
    let (mut read_half, write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcMessage>();

    let mut write_half = write_half;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_frame(&mut write_half, &msg).await.is_err() {
                break;
            }
        }
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

async fn handle_message(msg: IpcMessage, daemon: &Arc<Daemon>, out_tx: &mpsc::UnboundedSender<IpcMessage>) {
    match msg {
        IpcMessage::Attach {} => {
            info!("Attach received — replaying {} known connection(s)", daemon.conns.len());
            for entry in daemon.conns.iter() {
                let conn_id = entry.key().clone();
                let cache = entry.value().cache.lock().await;
                for replay in cache.replay_messages(&conn_id) {
                    let _ = out_tx.send(replay);
                }
            }
            // Marks "that's everything" so the client can safely diff against
            // what it expected and re-Dial anything missing, without racing
            // the replay above (see IpcMessage::AttachComplete's doc comment).
            let _ = out_tx.send(IpcMessage::AttachComplete {});
        }

        IpcMessage::Dial { conn_id, params } => {
            if daemon.conns.contains_key(&conn_id) {
                warn!("[{}] Dial ignored — daemon already owns this conn_id (reattach uses Attach, not Dial)", conn_id);
                return;
            }
            spawn_connection(daemon.clone(), conn_id, *params).await;
        }

        IpcMessage::RawSend { conn_id, line } => {
            match daemon.conns.get(&conn_id) {
                Some(h) => { let _ = h.cmd_tx.send(DaemonCmd::RawSend(line)); }
                None => warn!("[{}] RawSend for unknown conn_id — dropped", conn_id),
            }
        }

        IpcMessage::Drop { conn_id, reason } => {
            match daemon.conns.get(&conn_id) {
                Some(h) => { let _ = h.cmd_tx.send(DaemonCmd::Drop(reason)); }
                None => warn!("[{}] Drop for unknown conn_id — nothing to do", conn_id),
            }
        }

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
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let cache = Arc::new(Mutex::new(ConnCache { nick: params.nick.clone(), ..Default::default() }));

    match daemon.conns.entry(conn_id.clone()) {
        Entry::Occupied(_) => {
            warn!("[{}] Dial raced with an existing entry — ignoring (already owned)", conn_id);
            return;
        }
        Entry::Vacant(v) => {
            v.insert(ConnHandle { cmd_tx, cache: cache.clone() });
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
    let (emit_tx, mut emit_rx) = mpsc::unbounded_channel::<IpcMessage>();
    let emit = move |msg: IpcMessage| {
        let _ = emit_tx.send(msg);
    };
    let daemon_for_consumer = daemon.clone();
    let cache_for_consumer = cache.clone();
    tokio::spawn(async move {
        while let Some(msg) = emit_rx.recv().await {
            update_cache_and_forward(&cache_for_consumer, &daemon_for_consumer, msg).await;
        }
    });

    let conn_id_for_task = conn_id.clone();
    tokio::spawn(async move {
        run_connection(conn_id_for_task.clone(), params, emit, cmd_rx).await;
        daemon.conns.remove(&conn_id_for_task);
        info!("[{}] Connection task exited — removed from daemon", conn_id_for_task);
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
async fn update_cache_and_forward(cache: &Arc<Mutex<ConnCache>>, daemon: &Arc<Daemon>, msg: IpcMessage) {
    let mut c = cache.lock().await;
    match &msg {
        IpcMessage::RawLine { line, .. } => c.push_line(line.clone()),
        IpcMessage::SessionSync { nick, channels, registered, connected, lag_ms, message_tags, echo_message_enabled, .. } => {
            c.nick = nick.clone();
            c.channels = channels.clone();
            c.registered = *registered;
            c.connected = *connected;
            c.lag_ms = *lag_ms;
            c.message_tags = *message_tags;
            c.echo_message_enabled = *echo_message_enabled;
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
    // Deliberately still holding `c` (the cache lock) across this send — see
    // the function doc comment for why that's what closes the race.
    daemon.forward_live(msg).await;
    drop(c);
}
