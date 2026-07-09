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

/// Run forever: connect to the daemon, and on any disconnect (daemon
/// restarted/crashed, or never came up yet) retry after a short fixed delay.
/// Unlike IRC-side reconnect this is a local socket — either the daemon is up
/// or it's not, so there's no need for the exponential backoff the daemon
/// itself uses against real network flakiness.
pub async fn run(sock_path: String, state: AppState) {
    loop {
        match UnixStream::connect(&sock_path).await {
            Ok(stream) => {
                info!("Connected to irc-core daemon at {}", sock_path);
                if let Err(e) = handle_connection(stream, &state).await {
                    warn!("irc-core IPC connection lost: {}", e);
                }
            }
            Err(e) => {
                warn!("Could not connect to irc-core daemon at {} ({}) — retrying", sock_path, e);
            }
        }
        *state.ipc_out.lock().await = None;
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

async fn handle_connection(stream: UnixStream, state: &AppState) -> anyhow::Result<()> {
    let (mut read_half, write_half) = stream.into_split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcMessage>();

    // Install this connection's sender as the one every IrcConnection::send_raw
    // (and the Dial/RawSend/Drop senders below) will use.
    *state.ipc_out.lock().await = Some(out_tx.clone());

    let mut write_half = write_half;
    let writer_task = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_frame(&mut write_half, &msg).await.is_err() { break; }
        }
    });

    // Snapshot of conn_ids we believe should be live BEFORE this Attach cycle —
    // compared against what the daemon actually reports once AttachComplete
    // arrives, so a conn_id we expected but the daemon doesn't have (e.g. the
    // daemon itself restarted) gets a fresh Dial. `seen` accumulates as
    // SessionSync arrives during the replay burst.
    let expected: HashSet<String> = state.connections.iter().map(|e| e.key().clone()).collect();
    let mut seen: HashSet<String> = HashSet::new();

    out_tx.send(IpcMessage::Attach {}).ok();

    let result = loop {
        match read_frame(&mut read_half).await {
            Ok(Some(msg)) => handle_message(msg, state, &expected, &mut seen, &out_tx).await,
            Ok(None) => break Ok(()),
            Err(e) => break Err(anyhow::Error::from(e)),
        }
    };
    writer_task.abort();
    result
}

async fn handle_message(
    msg: IpcMessage,
    state: &AppState,
    expected: &HashSet<String>,
    seen: &mut HashSet<String>,
    out_tx: &mpsc::UnboundedSender<IpcMessage>,
) {
    match msg {
        IpcMessage::RawLine { conn_id, line, replayed } => {
            if let Some((_username, conn)) = ensure_connection_entry(state, &conn_id).await {
                if let Err(e) = irc::dispatch_line(state, &_username, &conn_id, &conn, &line, replayed).await {
                    warn!("[{}] dispatch_line error: {}", conn_id, e);
                }
            }
        }

        IpcMessage::ConnStatus { conn_id, state: lifecycle } => {
            // ensure_connection_entry (not just a conn_owners lookup) so a
            // brand-new Dial's very first message — always this one — has
            // somewhere to read `cfg.server` from for display.
            if let Some((username, conn)) = ensure_connection_entry(state, &conn_id).await {
                let evt = match lifecycle {
                    ConnLifecycle::Connecting => {
                        let server = conn.lock().await.cfg.server.clone();
                        ServerEvent::Connecting { conn_id: conn_id.clone(), server }
                    }
                    ConnLifecycle::Disconnected { reason } => {
                        {
                            let mut c = conn.lock().await;
                            c.connected = false;
                            // Without this, a daemon-internal reconnect (no re-Attach
                            // involved) that re-registers leaves `registered` stuck
                            // true from before the drop, so the SessionSync that
                            // follows sees `registered && !c.registered` = false and
                            // never re-fires ServerEvent::Connected — anything gated
                            // on "just (re)connected" goes stale until a manual reload.
                            c.registered = false;
                            // Drop in-flight WHO bookkeeping: the socket that owed us a
                            // 315 ENDOFWHO is gone, so those entries would never clear
                            // and would suppress a genuine post-reconnect /who. The
                            // reconnect's SessionSync re-seeds who_pending for the
                            // channels it resyncs.
                            c.who_pending.clear();
                        }
                        if state.disconnect_requested(&conn_id) {
                            state.abort_connect_task(&conn_id);
                            state.connections.remove(&conn_id);
                            state.conn_owners.remove(&conn_id);
                            state.clear_disconnect_request(&conn_id);
                        }
                        ServerEvent::Disconnected { conn_id: conn_id.clone(), reason }
                    }
                    ConnLifecycle::Reconnecting { attempt, delay_secs, reason } => {
                        let mut c = conn.lock().await;
                        c.connected = false;
                        c.registered = false;
                        // Same rationale as the Disconnected arm: the old socket's
                        // outstanding WHOs will never be answered, so clear the pending
                        // set rather than let stale keys block future auto-WHOs.
                        c.who_pending.clear();
                        ServerEvent::Reconnecting { conn_id: conn_id.clone(), attempt, delay_secs, reason }
                    }
                };
                state.send_to_user(&username, evt);
            }
        }

        IpcMessage::SessionSync { conn_id, nick, channels, registered, connected, lag_ms, message_tags, echo_message_enabled, self_userhost } => {
            seen.insert(conn_id.clone());
            if let Some((username, conn)) = ensure_connection_entry(state, &conn_id).await {
                let mut resync: Vec<String> = Vec::new();
                let mut newly_registered = None;
                {
                    let mut c = conn.lock().await;
                    c.nick = nick.clone();
                    // SessionSync is the single authoritative source for
                    // registered/Connected — the daemon always calls its own
                    // sync() BEFORE forwarding the raw "001" line, so
                    // dispatch_line's 001 arm deliberately does nothing (see
                    // its comment) rather than racing this same flag. Only
                    // fire Connected on the actual false→true edge, so a
                    // later SessionSync (still registered:true, e.g. after a
                    // JOIN) doesn't re-emit it.
                    if registered && !c.registered {
                        newly_registered = Some((nick.clone(), c.cfg.server.clone()));
                    }
                    c.registered = registered;
                    c.connected = connected;
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
                    if !self_userhost.is_empty() {
                        c.self_userhost = self_userhost.clone();
                    }
                    // Rebuild any channel the daemon says we're in but this
                    // (freshly (re)hydrated) web process doesn't have yet —
                    // insert a stub and queue a NAMES/TOPIC resync for it. This
                    // is the "rebuild display state via an ordinary resync
                    // burst" mechanism: no channel-state protocol of its own,
                    // just the same commands a manual /names would send.
                    for chan in &channels {
                        let key = cryptirc::ircproto::irc_lower(chan);
                        let need_resync = match c.channels.get(&key) {
                            None => {
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
                        if need_resync {
                            resync.push(chan.clone());
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
                }
                if let Some((connected_nick, server)) = newly_registered {
                    state.send_to_user(&username, ServerEvent::Connected {
                        conn_id: conn_id.clone(), server, nick: connected_nick,
                    });
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
                        for chan in &resync {
                            { let _ = conn2.lock().await.send_raw(&format!("NAMES {}\r\n", chan)).await; }
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        }
                        for chan in &resync {
                            { let _ = conn2.lock().await.send_raw(&format!("WHO {}\r\n", chan)).await; }
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        }
                        for chan in &resync {
                            { let _ = conn2.lock().await.send_raw(&format!("MODE {}\r\n", chan)).await; }
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        }
                        for chan in &resync {
                            { let _ = conn2.lock().await.send_raw(&format!("TOPIC {}\r\n", chan)).await; }
                            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
                        }
                    });
                }
            }
        }

        IpcMessage::AttachComplete {} => {
            // Reconciliation: anything we expected before this Attach cycle
            // that the daemon never reported (it restarted and lost its live
            // sockets, or this is a genuinely stale entry) gets re-Dialed —
            // reusing the exact decrypt-and-resolve path a normal Connect uses.
            for conn_id in expected.difference(seen) {
                if state.disconnect_requested(conn_id) { continue; }
                let Some(username) = state.conn_owners.get(conn_id).map(|r| r.clone()) else { continue };
                // I2: with a LOCKED vault, get_network_config returns secrets still
                // `enc:`-prefixed; re-dialing now would connect UNAUTHENTICATED (and, absent
                // the build_dial_params guard, leak ciphertext). Drop the now-dead entry
                // (the daemon no longer owns it) and defer — reconnect_for_user re-dials on
                // the next vault unlock (it re-seeds conn_owners + dials conns not already
                // live). Leaving it in `connections` would BOTH falsely show it connected
                // AND make reconnect_for_user skip it (its contains_key guard) → stranded.
                if !state.crypto.is_unlocked(&username).await {
                    state.connections.remove(conn_id);
                    state.send_to_user(&username, ServerEvent::Disconnected {
                        conn_id: conn_id.clone(),
                        reason: "Daemon restarted — unlock the vault to reconnect".into(),
                    });
                    continue;
                }
                let Some(cfg) = state.get_network_config(conn_id, &username).await else { continue };
                // I5: respect an intentional auto_reconnect=false — the daemon may have
                // cleanly stopped this conn; reconciliation must not revive a connection the
                // user configured not to auto-reconnect.
                if !cfg.auto_reconnect {
                    state.connections.remove(conn_id);
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
                let Some(cfg) = state.get_network_config(&conn_id, &username).await else {
                    state.clear_pending_dial(&conn_id);
                    continue;
                };
                state.clear_pending_dial(&conn_id);
                dial(state, &username, cfg, out_tx).await;
            }
        }

        // Daemon → web version handshake. Logged so a mismatch between a frozen
        // daemon and a newer web binary is visible in the journal; behavior stays
        // additive/tolerant either way (see the ipc.rs SCHEMA LAW comment).
        IpcMessage::Hello { proto_version } => {
            if proto_version != cryptirc::ipc::IPC_PROTO_VERSION {
                warn!("daemon IPC proto v{} != web v{} — running in compatibility mode", proto_version, cryptirc::ipc::IPC_PROTO_VERSION);
            } else {
                info!("daemon IPC proto v{} negotiated", proto_version);
            }
        }

        // Web → daemon variants; the client never receives its own outbound
        // messages. `DaemonControl` is web-originated too. `Unknown` is the
        // forward-compat catch-all for a variant a future peer added — ignore
        // rather than ever tear the connection down over it.
        IpcMessage::Attach {} | IpcMessage::Dial { .. } | IpcMessage::RawSend { .. }
        | IpcMessage::Drop { .. } | IpcMessage::DaemonControl { .. } | IpcMessage::Unknown => {}
    }
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
    let cfg = state.get_network_config(conn_id, &username).await?;
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
        self_userhost: String::new(),
        registered: false,
        echo_message_enabled: false,
        names_buf: HashMap::new(),
        who_pending: HashSet::new(),
        who_away: HashMap::new(),
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
    let params = build_dial_params(state, username, &cfg).await;
    let _ = out_tx.send(IpcMessage::Dial { conn_id, params: Box::new(params) });
}

/// Send `Drop` for `conn_id` through whatever IPC connection is currently up.
/// Best-effort, matching `send_raw`'s philosophy — if the daemon link happens
/// to be down right when the user disconnects, the daemon will simply have
/// nothing to tear down (there's no live socket for it to hold open either).
pub async fn send_drop(state: &AppState, conn_id: &str, reason: String) {
    if let Some(tx) = state.ipc_out.lock().await.as_ref() {
        let _ = tx.send(IpcMessage::Drop { conn_id: conn_id.to_string(), reason });
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

async fn build_dial_params(state: &AppState, username: &str, cfg: &NetworkConfig) -> DialParams {
    let client_identity = match &cfg.client_cert_id {
        Some(cert_id) if state.certs.exists(cert_id).await => {
            let dir = state.certs.cert_path_for(cert_id);
            let cert_bytes = tokio::fs::read(dir.join("cert.pem")).await;
            let key_enc = tokio::fs::read_to_string(dir.join("key.enc")).await;
            match (cert_bytes, key_enc) {
                (Ok(cert_bytes), Ok(key_enc)) => match state.crypto.decrypt(username, key_enc.trim()).await {
                    Ok(key_bytes) => Some(ClientIdentity {
                        cert_pem: String::from_utf8_lossy(&cert_bytes).into_owned(),
                        key_pem: String::from_utf8_lossy(&key_bytes).into_owned(),
                    }),
                    Err(e) => {
                        warn!("[{}] client cert key decrypt failed (vault locked?): {}", cfg.id, e);
                        None
                    }
                },
                _ => {
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

    // I2 defense-in-depth: NEVER forward an `enc:`-prefixed secret to the IRC server.
    // `get_network_config` leaves secrets `enc:`-prefixed when the vault is locked
    // (undecryptable); sending that ciphertext as PASS / SASL / oper / nickserv would
    // leak an AEAD blob to the server operator and break auth. Drop each such field to
    // None (+ warn), exactly like the client-cert branch degrades on decrypt failure.
    let deny_enc = |v: &Option<String>, what: &str| -> Option<String> {
        match v {
            Some(s) if s.starts_with("enc:") => {
                warn!("[{}] {} still encrypted (vault locked) — omitting from dial", cfg.id, what);
                None
            }
            other => other.clone(),
        }
    };
    let password = deny_enc(&cfg.password, "server password");
    let oper_pass = deny_enc(&cfg.oper_pass, "oper password");
    let nickserv_pass = deny_enc(&cfg.nickserv_pass, "nickserv password");
    let sasl_plain = cfg.sasl_plain.as_ref().and_then(|s: &SaslConfig| {
        if s.password.starts_with("enc:") {
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
        channel_keys: cfg.channel_keys.clone(),
        perform_commands: cfg.perform_commands.clone(),
        disabled_caps: cfg.disabled_caps.clone(),
        label: cfg.label.clone(),
        auto_reconnect: cfg.auto_reconnect,
    }
}
