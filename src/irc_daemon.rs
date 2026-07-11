//! irc_daemon.rs — the persistent connection core relocated out of the web
//! process. Owns the raw TCP/TLS socket, registration/SASL/CAP handshake,
//! PING/PONG keepalive, and reconnect/backoff — exactly the logic that used to
//! live in `src/irc.rs`'s `connect()`/`do_connect()`/`run_loop()`, adapted to
//! take already-decrypted `DialParams` instead of `NetworkConfig`+`AppState`,
//! and to emit `IpcMessage`s via a sink closure instead of `state.send_to_user`.
//!
//! Design principle ("act AND forward"): every inbound line the daemon acts on
//! for its own registration/membership bookkeeping is ALSO forwarded to the web
//! side as `IpcMessage::RawLine`, so the web side's (unmodified) parsing can
//! independently re-derive whatever it needs (SaslStatus, message_tags,
//! echo-message, etc.) by re-parsing the same wire content a second time — the
//! only exception is PING/PONG, which are pure keepalive noise fully consumed
//! here (lag_ms travels to the web side via `SessionSync` instead).
//!
//! NOT included here (deliberately, matches the "thin socket-keeper" design):
//! away-state WHO polling (a cosmetic web-side UI feature, not needed for the
//! connection to survive — it can become a web-side timer that sends WHO via
//! ordinary `RawSend` in a later phase), full ChannelState (topics/names/keys
//! — rebuilt web-side via a NAMES/TOPIC resync burst on reattach), and channel
//! auto-rejoin key persistence (needs the vault/filesystem, stays web-only).

use crate::ipc::{ClientIdentity, ConnLifecycle, DialParams, IpcMessage, WebVersionCell};
use crate::ircproto::{
    irc_lower, nick_from_prefix, parse_irc, read_capped_line, strip_crlf, truncate_chars,
    CappedLine, MAX_IRC_LINE_LEN,
};
use anyhow::Result;
use rand::Rng;
use std::collections::HashSet;
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{mpsc, Mutex},
    time::{sleep, timeout, Duration, Instant},
};
use tracing::{info, warn};
use zeroize::Zeroize;

const PING_INTERVAL: Duration = Duration::from_secs(30);
const PONG_TIMEOUT: Duration = Duration::from_secs(90);
const RECONNECT_BASE: Duration = Duration::from_secs(5);
const RECONNECT_MAX: Duration = Duration::from_secs(300);
/// A clean server-close resets the backoff to RECONNECT_BASE (fast reconnect) ONLY if the
/// connection was up at least this long — a genuine drop / server restart. A shorter-lived
/// clean close is treated as a connect/close FLAP (k-line, rejected unregistered
/// connection) and keeps escalating toward RECONNECT_MAX instead of hammering the server
/// every RECONNECT_BASE.
const STABLE_CONNECTION: Duration = Duration::from_secs(60);
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_NICK_RETRIES: u32 = 5;
const MAX_SASL_RETRIES: u32 = 3;
/// Bound on TCP connect + TLS handshake. A SYN black-hole or a server that
/// finishes TCP then stalls the handshake must NOT suspend the dial forever
/// (no reconnect would ever fire). On elapse we fall into the normal backoff.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on a single outbound socket write+flush. See `DaemonConn::send_raw` — a
/// zero-window/stalled peer must never suspend a write forever and freeze the loop.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Absolute deadline to reach registration (001). Pre-001 the PONG heartbeat is
/// gated off, and READ_TIMEOUT resets per line — so a slow-drip server (endless
/// CAP LS `*`, SASL stall) could otherwise pin a connection pre-registered
/// forever. One deadline closes the whole class.
const REG_TIMEOUT: Duration = Duration::from_secs(75);
/// #45 (carried over): minimum interval between automatic CTCP replies.
const CTCP_REPLY_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// #31 (carried over): inbound line rate limit (token bucket).
const INBOUND_RATE_BURST: f64 = 1024.0;
const INBOUND_RATE_REFILL: f64 = 64.0;
/// Cap on how many channels the daemon will track for re-join (a hostile server
/// can spoof self-JOIN prefixes to force unlimited distinct channels).
const MAX_TRACKED_CHANNELS: usize = 512;
/// Cap on a tracked channel-NAME's length (real CHANNELLEN is ~50). Combined with
/// `is_trackable_channel`'s char filter (below), a tracked name serializes 1:1 in the
/// SessionSync JSON, so MAX_TRACKED_CHANNELS × this bounds the frame to ~52 KB < the
/// 64 KiB MAX_FRAME_LEN. Capping raw length ALONE is not enough — `"`/`\`/control bytes
/// escape to 2-6 JSON bytes each, so a hostile server could otherwise 2-6× the size past
/// the frame cap and permanently silence the daemon→web state channel.
const MAX_CHANNEL_NAME_LEN: usize = 100;
/// Cap on a learned `self_userhost` (also serialized in every SessionSync — same frame-
/// bloat concern). A real user@host is well under this.
const MAX_USERHOST_LEN: usize = 128;

/// A channel name we'll TRACK (for SessionSync + reconnect re-join) must be sane:
/// channel-prefixed, length-bounded, and free of bytes that aren't valid in a channel
/// (space/comma/control) or that would BLOAT the JSON-serialized SessionSync (`"`, `\`,
/// and control chars escape to 2-6 bytes). Everything that passes here serializes 1:1,
/// making the SessionSync frame size provably bounded regardless of a hostile server's
/// spoofed self-JOIN names. Untrackable names are still forwarded as raw lines.
fn is_trackable_channel(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_CHANNEL_NAME_LEN { return false; }
    if !matches!(name.as_bytes()[0], b'#' | b'&' | b'+' | b'!') { return false; }
    // > 0x20 rejects control bytes AND space; multibyte UTF-8 (>= 0x80) passes and
    // serializes 1:1. Reject the JSON-escaping / channel-illegal bytes explicitly.
    name.bytes().all(|b| b > 0x20 && b != b'"' && b != b'\\' && b != b',')
}

/// Bound + sanitize a learned `self_userhost` before storing it. Returns None if it's
/// implausible (empty, too long, or contains JSON-escaping/control bytes) so the caller
/// keeps the previous value rather than poisoning every SessionSync.
fn clean_userhost(uh: &str) -> Option<String> {
    let uh = strip_crlf(uh);
    if uh.is_empty() || uh.len() > MAX_USERHOST_LEN { return None; }
    // > 0x20 (not >=): reject control bytes AND space AND DEL uniformly, matching
    // is_trackable_channel. A real user@host never contains any of those.
    if !uh.bytes().all(|b| b > 0x20 && b != b'"' && b != b'\\') { return None; }
    Some(uh)
}

/// Enable TCP keepalive so a silently-dead peer (NAT rebind, midpoint failure)
/// is detected by the OS even if the app-level PING path is wedged. Best-effort.
fn enable_keepalive(tcp: &TcpStream) {
    let sock = socket2::SockRef::from(tcp);
    let ka = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(15));
    let _ = sock.set_tcp_keepalive(&ka);
}

/// Decorrelate a backoff delay with ±50% jitter so a network blip that drops many
/// connections at once doesn't make them all re-dial in lockstep (a self-inflicted
/// thundering-herd reconnect storm against a recovering server).
fn jitter(d: Duration) -> Duration {
    let f = rand::thread_rng().gen_range(0.5_f64..1.5_f64);
    d.mul_f64(f)
}

/// Defense-in-depth CRLF sanitization for a web-originated raw line before it hits
/// the IRC socket. The web is TRUSTED to have stripped interior CR/LF, but the
/// daemon is the last line of defense and can never be patched — so re-enforce it
/// here. COLLAPSE semantics (mirrors `strip_crlf`): strip every CR/LF/NUL across
/// the whole payload, then terminate with exactly ONE CRLF. An injected interior
/// newline is folded into the surrounding text (`"hi\r\nJOIN #evil"` → the literal
/// bytes `"hiJOIN #evil"` in one PRIVMSG), never re-framed into a second executable
/// command — that is the whole point, and splitting-then-reterminating would do the
/// opposite. Trailing bytes are preserved (IRC trailing params are byte-exact); an
/// all-control-char line collapses to empty and is dropped.
fn sanitize_outbound(line: &str) -> String {
    let clean: String = line.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect();
    if clean.is_empty() { String::new() } else { format!("{}\r\n", clean) }
}

/// Resolve the `(version, build)` a CTCP VERSION reply should quote: prefer the
/// last web-Attach-announced value (kept current across a web-only redeploy
/// with no daemon restart — see `WebVersionCell`), falling back to this
/// (possibly stale, since the daemon is intentionally not restarted on a
/// routine redeploy) binary's own compiled-in version if no web binary has
/// Attached yet.
fn resolve_ctcp_version(web_version: &WebVersionCell) -> (String, String) {
    web_version.get().unwrap_or_else(|| (
        env!("CARGO_PKG_VERSION").to_string(),
        option_env!("CRYPTIRC_BUILD").unwrap_or("dev").to_string(),
    ))
}

/// A command routed in from the IPC server for a specific conn_id — the
/// inbound half that lets a running connection be driven from outside (the
/// web process, via the daemon's IPC dispatch).
pub enum DaemonCmd {
    /// Forward one raw outbound line (mirrors `ClientMessage::Send` and every
    /// other existing `send_raw()` call site that now originates web-side).
    RawSend(String),
    /// User explicitly disconnected this conn_id. Sends QUIT and stops the
    /// reconnect loop — no further attempts until a fresh `Dial` arrives.
    Drop(String),
    /// Force-cycle the live socket (drop it and let the reconnect loop redial).
    /// A future control lever; reuses the same DialParams (for a fresh cert use a
    /// full re-Dial instead — see ipc_server's Dial-replace).
    Reconnect,
    /// Undo an auto-SASL-disable for this session so the next attempt re-tries SASL.
    RearmSasl,
}

enum SaslMethod {
    External,
    Plain { account: String, password: String },
}

#[derive(PartialEq)]
enum SaslState {
    Idle,
    CapLsSent,
    CapReqSent,
    AuthenticateSent,
    Done,
    Failed(String),
}

/// The daemon's own narrow per-connection state — nick + which channels we
/// believe we're in (case-folded names only) + the real socket writer. No
/// topics/names/keys/message log; that display-layer state stays web-side.
struct DaemonConn {
    nick: String,
    channels: HashSet<String>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    /// Set once, when the corresponding CAP ACK is seen during registration.
    /// Carried into every `SessionSync` so a re-`Attach`'d web process (fresh
    /// `IrcConnection`, defaults false) learns the CAPs this already-live
    /// connection actually negotiated instead of silently losing self-echo
    /// suppression / TAGMSG support until a real reconnect happens.
    message_tags: bool,
    echo_message_enabled: bool,
    /// Our own `user@host` as the server sees it, learned from the self-JOIN
    /// prefix (extended-join gives it directly) and updated on CHGHOST. Forwarded
    /// in every SessionSync so a re-`Attach`'d web process can re-arm its forged-
    /// `NICK` spoof guard (#30) without waiting for a self-JOIN that a reattach
    /// never produces.
    self_userhost: String,
}

impl DaemonConn {
    async fn send_raw(&mut self, line: &str) -> Result<()> {
        // BOUNDED write. This is the one await in a connection's whole lifetime that
        // is otherwise unbounded: a peer that stalls its receive window (zero-window
        // advertiser, a wedged bouncer between us and the network) makes write_all()
        // suspend forever — TCP's persist timer probes a zero window indefinitely and
        // never errors, and TCP keepalive can't rescue it because there IS data in
        // flight. Because send_raw runs inside a select! branch BODY (PING reply, PONG,
        // heartbeat, JOIN burst…), a blocked write freezes the entire loop: the
        // PONG-timeout liveness check never runs, so the task hangs and leaks its
        // socket for the life of a never-restarted daemon. On elapse we error out so the
        // normal reconnect/backoff path fires. Untimed reads are fine (idle is legit);
        // an untimed WRITE is not.
        let w = &mut self.writer;
        let bytes = line.as_bytes();
        match tokio::time::timeout(WRITE_TIMEOUT, async move {
            w.write_all(bytes).await?;
            w.flush().await
        }).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("socket write timed out")),
        }
    }
}

/// Run one conn_id forever: dial, register, hold the connection, and
/// reconnect with backoff on any drop. Mirrors `irc::connect()`'s outer loop
/// exactly (same RECONNECT_BASE/MAX/attempt/sasl_failures state machine).
/// Returns when a `DaemonCmd::Drop` is received (either mid-connection or
/// during the backoff wait) — the caller's `DashMap` entry for this conn_id
/// should be removed once this returns, since it will never reconnect again.
pub async fn run_connection<F>(
    conn_id: String,
    mut params: DialParams,
    emit: F,
    mut cmd_rx: mpsc::Receiver<DaemonCmd>,
    web_version: Arc<WebVersionCell>,
) where
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let mut delay = RECONNECT_BASE;
    let mut attempt = 0u32;
    let mut sasl_failures = 0u32;
    let original_sasl_external = params.sasl_external;
    // Channels the daemon has joined, persisted ACROSS its own reconnects so a
    // ping-timeout/netsplit re-join restores EVERY channel — not just auto_join
    // (findings #3/#8: a manually-joined channel was silently dropped on a
    // daemon-internal reconnect). run_loop seeds from + updates this set.
    let mut persistent_channels: HashSet<String> = HashSet::new();

    loop {
        attempt = attempt.saturating_add(1);
        info!(
            "[{}] Connect attempt {} → {}:{} (sasl_external={})",
            conn_id, attempt, params.server, params.port, params.sasl_external
        );
        emit(IpcMessage::ConnStatus {
            conn_id: conn_id.clone(),
            state: ConnLifecycle::Connecting,
        });

        let mut stopped = false;
        let mut registered_ok = false;
        // do_connect runs the dial + read loop until the socket closes, so its elapsed
        // time is this connection attempt's lifetime — used below to tell a genuine drop
        // (up a while → reconnect fast) from a connect/close FLAP (up briefly → keep
        // backing off) so a rejecting server isn't hammered every RECONNECT_BASE.
        // NOTE: this INCLUDES dial time (≤ CONNECT_TIMEOUT for TCP + TLS). The
        // misclassification is one-directional and benign: only a pathological ~60s slow
        // dial followed by an instant clean close could read as "stable" — and even then
        // the ~60s dial itself paces the retry, so it never becomes a tight hammer. A real
        // flap dials in milliseconds; a genuine long session is never misread as a flap.
        let attempt_start = Instant::now();
        let result = do_connect(&conn_id, &params, &emit, &mut cmd_rx, &mut stopped, &mut registered_ok, &mut persistent_channels, &web_version).await;
        let uptime = attempt_start.elapsed();
        // If this attempt reached registration, the connection genuinely worked —
        // reset the SASL-failure counter and re-arm SASL for next time (W5: an
        // auto-disable must not persist forever across later error-path reconnects).
        if registered_ok {
            sasl_failures = 0;
            params.sasl_external = original_sasl_external;
        }

        if stopped {
            info!("[{}] Drop requested, stopping reconnect loop", conn_id);
            emit(IpcMessage::ConnStatus {
                conn_id: conn_id.clone(),
                state: ConnLifecycle::Disconnected { reason: "User requested".into() },
            });
            return;
        }

        if !params.auto_reconnect {
            info!("[{}] auto_reconnect=false, not reconnecting", conn_id);
            let reason = match &result {
                Ok(_) => "Clean disconnect".to_string(),
                Err(e) => e.to_string(),
            };
            emit(IpcMessage::ConnStatus {
                conn_id: conn_id.clone(),
                state: ConnLifecycle::Disconnected { reason },
            });
            return;
        }

        match result {
            Ok(_) => {
                // Clean server close. Only reset the backoff to base (fast reconnect) if the
                // connection was up a real while — a genuine drop / server restart / netsplit,
                // where you WANT to come back quickly. If the server instead accepted us and
                // immediately closed (a k-line, a rejected unregistered connection — a
                // "connect/close flap"), resetting would hammer it every RECONNECT_BASE
                // forever. In that case do NOT reset: let the backoff keep climbing
                // 5→10→20→…→RECONNECT_MAX (5 min) and hold there, retrying forever — never
                // gives up, never spins.
                let reason = if uptime >= STABLE_CONNECTION {
                    warn!("[{}] Server closed a stable connection (up {:?}). Reconnecting in {:?}", conn_id, uptime, RECONNECT_BASE);
                    delay = RECONNECT_BASE;
                    attempt = 0;
                    sasl_failures = 0;
                    params.sasl_external = original_sasl_external;
                    "Server closed the connection".to_string()
                } else {
                    warn!("[{}] Server closed connection after only {:?} (flap) — escalating backoff, reconnecting in {:?}", conn_id, uptime, delay);
                    "Server keeps closing the connection".to_string()
                };
                // Surface the (possibly escalating) backoff to the web, same as the Err path
                // — otherwise a clean-close flap silently loops with no status for the user.
                emit(IpcMessage::ConnStatus {
                    conn_id: conn_id.clone(),
                    state: ConnLifecycle::Reconnecting {
                        attempt,
                        delay_secs: delay.as_secs(),
                        reason,
                    },
                });
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.starts_with("SASL_FATAL:") {
                    warn!("[{}] {}", conn_id, msg);
                    emit(IpcMessage::ConnStatus {
                        conn_id: conn_id.clone(),
                        state: ConnLifecycle::Disconnected { reason: msg },
                    });
                    return;
                }
                if msg.starts_with("SASL_RETRY:") {
                    sasl_failures += 1;
                    if sasl_failures == 1 {
                        let advice = if params.sasl_external {
                            "SASL EXTERNAL rejected by server — client certificate not registered with this network."
                        } else {
                            "SASL authentication rejected — check SASL account/password."
                        };
                        info!("[{}] SASL failure 1/{}: {}. Fast retry for DNS cycling", conn_id, MAX_SASL_RETRIES, advice);
                        delay = RECONNECT_BASE;
                    } else if sasl_failures >= MAX_SASL_RETRIES {
                        warn!("[{}] SASL failed {} times — disabling SASL for this session", conn_id, sasl_failures);
                        params.sasl_external = false;
                        delay = delay.max(Duration::from_secs(30));
                    } else {
                        info!("[{}] SASL failure {}/{}, backing off", conn_id, sasl_failures, MAX_SASL_RETRIES);
                        delay = delay.max(Duration::from_secs(30));
                    }
                }
                warn!("[{}] Connection error: {}. Reconnecting in {:?}", conn_id, e, delay);
                emit(IpcMessage::ConnStatus {
                    conn_id: conn_id.clone(),
                    state: ConnLifecycle::Reconnecting {
                        attempt,
                        delay_secs: delay.as_secs(),
                        reason: e.to_string(),
                    },
                });
            }
        }

        // Let a Drop arriving DURING the backoff wait interrupt it immediately
        // instead of waiting out the full delay before honoring it. The sleep is
        // JITTERED (±50%) so many connections dropped by one network blip don't
        // re-dial in lockstep (thundering-herd reconnect storm).
        tokio::select! {
            _ = sleep(jitter(delay)) => {}
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(DaemonCmd::Drop(reason)) => {
                        info!("[{}] Drop requested during backoff, stopping", conn_id);
                        emit(IpcMessage::ConnStatus {
                            conn_id: conn_id.clone(),
                            state: ConnLifecycle::Disconnected { reason },
                        });
                        return;
                    }
                    // Reconnect now — skip the rest of the backoff wait.
                    Some(DaemonCmd::Reconnect) => { info!("[{}] Reconnect during backoff", conn_id); }
                    // Re-arm SASL for the next attempt.
                    Some(DaemonCmd::RearmSasl) => { params.sasl_external = original_sasl_external; sasl_failures = 0; }
                    // No live connection to send to while backing off — the line can't go
                    // out. F2: log it (not silent). The web-side connected-check already
                    // told the user "not connected"; this makes the drop observable here.
                    Some(DaemonCmd::RawSend(_)) => {
                        warn!("[{}] dropping web RawSend — connection is down (reconnecting)", conn_id);
                    }
                    // Sender side gone (server task exited) — nothing more will
                    // ever arrive for this conn_id; stop rather than spin forever.
                    None => return,
                }
            }
        }
        // Overflow-safe doubling (never panic even in a debug build).
        delay = delay.checked_mul(2).unwrap_or(RECONNECT_MAX).min(RECONNECT_MAX);
    }
}

/// One connection attempt: dial, TLS (with or without client cert), then run
/// the registration + read loop. Mirrors `irc::do_connect()`.
async fn do_connect<F>(
    conn_id: &str,
    params: &DialParams,
    emit: &F,
    cmd_rx: &mut mpsc::Receiver<DaemonCmd>,
    stopped: &mut bool,
    registered_out: &mut bool,
    persistent_channels: &mut HashSet<String>,
    web_version: &Arc<WebVersionCell>,
) -> Result<()>
where
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let addr = format!("{}:{}", params.server, params.port);
    // TCP connect, bounded + nodelay + keepalive. Connected ONCE per path (the old
    // code dialed upfront then dropped-and-redialed for the client-cert path, which
    // re-resolved DNS and could land on a different, dead round-robin address).
    let dial_tcp = || async {
        let tcp = timeout(CONNECT_TIMEOUT, TcpStream::connect(&addr)).await
            .map_err(|_| anyhow::anyhow!("TCP connect timed out"))??;
        tcp.set_nodelay(true)?;
        enable_keepalive(&tcp);
        Ok::<TcpStream, anyhow::Error>(tcp)
    };

    if params.tls {
        if let Some(ClientIdentity { cert_pem, key_pem }) = &params.client_identity {
            // Client cert path: openssl directly, TLS 1.3 post-handshake auth.
            let mut ssl_builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())?;
            if params.tls_accept_invalid_certs {
                ssl_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            } else if let Err(e) = ssl_builder.set_ca_file("/etc/ssl/certs/ca-certificates.crt") {
                warn!("[{}] Failed to load CA certs, falling back to default paths: {}", conn_id, e);
                let _ = ssl_builder.set_default_verify_paths();
            }
            let x509 = openssl::x509::X509::from_pem(cert_pem.as_bytes())?;
            let mut key_pem_owned = key_pem.clone();
            let pkey = openssl::pkey::PKey::private_key_from_pem(key_pem_owned.as_bytes())?;
            // F26 (carried over): scrub the plaintext key PEM once PKey holds a copy.
            key_pem_owned.zeroize();
            ssl_builder.set_certificate(&x509)?;
            ssl_builder.set_private_key(&pkey)?;
            unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(ssl_builder.as_ptr() as *mut _, 1); }
            let connector = ssl_builder.build();
            let tcp = dial_tcp().await?;
            let ssl = connector.configure()?.into_ssl(&params.server)?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp)?;
            timeout(CONNECT_TIMEOUT, std::pin::Pin::new(&mut stream).connect()).await
                .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
            info!("[{}] TLS connected with client cert (post-handshake auth enabled)", conn_id);
            run_loop(conn_id, params, emit, stream, cmd_rx, stopped, registered_out, persistent_channels, web_version).await
        } else if params.sasl_external {
            // Config asked for SASL EXTERNAL but no identity was resolved — fatal
            // (params never change without a fresh Dial). No connect wasted.
            Err(anyhow::anyhow!("SASL_FATAL: client identity missing for SASL EXTERNAL"))
        } else {
            let mut builder = native_tls::TlsConnector::builder();
            if params.tls_accept_invalid_certs {
                builder.danger_accept_invalid_certs(true);
            }
            let tcp = dial_tcp().await?;
            let tls = timeout(CONNECT_TIMEOUT, tokio_native_tls::TlsConnector::from(builder.build()?)
                .connect(&params.server, tcp)).await
                .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
            run_loop(conn_id, params, emit, tls, cmd_rx, stopped, registered_out, persistent_channels, web_version).await
        }
    } else {
        let tcp = dial_tcp().await?;
        run_loop(conn_id, params, emit, tcp, cmd_rx, stopped, registered_out, persistent_channels, web_version).await
    }
}

/// Registration + read loop. Mirrors `irc::run_loop()`'s pre-001 half and the
/// heartbeat/CAP/SASL/001/nick-retry match arms; everything else (PRIVMSG,
/// JOIN display state, TOPIC, MODE, etc.) is forwarded verbatim as `RawLine`
/// for the web side's own (unchanged) parsing to handle.
async fn run_loop<S, F>(
    conn_id: &str,
    params: &DialParams,
    emit: &F,
    stream: S,
    cmd_rx: &mut mpsc::Receiver<DaemonCmd>,
    stopped: &mut bool,
    registered_out: &mut bool,
    persistent_channels: &mut HashSet<String>,
    web_version: &Arc<WebVersionCell>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let conn = Arc::new(Mutex::new(DaemonConn {
        nick: params.nick.clone(),
        channels: HashSet::new(),
        writer: Box::new(write_half),
        message_tags: false,
        echo_message_enabled: false,
        self_userhost: String::new(),
    }));

    let sync = |c: &DaemonConn, registered: bool, connected: bool, lag_ms: Option<u64>| {
        emit(IpcMessage::SessionSync {
            conn_id: conn_id.to_string(),
            nick: c.nick.clone(),
            channels: c.channels.iter().cloned().collect(),
            registered,
            connected,
            lag_ms,
            message_tags: c.message_tags,
            echo_message_enabled: c.echo_message_enabled,
            self_userhost: c.self_userhost.clone(),
        });
    };
    let fwd = |line: &str| emit(IpcMessage::RawLine { conn_id: conn_id.to_string(), line: line.to_string(), replayed: false });

    let sasl_method: Option<SaslMethod> = if params.sasl_external {
        Some(SaslMethod::External)
    } else if let Some(sc) = &params.sasl_plain {
        if !params.tls {
            warn!("[{}] SASL PLAIN disabled — TLS is off, credentials would travel in cleartext", conn_id);
            None
        } else {
            Some(SaslMethod::Plain { account: sc.account.clone(), password: sc.password.clone() })
        }
    } else {
        None
    };
    let use_sasl = sasl_method.is_some();
    let mut sasl_state = SaslState::Idle;
    let mut available_caps: Vec<String> = Vec::new();
    let mut last_pong = Instant::now();
    // Set when a heartbeat PING is outstanding; cleared by any PONG in our private
    // `hb-<ts>` namespace (see the PONG handler). A foreign PONG can't clear it, so it
    // can't mask a real timeout.
    let mut ping_out = false;
    let mut nick_retries = 0u32;
    let mut last_ctcp_reply: Option<Instant> = None;

    let efnet = params.label.to_lowercase().contains("efnet") || params.server.to_lowercase().contains("efnet");
    if efnet {
        info!("[{}] EFnet detected (label='{}' server='{}') — IRCv3 caps disabled", conn_id, params.label, params.server);
        // EFnet skips CAP LS entirely, so SASL is never negotiated even if configured.
        // Surface that instead of silently registering unauthenticated.
        if use_sasl {
            warn!("[{}] SASL configured but SKIPPED — EFnet-style network has CAP/SASL disabled; registering unauthenticated", conn_id);
        }
    }
    {
        let mut c = conn.lock().await;
        if let Some(pass) = &params.password {
            c.send_raw(&format!("PASS {}\r\n", strip_crlf(pass))).await?;
        }
        if !efnet {
            c.send_raw("CAP LS 302\r\n").await?;
            if use_sasl {
                sasl_state = SaslState::CapLsSent;
            }
        }
        c.send_raw(&format!("NICK {}\r\n", strip_crlf(&params.nick))).await?;
        c.send_raw(&format!("USER {} 0 * :{}\r\n", strip_crlf(&params.username), strip_crlf(&params.realname))).await?;
    }

    let mut reader = BufReader::new(read_half);
    let mut registered = false;
    let mut ping_ticker = tokio::time::interval(PING_INTERVAL);
    let mut inbound_tokens: f64 = INBOUND_RATE_BURST;
    let mut inbound_refill_at = Instant::now();
    // Absolute deadline to reach 001. The per-line READ_TIMEOUT resets on every
    // byte, and the heartbeat is gated off pre-registration — so a server that
    // slow-drips CAP/SASL forever would otherwise pin this task un-registered
    // with no reconnect ever firing. Disarmed the instant we register.
    let reg_timer = sleep(REG_TIMEOUT);
    tokio::pin!(reg_timer);

    loop {
        tokio::select! {
            _ = &mut reg_timer, if !registered => {
                // If we stalled specifically DURING the SASL exchange (we sent CAP REQ
                // :sasl or AUTHENTICATE and the server then went silent — never a 903
                // success nor a 90x failure), classify this as a SASL retry. Otherwise
                // it never matches the `SASL_RETRY:` prefix in run_connection, so the
                // 3-strikes auto-disable never engages and the connection cycles forever
                // un-registered instead of falling back to unauthenticated registration
                // (the same recovery the explicit-904 path already gets).
                if use_sasl && matches!(sasl_state, SaslState::CapReqSent | SaslState::AuthenticateSent) {
                    return Err(anyhow::anyhow!("SASL_RETRY: registration stalled during SASL handshake"));
                }
                return Err(anyhow::anyhow!("registration timeout — no 001 within {}s", REG_TIMEOUT.as_secs()));
            }

            _ = ping_ticker.tick() => {
                if ping_out && last_pong.elapsed() > PONG_TIMEOUT {
                    warn!("[{}] PONG timeout, triggering reconnect", conn_id);
                    return Err(anyhow::anyhow!("PONG timeout — server unresponsive"));
                }
                if registered {
                    let ts = chrono::Utc::now().timestamp_millis() as u64;
                    conn.lock().await.send_raw(&format!("PING :hb-{}\r\n", ts)).await?;
                    ping_out = true;
                }
            }

            // Inbound control from the IPC server (web-originated Send/Disconnect).
            // A closed channel resolves to `None` exactly once and the None arm
            // returns, so there's no busy-spin to guard against.
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(DaemonCmd::RawSend(line)) => {
                        // Defense-in-depth: the web is trusted to have stripped
                        // interior CR/LF, but the daemon is the last barrier before
                        // the socket and can never be patched — re-enforce it here so
                        // command injection is structurally impossible at the boundary.
                        conn.lock().await.send_raw(&sanitize_outbound(&line)).await?;
                    }
                    Some(DaemonCmd::Drop(reason)) => {
                        let _ = conn.lock().await.send_raw(&format!("QUIT :{}\r\n", strip_crlf(&reason))).await;
                        *stopped = true;
                        return Ok(());
                    }
                    // Cycle the socket: clean-return so run_connection re-dials
                    // (fast base backoff) and re-joins every persistent channel.
                    Some(DaemonCmd::Reconnect) => {
                        info!("[{}] Reconnect requested — cycling socket", conn_id);
                        let _ = conn.lock().await.send_raw("QUIT :reconnecting\r\n").await;
                        return Ok(());
                    }
                    // SASL is negotiated at connect; a live re-arm only matters on the
                    // NEXT dial (run_connection restores params.sasl_external there).
                    Some(DaemonCmd::RearmSasl) => {
                        info!("[{}] RearmSasl noted (takes effect on next reconnect)", conn_id);
                    }
                    // Every sender dropped: the daemon removed this conn_id's entry (a
                    // Drop handler or a Dial-replace), possibly AFTER shedding a
                    // full-queue Drop command. The connection must NEVER outlive its
                    // command channel — otherwise it's an un-droppable, un-redialable
                    // zombie socket that leaks against MemoryMax/LimitNOFILE forever on a
                    // daemon that never restarts. Send a best-effort QUIT and stop for
                    // good (stopped=true → run_connection does not reconnect it).
                    None => {
                        info!("[{}] Command channel closed — tearing down connection", conn_id);
                        let _ = conn.lock().await.send_raw("QUIT :connection closed\r\n").await;
                        *stopped = true;
                        return Ok(());
                    }
                }
            }

            res = timeout(READ_TIMEOUT, async {
                let now = Instant::now();
                inbound_tokens = (inbound_tokens
                    + now.duration_since(inbound_refill_at).as_secs_f64() * INBOUND_RATE_REFILL)
                    .min(INBOUND_RATE_BURST);
                inbound_refill_at = now;
                if inbound_tokens < 1.0 {
                    let wait = Duration::from_secs_f64((1.0 - inbound_tokens) / INBOUND_RATE_REFILL);
                    sleep(wait).await;
                    inbound_tokens = 1.0;
                    inbound_refill_at = Instant::now();
                }
                inbound_tokens -= 1.0;
                read_capped_line(&mut reader).await
            }) => {
                let line = match res {
                    Err(_) => return Err(anyhow::anyhow!("Read timeout")),
                    Ok(Ok(CappedLine::Line(l))) => l,
                    Ok(Ok(CappedLine::Eof)) => return Ok(()),
                    Ok(Ok(CappedLine::Oversized)) => {
                        warn!("[{}] Dropping oversized IRC line (> {} bytes)", conn_id, MAX_IRC_LINE_LEN);
                        continue;
                    }
                    Ok(Err(e)) => return Err(e.into()),
                };
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.is_empty() { continue; }
                if line.len() > MAX_IRC_LINE_LEN {
                    warn!("[{}] Dropping oversized IRC line ({} bytes)", conn_id, line.len());
                    continue;
                }

                let p = parse_irc(&line);

                match p.command.as_str() {
                    "PING" => {
                        let tok = p.params.last().cloned().unwrap_or_default();
                        conn.lock().await.send_raw(&format!("PONG :{}\r\n", strip_crlf(&tok))).await?;
                        // Consumed entirely daemon-side — never forwarded.
                    }
                    "PONG" => {
                        let tok = p.params.last().cloned().unwrap_or_default();
                        // Any PONG proves the server→us path is alive; refresh the
                        // liveness clock unconditionally.
                        last_pong = Instant::now();
                        // Clear the outstanding heartbeat for ANY token in our private
                        // `hb-<ts>` namespace (no other sender emits it). Matching the
                        // namespace rather than the exact latest token still ignores a
                        // foreign PONG (e.g. a web-issued /PING via RawSend) so it can't
                        // mask a real timeout — yet tolerates a lost/reordered reply to
                        // the most recent ping instead of stranding ping_out=true until
                        // an exact match that may never come.
                        if let Some(sent) = tok.strip_prefix("hb-").and_then(|s| s.parse::<u64>().ok()) {
                            ping_out = false;
                            let ms = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(sent);
                            let c = conn.lock().await;
                            sync(&c, registered, true, Some(ms));
                        }
                        // Consumed entirely daemon-side — never forwarded.
                    }

                    "CAP" => {
                        let sub = p.params.get(1).map(|s| s.as_str()).unwrap_or("");
                        let is_multiline = p.params.get(2).map(|s| s.as_str()) == Some("*");
                        let caps = if is_multiline {
                            p.params.get(3).cloned().unwrap_or_default()
                        } else {
                            p.params.last().cloned().unwrap_or_default()
                        };
                        match sub {
                            "LS" => {
                                for cap in caps.split_whitespace() {
                                    let cap_name = cap.split('=').next().unwrap_or(cap);
                                    available_caps.push(cap_name.to_string());
                                }
                                if available_caps.len() > 256 { available_caps.truncate(256); }
                                if is_multiline { fwd(&line); continue; }

                                // Same wanted-cap list as today — negotiating these
                                // shapes what the SERVER sends (server-time tags,
                                // batch wrapping, echo-message echoes, etc.), which
                                // the web side's re-parsing depends on matching.
                                let wanted: &[&str] = &[
                                    "away-notify", "account-notify", "extended-join",
                                    "server-time", "multi-prefix", "cap-notify",
                                    "message-tags", "batch", "echo-message",
                                    "invite-notify", "setname", "account-tag",
                                    "userhost-in-names", "chghost", "labeled-response",
                                    "draft/typing", "typing", "standard-replies",
                                ];
                                let mut req: Vec<&str> = Vec::new();
                                for w in wanted {
                                    if params.disabled_caps.iter().any(|d| d == w) { continue; }
                                    if available_caps.iter().any(|c| c == w) { req.push(w); }
                                }
                                if !req.is_empty() {
                                    let req_str = req.join(" ");
                                    info!("[{}] Requesting CAPs: {}", conn_id, req_str);
                                    conn.lock().await.send_raw(&format!("CAP REQ :{}\r\n", req_str)).await?;
                                }
                                if use_sasl && available_caps.iter().any(|c| c == "sasl") {
                                    conn.lock().await.send_raw("CAP REQ :sasl\r\n").await?;
                                    sasl_state = SaslState::CapReqSent;
                                } else if use_sasl {
                                    warn!("[{}] Server has no sasl cap", conn_id);
                                    sasl_state = SaslState::Done;
                                    if req.is_empty() { conn.lock().await.send_raw("CAP END\r\n").await?; }
                                } else if req.is_empty() {
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                }
                                available_caps.clear();
                            }
                            "ACK" => {
                                info!("[{}] CAP ACK: {}", conn_id, caps);
                                {
                                    let mut c = conn.lock().await;
                                    if caps.contains("message-tags") { c.message_tags = true; }
                                    if caps.contains("echo-message") { c.echo_message_enabled = true; }
                                }
                                if caps.contains("sasl") && sasl_state == SaslState::CapReqSent {
                                    let method = match &sasl_method {
                                        Some(SaslMethod::External) => "EXTERNAL",
                                        Some(SaslMethod::Plain { .. }) => "PLAIN",
                                        None => "PLAIN",
                                    };
                                    conn.lock().await.send_raw(&format!("AUTHENTICATE {}\r\n", method)).await?;
                                    sasl_state = SaslState::AuthenticateSent;
                                } else if !caps.contains("sasl") {
                                    let sasl_pending = matches!(sasl_state, SaslState::CapLsSent | SaslState::CapReqSent | SaslState::AuthenticateSent);
                                    if !sasl_pending {
                                        conn.lock().await.send_raw("CAP END\r\n").await?;
                                    }
                                }
                            }
                            "NAK" => {
                                warn!("[{}] CAP NAK: {}", conn_id, caps);
                                if use_sasl && caps.contains("sasl") {
                                    sasl_state = SaslState::Failed("CAP NAK".into());
                                }
                                conn.lock().await.send_raw("CAP END\r\n").await?;
                            }
                            "NEW" => {
                                info!("[{}] CAP NEW: {}", conn_id, caps);
                                let wanted: &[&str] = &[
                                    "away-notify", "account-notify", "extended-join",
                                    "server-time", "multi-prefix", "cap-notify",
                                    "message-tags", "batch", "echo-message",
                                    "invite-notify", "setname", "account-tag",
                                    "userhost-in-names", "chghost", "labeled-response",
                                    "draft/typing", "typing", "standard-replies",
                                ];
                                let mut req: Vec<&str> = Vec::new();
                                for cap in caps.split_whitespace() {
                                    let cap_name = cap.split('=').next().unwrap_or(cap);
                                    if params.disabled_caps.iter().any(|d| d == cap_name) { continue; }
                                    if wanted.contains(&cap_name) { req.push(cap_name); }
                                }
                                if !req.is_empty() {
                                    let req_str = req.join(" ");
                                    conn.lock().await.send_raw(&format!("CAP REQ :{}\r\n", req_str)).await?;
                                }
                            }
                            "DEL" => {
                                // Server withdrew a cap mid-session (e.g. a services/ircd
                                // reload). Without this, message_tags/echo_message_enabled
                                // would stay stuck true forever — SessionSync is
                                // authoritative on reattach, so a stale true here would
                                // silently reintroduce the self-echo-message duplication
                                // bug (or TAGMSG-based typing) via a different trigger
                                // than the reattach case that motivated tracking them.
                                info!("[{}] CAP DEL: {}", conn_id, caps);
                                let mut c = conn.lock().await;
                                let mut changed = false;
                                if caps.contains("message-tags") { c.message_tags = false; changed = true; }
                                if caps.contains("echo-message") { c.echo_message_enabled = false; changed = true; }
                                // Propagate immediately rather than waiting for the next
                                // unrelated sync() (JOIN/PART/NICK) — a stale true in the
                                // meantime is exactly the bug this handler exists to fix.
                                if changed { sync(&c, registered, true, None); }
                            }
                            _ => {}
                        }
                        fwd(&line);
                    }

                    "AUTHENTICATE" => {
                        if p.params.first().map(|s| s.as_str()) == Some("+") && sasl_state == SaslState::AuthenticateSent {
                            let response = match &sasl_method {
                                Some(SaslMethod::Plain { account, password }) => {
                                    let mut pl = Vec::with_capacity(account.len() + password.len() + 2);
                                    pl.push(0u8);
                                    pl.extend_from_slice(account.as_bytes());
                                    pl.push(0u8);
                                    pl.extend_from_slice(password.as_bytes());
                                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pl)
                                }
                                Some(SaslMethod::External) => "+".to_string(),
                                None => "+".to_string(),
                            };
                            conn.lock().await.send_raw(&format!("AUTHENTICATE {}\r\n", response)).await?;
                        }
                        fwd(&line);
                    }

                    "903" => {
                        info!("[{}] SASL 903: authentication successful", conn_id);
                        sasl_state = SaslState::Done;
                        conn.lock().await.send_raw("CAP END\r\n").await?;
                        fwd(&line);
                    }
                    "902" | "904" | "905" | "906" | "907" => {
                        let reason = p.params.last().cloned().unwrap_or_else(|| "SASL failed".into());
                        warn!("[{}] SASL {} FAILED: {}", conn_id, p.command, reason);
                        fwd(&line);
                        return Err(anyhow::anyhow!("SASL_RETRY: {}", reason));
                    }
                    "900" => {
                        fwd(&line);
                    }

                    "001" => {
                        // #29 (carried over): idempotent — ignore a replayed 001.
                        if registered { fwd(&line); continue; }
                        registered = true;
                        // Tell run_connection this attempt genuinely reached the
                        // network — it uses this to reset SASL-failure state / re-arm.
                        *registered_out = true;
                        last_pong = Instant::now();
                        let actual_nick = {
                            let mut c = conn.lock().await;
                            if let Some(real) = p.params.first() {
                                if !real.is_empty() && real.as_str() != "*" {
                                    c.nick = strip_crlf(real);
                                }
                            }
                            c.nick.clone()
                        };
                        if let (Some(login), Some(pass)) = (&params.oper_login, &params.oper_pass) {
                            if !login.is_empty() && !pass.is_empty() {
                                conn.lock().await.send_raw(&format!("OPER {} {}\r\n", strip_crlf(login), strip_crlf(pass))).await?;
                            }
                        }
                        if params.auto_identify {
                            if let Some(pass) = &params.nickserv_pass {
                                if !pass.is_empty() {
                                    conn.lock().await.send_raw(&format!("PRIVMSG NickServ :IDENTIFY {}\r\n", strip_crlf(pass))).await?;
                                }
                            }
                        }
                        for entry in &params.perform_commands {
                            for pl in entry.split(['\n', '\r']) {
                                let raw = strip_crlf(pl.trim());
                                if raw.is_empty() { continue; }
                                let to_send_opt: Option<String> = if let Some(rest) = raw.strip_prefix('/') {
                                    let mut it = rest.splitn(2, ' ');
                                    let cmd = it.next().unwrap_or("").to_ascii_uppercase();
                                    let args = it.next().unwrap_or("").trim_start();
                                    match cmd.as_str() {
                                        "MSG" | "PRIVMSG" => {
                                            let mut ait = args.splitn(2, ' ');
                                            let t = ait.next().unwrap_or("");
                                            let m = ait.next().unwrap_or("");
                                            if t.is_empty() || m.is_empty() { None } else { Some(format!("PRIVMSG {} :{}", t, m)) }
                                        }
                                        "NOTICE" => {
                                            let mut ait = args.splitn(2, ' ');
                                            let t = ait.next().unwrap_or("");
                                            let m = ait.next().unwrap_or("");
                                            if t.is_empty() || m.is_empty() { None } else { Some(format!("NOTICE {} :{}", t, m)) }
                                        }
                                        "NS" | "NICKSERV" => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :{}", args)) },
                                        "CS" | "CHANSERV" => if args.is_empty() { None } else { Some(format!("PRIVMSG ChanServ :{}", args)) },
                                        "IDENTIFY" | "ID" => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :IDENTIFY {}", args)) },
                                        "GHOST" => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :GHOST {}", args)) },
                                        "QUOTE" | "RAW" => if args.is_empty() { None } else { Some(args.to_string()) },
                                        _ => Some(rest.to_string()),
                                    }
                                } else {
                                    Some(raw.to_string())
                                };
                                let Some(mut to_send) = to_send_opt else { continue; };
                                to_send = crate::ircproto::expand_perform_token(&to_send, "$nick", &actual_nick);
                                to_send = crate::ircproto::expand_perform_token(&to_send, "$me", &actual_nick);
                                conn.lock().await.send_raw(&format!("{}\r\n", to_send)).await?;
                            }
                        }
                        let auto_lc: HashSet<String> =
                            params.auto_join.iter().map(|c| irc_lower(c)).collect();
                        for ch in &params.auto_join {
                            let safe = strip_crlf(ch);
                            if !safe.is_empty() {
                                let lc = irc_lower(&safe);
                                let cmd = if let Some(key) = params.channel_keys.get(&lc) {
                                    format!("JOIN {} {}\r\n", safe, strip_crlf(key))
                                } else {
                                    format!("JOIN {}\r\n", safe)
                                };
                                conn.lock().await.send_raw(&cmd).await?;
                            }
                        }
                        // Re-join channels we were in during the PREVIOUS session that
                        // aren't in auto_join (findings #3/#8: a manually-joined channel
                        // was silently dropped whenever the daemon reconnected on its own
                        // — ping timeout, netsplit — because only auto_join was re-sent).
                        // `persistent_channels` survives across do_connect() calls.
                        for lc in persistent_channels.iter() {
                            if auto_lc.contains(lc) { continue; }
                            let safe = strip_crlf(lc);
                            if safe.is_empty() { continue; }
                            let cmd = if let Some(key) = params.channel_keys.get(lc) {
                                format!("JOIN {} {}\r\n", safe, strip_crlf(key))
                            } else {
                                format!("JOIN {}\r\n", safe)
                            };
                            conn.lock().await.send_raw(&cmd).await?;
                        }
                        {
                            let c = conn.lock().await;
                            sync(&c, registered, true, None);
                        }
                        fwd(&line);
                    }

                    "432" | "433" | "436" => {
                        if !registered {
                            nick_retries += 1;
                            if nick_retries > MAX_NICK_RETRIES {
                                return Err(anyhow::anyhow!("Nick collision: exhausted {} retries", MAX_NICK_RETRIES));
                            }
                            let mut c = conn.lock().await;
                            let base = truncate_chars(&c.nick, 28);
                            let new_nick = format!("{}_{}", base, nick_retries);
                            c.nick = new_nick.clone();
                            c.send_raw(&format!("NICK {}\r\n", new_nick)).await?;
                        }
                        // Post-registration: no daemon action (a manual /nick
                        // collision is surfaced by the web side re-parsing this
                        // forwarded line — no silent nick switch).
                        fwd(&line);
                    }

                    "JOIN" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut joined: Option<String> = None;
                        {
                            let mut c = conn.lock().await;
                            if irc_lower(&who) == irc_lower(&c.nick) {
                                // extended-join carries our own user@host in the prefix —
                                // learn it so SessionSync can re-arm the web spoof guard.
                                if let Some(uh) = p.prefix.as_deref()
                                    .and_then(|pre| pre.split_once('!'))
                                    .map(|(_, uh)| uh)
                                {
                                    // Bound + sanitize before storing (serialized in every
                                    // SessionSync — see clean_userhost): a hostile server can't
                                    // poison the state channel with a giant/escaping userhost.
                                    if uh.contains('@') {
                                        if let Some(u) = clean_userhost(uh) { c.self_userhost = u; }
                                    }
                                }
                                if let Some(chan) = p.params.first() {
                                    // Only TRACK a syntactically sane, JSON-1:1-serializable
                                    // channel name (see is_trackable_channel). A hostile server
                                    // controls the JOIN prefix, so a spoofed self-JOIN with a
                                    // giant or `"`/control-filled name would otherwise bloat the
                                    // SessionSync past MAX_FRAME_LEN — write_frame then drops it on
                                    // BOTH live and replay paths, silencing the daemon→web state
                                    // channel PERMANENTLY. Untrackable names are still forwarded
                                    // as the raw line below; they just aren't tracked/re-joined.
                                    if is_trackable_channel(chan) {
                                        let lc = irc_lower(chan);
                                        // Cap membership count too; a real client never nears it.
                                        if c.channels.len() < MAX_TRACKED_CHANNELS || c.channels.contains(&lc) {
                                            c.channels.insert(lc.clone());
                                        }
                                        joined = Some(lc);
                                    }
                                    sync(&c, registered, true, None);
                                }
                            }
                        }
                        if let Some(lc) = joined {
                            // Bounded: a hostile server can't force unbounded growth by
                            // spoofing self-JOIN prefixes to arbitrary channel names.
                            if persistent_channels.len() < MAX_TRACKED_CHANNELS {
                                persistent_channels.insert(lc);
                            }
                        }
                        fwd(&line);
                    }
                    "PART" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut parted: Option<String> = None;
                        {
                            let mut c = conn.lock().await;
                            if irc_lower(&who) == irc_lower(&c.nick) {
                                if let Some(chan) = p.params.first() {
                                    let lc = irc_lower(chan);
                                    c.channels.remove(&lc);
                                    sync(&c, registered, true, None);
                                    parted = Some(lc);
                                }
                            }
                        }
                        if let Some(lc) = parted { persistent_channels.remove(&lc); }
                        fwd(&line);
                    }
                    "KICK" => {
                        let mut kicked_from: Option<String> = None;
                        {
                            let mut c = conn.lock().await;
                            if let Some(kicked) = p.params.get(1) {
                                if irc_lower(kicked) == irc_lower(&c.nick) {
                                    if let Some(chan) = p.params.first() {
                                        let lc = irc_lower(chan);
                                        c.channels.remove(&lc);
                                        sync(&c, registered, true, None);
                                        kicked_from = Some(lc);
                                    }
                                }
                            }
                        }
                        if let Some(lc) = kicked_from { persistent_channels.remove(&lc); }
                        fwd(&line);
                    }
                    "NICK" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut c = conn.lock().await;
                        if irc_lower(&who) == irc_lower(&c.nick) {
                            if let Some(new_nick) = p.params.first() {
                                c.nick = strip_crlf(new_nick);
                                sync(&c, registered, true, None);
                            }
                        }
                        drop(c);
                        fwd(&line);
                    }
                    "CHGHOST" => {
                        // Server changed our user@host mid-session — keep the learned
                        // value fresh so the web spoof guard stays accurate after reattach.
                        let who = nick_from_prefix(&p.prefix);
                        let mut c = conn.lock().await;
                        if irc_lower(&who) == irc_lower(&c.nick) {
                            if let (Some(u), Some(h)) = (p.params.first(), p.params.get(1)) {
                                // Bound + sanitize (serialized in every SessionSync).
                                if let Some(uh) = clean_userhost(&format!("{}@{}", u, h)) {
                                    c.self_userhost = uh;
                                    sync(&c, registered, true, None);
                                }
                            }
                        }
                        drop(c);
                        fwd(&line);
                    }

                    "PRIVMSG" => {
                        // CTCP VERSION is the one outbound action left that's
                        // purely protocol-level (not app-display logic) — rate
                        // limited exactly as before — everything else about
                        // PRIVMSG stays web-side (dispatch_line).
                        let text = p.params.get(1).cloned().unwrap_or_default();
                        if text == "\x01VERSION\x01" {
                            let from = nick_from_prefix(&p.prefix);
                            let now = Instant::now();
                            let allow = last_ctcp_reply.map_or(true, |t| now.duration_since(t) >= CTCP_REPLY_MIN_INTERVAL);
                            if allow {
                                last_ctcp_reply = Some(now);
                                let (ver, build) = resolve_ctcp_version(web_version);
                                conn.lock().await.send_raw(&format!(
                                    "NOTICE {} :\x01VERSION CryptIRC v{} · {} - Made by gh0st - Visit irc.twistednet.org #dev #twisted\x01\r\n",
                                    strip_crlf(&from),
                                    ver,
                                    build,
                                )).await?;
                            }
                        }
                        fwd(&line);
                    }

                    _ => {
                        fwd(&line);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trackable_channel_filter() {
        assert!(is_trackable_channel("#chan"));
        assert!(is_trackable_channel("&local"));
        assert!(is_trackable_channel("#Über")); // multibyte UTF-8 ok (serializes 1:1)
        assert!(!is_trackable_channel(""));
        assert!(!is_trackable_channel("nochanprefix"));
        assert!(!is_trackable_channel("#with\"quote"));
        assert!(!is_trackable_channel("#with\\backslash"));
        assert!(!is_trackable_channel("#with space"));
        assert!(!is_trackable_channel("#with,comma"));
        assert!(!is_trackable_channel("#with\u{01}ctrl"));
        assert!(!is_trackable_channel(&format!("#{}", "x".repeat(MAX_CHANNEL_NAME_LEN))));
    }

    #[test]
    fn clean_userhost_filter() {
        assert_eq!(clean_userhost("user@host.example"), Some("user@host.example".to_string()));
        assert!(clean_userhost("").is_none());
        assert!(clean_userhost(&format!("u@{}", "h".repeat(MAX_USERHOST_LEN))).is_none());
        assert!(clean_userhost("u@ho\"st").is_none());
        assert!(clean_userhost("u@ho\u{01}st").is_none());
    }

    // A fresh daemon (no web has Attached yet) must fall back to its own compiled
    // version — never send an empty/garbage CTCP VERSION reply.
    #[test]
    fn ctcp_version_falls_back_to_compiled_when_no_web_attach() {
        let cell = WebVersionCell::default();
        let (ver, build) = resolve_ctcp_version(&cell);
        assert_eq!(ver, env!("CARGO_PKG_VERSION"));
        assert_eq!(build, option_env!("CRYPTIRC_BUILD").unwrap_or("dev"));
    }

    // The whole point of this fix: once a web binary has Attached with its own
    // version, CTCP VERSION must quote THAT — not the daemon's own (possibly
    // stale, since it isn't restarted for a routine web-only redeploy) compiled
    // version.
    #[test]
    fn ctcp_version_prefers_web_announced_version() {
        let cell = WebVersionCell::default();
        cell.set("9.9.9".into(), "deadbee".into());
        let (ver, build) = resolve_ctcp_version(&cell);
        assert_eq!(ver, "9.9.9");
        assert_eq!(build, "deadbee");
    }

    /// The whole point of Byzantine-1: a WORST-CASE SessionSync — MAX_TRACKED_CHANNELS
    /// names each at MAX_CHANNEL_NAME_LEN, plus a max-length userhost/nick — must still
    /// serialize UNDER MAX_FRAME_LEN, so no hostile server can spoof self-JOINs to silence
    /// the state channel. All fields here pass the is_trackable_channel/clean_userhost
    /// filters, so they serialize 1:1 (no JSON escaping bloat).
    #[test]
    fn worst_case_sessionsync_fits_frame() {
        let channels: Vec<String> = (0..MAX_TRACKED_CHANNELS)
            .map(|i| {
                let mut s = format!("#{:07}", i);
                while s.len() < MAX_CHANNEL_NAME_LEN { s.push('x'); }
                s.truncate(MAX_CHANNEL_NAME_LEN);
                assert!(is_trackable_channel(&s));
                s
            })
            .collect();
        let msg = crate::ipc::IpcMessage::SessionSync {
            conn_id: "c".repeat(36),
            nick: "n".repeat(32),
            channels,
            registered: true,
            connected: true,
            lag_ms: Some(u64::MAX),
            message_tags: true,
            echo_message_enabled: true,
            self_userhost: clean_userhost(&format!("user@{}", "h".repeat(MAX_USERHOST_LEN - 5))).unwrap(),
        };
        let body = serde_json::to_vec(&msg).unwrap();
        assert!(
            body.len() < crate::ipc_framing::MAX_FRAME_LEN as usize,
            "worst-case SessionSync serialized to {} bytes, must be < MAX_FRAME_LEN ({})",
            body.len(), crate::ipc_framing::MAX_FRAME_LEN
        );
    }
}
