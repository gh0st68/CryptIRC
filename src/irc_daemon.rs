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

use crate::ipc::{ClientIdentity, ConnLifecycle, DialParams, IpcMessage};
use crate::ircproto::{
    irc_lower, nick_from_prefix, parse_irc, read_capped_line, strip_crlf, truncate_chars,
    CappedLine, MAX_IRC_LINE_LEN,
};
use anyhow::Result;
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
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_NICK_RETRIES: u32 = 5;
const MAX_SASL_RETRIES: u32 = 3;
/// #45 (carried over): minimum interval between automatic CTCP replies.
const CTCP_REPLY_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// #31 (carried over): inbound line rate limit (token bucket).
const INBOUND_RATE_BURST: f64 = 1024.0;
const INBOUND_RATE_REFILL: f64 = 64.0;

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
}

impl DaemonConn {
    async fn send_raw(&mut self, line: &str) -> Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
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
    mut cmd_rx: mpsc::UnboundedReceiver<DaemonCmd>,
) where
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let mut delay = RECONNECT_BASE;
    let mut attempt = 0u32;
    let mut sasl_failures = 0u32;
    let original_sasl_external = params.sasl_external;

    loop {
        attempt += 1;
        info!(
            "[{}] Connect attempt {} → {}:{} (sasl_external={})",
            conn_id, attempt, params.server, params.port, params.sasl_external
        );
        emit(IpcMessage::ConnStatus {
            conn_id: conn_id.clone(),
            state: ConnLifecycle::Connecting,
        });

        let mut stopped = false;
        let result = do_connect(&conn_id, &params, &emit, &mut cmd_rx, &mut stopped).await;

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
                warn!("[{}] Server closed connection. Reconnecting in {:?}", conn_id, RECONNECT_BASE);
                delay = RECONNECT_BASE;
                attempt = 0;
                sasl_failures = 0;
                params.sasl_external = original_sasl_external;
            }
            Err(e) => {
                let msg = e.to_string();
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
        // instead of waiting out the full delay before honoring it.
        tokio::select! {
            _ = sleep(delay) => {}
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
                    // No live connection to send to while backing off; drop silently.
                    Some(DaemonCmd::RawSend(_)) => {}
                    // Sender side gone (server task exited) — nothing more will
                    // ever arrive for this conn_id; stop rather than spin forever.
                    None => return,
                }
            }
        }
        delay = (delay * 2).min(RECONNECT_MAX);
    }
}

/// One connection attempt: dial, TLS (with or without client cert), then run
/// the registration + read loop. Mirrors `irc::do_connect()`.
async fn do_connect<F>(
    conn_id: &str,
    params: &DialParams,
    emit: &F,
    cmd_rx: &mut mpsc::UnboundedReceiver<DaemonCmd>,
    stopped: &mut bool,
) -> Result<()>
where
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let addr = format!("{}:{}", params.server, params.port);
    let tcp = TcpStream::connect(&addr).await?;
    tcp.set_nodelay(true)?;

    if params.tls {
        if let Some(ClientIdentity { cert_pem, key_pem }) = &params.client_identity {
            // Client cert path: openssl directly, TLS 1.3 post-handshake auth
            // (matches irc.rs's do_connect exactly, minus the CertStore/vault
            // lookup — the PEM bytes already arrived decrypted in DialParams).
            drop(tcp);
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
            let tcp2 = TcpStream::connect(&addr).await?;
            tcp2.set_nodelay(true)?;
            let ssl = connector.configure()?.into_ssl(&params.server)?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp2)?;
            std::pin::Pin::new(&mut stream).connect().await?;
            info!("[{}] TLS connected with client cert (post-handshake auth enabled)", conn_id);
            run_loop(conn_id, params, emit, stream, cmd_rx, stopped).await
        } else if params.sasl_external {
            // Config asked for SASL EXTERNAL but no identity was resolved — the
            // web side failed to decrypt/find the cert at Dial time. Retrying
            // won't self-heal (params never change without a fresh Dial), but
            // we still go through the normal backoff path for now rather than
            // inventing a separate "terminal, don't retry" signal — a future
            // phase with real Dial/Attach request-response semantics may want
            // to short-circuit this case instead.
            Err(anyhow::anyhow!("SASL_RETRY: client identity missing for SASL EXTERNAL"))
        } else {
            let mut builder = native_tls::TlsConnector::builder();
            if params.tls_accept_invalid_certs {
                builder.danger_accept_invalid_certs(true);
            }
            let tls = tokio_native_tls::TlsConnector::from(builder.build()?)
                .connect(&params.server, tcp)
                .await?;
            run_loop(conn_id, params, emit, tls, cmd_rx, stopped).await
        }
    } else {
        run_loop(conn_id, params, emit, tcp, cmd_rx, stopped).await
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
    cmd_rx: &mut mpsc::UnboundedReceiver<DaemonCmd>,
    stopped: &mut bool,
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
    }));

    let sync = |c: &DaemonConn, registered: bool, connected: bool, lag_ms: Option<u64>| {
        emit(IpcMessage::SessionSync {
            conn_id: conn_id.to_string(),
            nick: c.nick.clone(),
            channels: c.channels.iter().cloned().collect(),
            registered,
            connected,
            lag_ms,
        });
    };
    let fwd = |line: &str| emit(IpcMessage::RawLine { conn_id: conn_id.to_string(), line: line.to_string() });

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
    let mut ping_out = false;
    let mut nick_retries = 0u32;
    let mut last_ctcp_reply: Option<Instant> = None;

    let efnet = params.label.to_lowercase().contains("efnet") || params.server.to_lowercase().contains("efnet");
    if efnet {
        info!("[{}] EFnet detected (label='{}' server='{}') — IRCv3 caps disabled", conn_id, params.label, params.server);
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
    // Once cmd_rx closes (all senders dropped), `.recv()` resolves to `None`
    // IMMEDIATELY on every poll — without this guard the select! below would
    // busy-spin that branch forever instead of blocking on the others.
    let mut cmd_closed = false;

    loop {
        tokio::select! {
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
            // Guarded by `!cmd_closed` so a closed channel stops being polled
            // instead of resolving to None on every loop iteration.
            cmd = cmd_rx.recv(), if !cmd_closed => {
                match cmd {
                    Some(DaemonCmd::RawSend(line)) => {
                        conn.lock().await.send_raw(&line).await?;
                    }
                    Some(DaemonCmd::Drop(reason)) => {
                        let _ = conn.lock().await.send_raw(&format!("QUIT :{}\r\n", strip_crlf(&reason))).await;
                        *stopped = true;
                        return Ok(());
                    }
                    // Sender side gone — server task exited; stop polling this
                    // branch but keep running the connection itself.
                    None => { cmd_closed = true; }
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
                        last_pong = Instant::now();
                        ping_out = false;
                        if let Some(sent) = tok.strip_prefix("hb-").and_then(|s| s.parse::<u64>().ok()) {
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
                        last_pong = Instant::now();
                        let actual_nick = {
                            let mut c = conn.lock().await;
                            if let Some(real) = p.params.get(0) {
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
                        let mut c = conn.lock().await;
                        if irc_lower(&who) == irc_lower(&c.nick) {
                            if let Some(chan) = p.params.get(0) {
                                c.channels.insert(irc_lower(chan));
                                sync(&c, registered, true, None);
                            }
                        }
                        drop(c);
                        fwd(&line);
                    }
                    "PART" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut c = conn.lock().await;
                        if irc_lower(&who) == irc_lower(&c.nick) {
                            if let Some(chan) = p.params.get(0) {
                                c.channels.remove(&irc_lower(chan));
                                sync(&c, registered, true, None);
                            }
                        }
                        drop(c);
                        fwd(&line);
                    }
                    "KICK" => {
                        let mut c = conn.lock().await;
                        if let Some(kicked) = p.params.get(1) {
                            if irc_lower(kicked) == irc_lower(&c.nick) {
                                if let Some(chan) = p.params.get(0) {
                                    c.channels.remove(&irc_lower(chan));
                                    sync(&c, registered, true, None);
                                }
                            }
                        }
                        drop(c);
                        fwd(&line);
                    }
                    "NICK" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut c = conn.lock().await;
                        if irc_lower(&who) == irc_lower(&c.nick) {
                            if let Some(new_nick) = p.params.get(0) {
                                c.nick = strip_crlf(new_nick);
                                sync(&c, registered, true, None);
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
                                conn.lock().await.send_raw(&format!(
                                    "NOTICE {} :\x01VERSION CryptIRC v{} · {} - Made by gh0st - Visit irc.twistednet.org #dev #twisted\x01\r\n",
                                    strip_crlf(&from),
                                    env!("CARGO_PKG_VERSION"),
                                    option_env!("CRYPTIRC_BUILD").unwrap_or("dev"),
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
