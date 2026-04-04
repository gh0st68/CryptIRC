//! irc.rs — IRC connection handler
//!
//! Fixes this pass:
//!   B1/B2 — removed unused imports (AtomicBool, Ordering, SaslConfig)
//!   S3    — names_buf bounded (max 512 channels × 4096 entries each)
//!   S4    — nick collision aborts after MAX_NICK_RETRIES attempts
//!   L1    — auto_reconnect flag respected in outer connect() loop
//!   L3    — stale IrcConnection removed from map on run_loop exit

use anyhow::Result;
use std::{collections::HashMap, sync::Arc};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
    time::{sleep, timeout, Duration, Instant},
};
use tracing::{error, info, warn};

use crate::{certs::CertStore, strip_crlf, AppState, MessageKind, NetworkConfig, ServerEvent};

// ─── Constants ────────────────────────────────────────────────────────────────

const PING_INTERVAL:     Duration = Duration::from_secs(30);
const PONG_TIMEOUT:      Duration = Duration::from_secs(90);
const RECONNECT_BASE:    Duration = Duration::from_secs(5);
const RECONNECT_MAX:     Duration = Duration::from_secs(300);
const READ_TIMEOUT:      Duration = Duration::from_secs(120);
/// S4: maximum number of times we'll retry a nick before aborting registration
const MAX_NICK_RETRIES:  u32 = 5;
/// S3: maximum total channels in names_buf
const NAMES_BUF_MAX_CHANNELS: usize = 512;
/// S3: maximum entries per channel in names_buf
const NAMES_BUF_MAX_PER_CHAN: usize = 4096;
/// S7: maximum IRC line length (prevent memory exhaustion from rogue server)
const MAX_IRC_LINE_LEN: usize = 8192;

// ─── Public types ─────────────────────────────────────────────────────────────

pub struct ChannelState {
    pub topic: String,
    pub names: Vec<String>,
}

pub struct IrcConnection {
    pub conn_id:   String,
    pub nick:      String,
    pub connected: bool,
    pub lag_ms:    Option<u64>,
    pub channels:  HashMap<String, ChannelState>,
    pub writer:    Box<dyn AsyncWrite + Send + Unpin>,
    pub message_tags: bool,
}

impl IrcConnection {
    pub async fn send_raw(&mut self, line: &str) -> Result<()> {
        self.writer.write_all(line.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }
}

// ─── SASL types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum SaslState {
    Idle,
    CapLsSent,
    CapReqSent,
    AuthenticateSent,
    Done,
    Failed(String),
}

#[derive(Debug, Clone)]
enum SaslMethod {
    Plain    { account: String, password: String },
    External,
}

// ─── Entry point: reconnect loop ─────────────────────────────────────────────

pub async fn connect(
    conn_id:  String,
    cfg:      NetworkConfig,
    username: String,
    state:    AppState,
) -> Result<()> {
    let mut delay   = RECONNECT_BASE;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!("[{}] Connect attempt {} → {}:{}", conn_id, attempt, cfg.server, cfg.port);
        state.send_to_user(&username, ServerEvent::Connecting {
            conn_id: conn_id.clone(),
            server:  cfg.server.clone(),
        });

        let result = do_connect(&conn_id, &cfg, &username, &state).await;

        // Always remove dead connection from map immediately (L3)
        state.connections.remove(&conn_id);
        state.conn_owners.remove(&conn_id);

        // User-requested disconnect → stop regardless of result
        if state.disconnect_requested(&conn_id) {
            info!("[{}] Disconnect requested, stopping reconnect loop", conn_id);
            state.clear_disconnect_request(&conn_id);
            state.send_to_user(&username, ServerEvent::Disconnected {
                conn_id: conn_id.clone(),
                reason:  "User requested".into(),
            });
            return Ok(());
        }

        // L1: respect auto_reconnect flag
        if !cfg.auto_reconnect {
            info!("[{}] auto_reconnect=false, not reconnecting", conn_id);
            let reason = match &result {
                Ok(_)  => "Clean disconnect".to_string(),
                Err(e) => e.to_string(),
            };
            state.send_to_user(&username, ServerEvent::Disconnected {
                conn_id: conn_id.clone(), reason,
            });
            return Ok(());
        }

        match result {
            Ok(_) => {
                // Server sent clean close — reset backoff since we were connected
                warn!("[{}] Server closed connection. Reconnecting in {:?}", conn_id, RECONNECT_BASE);
                delay = RECONNECT_BASE;
                attempt = 0;
            }
            Err(e) => {
                warn!("[{}] Connection error: {}. Reconnecting in {:?}", conn_id, e, delay);
                state.send_to_user(&username, ServerEvent::Reconnecting {
                    conn_id:    conn_id.clone(),
                    attempt,
                    delay_secs: delay.as_secs(),
                    reason:     e.to_string(),
                });
            }
        }

        sleep(delay).await;
        delay = (delay * 2).min(RECONNECT_MAX);
    }
}

// ─── Single connection attempt ────────────────────────────────────────────────

async fn do_connect(
    conn_id:  &str,
    cfg:      &NetworkConfig,
    username: &str,
    state:    &AppState,
) -> Result<()> {
    let addr = format!("{}:{}", cfg.server, cfg.port);
    let tcp  = TcpStream::connect(&addr).await?;
    tcp.set_nodelay(true)?;

    if cfg.tls {
        let identity = if let Some(ref cert_id) = cfg.client_cert_id {
            info!("[{}] Client cert ID configured: {}", conn_id, cert_id);
            let store = CertStore::new(&state.data_dir, state.crypto.clone());
            if store.exists(cert_id).await {
                info!("[{}] Cert files found, loading identity...", conn_id);
                match store.load_identity(username, cert_id).await {
                    Ok(id) => { info!("[{}] Client cert loaded successfully", conn_id); Some(id) }
                    Err(e) => { warn!("[{}] Client cert load FAILED: {}", conn_id, e); None }
                }
            } else { warn!("[{}] Cert files NOT found for {}", conn_id, cert_id); None }
        } else { info!("[{}] No client_cert_id configured", conn_id); None };

        if identity.is_some() {
            // Use openssl directly for client cert — need post_handshake_auth for TLS 1.3
            drop(tcp); // We'll create a fresh connection
            let mut ssl_builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls_client())?;
            // Client cert path uses openssl directly for TLS 1.3 post-handshake auth.
            if cfg.tls_accept_invalid_certs {
                ssl_builder.set_verify(openssl::ssl::SslVerifyMode::NONE);
            } else {
                // Load system CA certs for proper server cert verification
                if let Err(e) = ssl_builder.set_ca_file("/etc/ssl/certs/ca-certificates.crt") {
                    warn!("[{}] Failed to load CA certs, falling back to default paths: {}", conn_id, e);
                    let _ = ssl_builder.set_default_verify_paths();
                }
            }
            // Load client cert + key from PEM
            let cert_id = cfg.client_cert_id.as_ref().unwrap();
            let dir = std::path::PathBuf::from(&state.data_dir).join("certs").join(cert_id);
            let cert_pem = tokio::fs::read(dir.join("cert.pem")).await?;
            let key_enc = tokio::fs::read_to_string(dir.join("key.enc")).await?;
            let key_pem = state.crypto.decrypt(username, key_enc.trim()).await?;
            let x509 = openssl::x509::X509::from_pem(&cert_pem)?;
            let pkey = openssl::pkey::PKey::private_key_from_pem(&key_pem)?;
            ssl_builder.set_certificate(&x509)?;
            ssl_builder.set_private_key(&pkey)?;
            // Enable post-handshake auth for TLS 1.3 client certs
            unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(ssl_builder.as_ptr() as *mut _, 1); }
            let connector = ssl_builder.build();
            let tcp2 = TcpStream::connect(&addr).await?;
            tcp2.set_nodelay(true)?;
            let mut ssl = openssl::ssl::Ssl::new(connector.context())?;
            ssl.set_hostname(&cfg.server)?;
            let mut stream = tokio_openssl::SslStream::new(ssl, tcp2)?;
            std::pin::Pin::new(&mut stream).connect().await?;
            info!("[{}] TLS connected with client cert (post-handshake auth enabled)", conn_id);
            run_loop(conn_id, cfg, username, state, stream).await
        } else {
            let mut builder = native_tls::TlsConnector::builder();
            if cfg.tls_accept_invalid_certs {
                builder.danger_accept_invalid_certs(true);
            }
            let tls = tokio_native_tls::TlsConnector::from(builder.build()?)
                .connect(&cfg.server, tcp).await?;
            run_loop(conn_id, cfg, username, state, tls).await
        }
    } else {
        run_loop(conn_id, cfg, username, state, tcp).await
    }
}

// ─── Main read/write loop ─────────────────────────────────────────────────────

async fn run_loop<S>(
    conn_id:  &str,
    cfg:      &NetworkConfig,
    username: &str,
    state:    &AppState,
    stream:   S,
) -> Result<()>
where S: AsyncRead + AsyncWrite + Send + Unpin + 'static
{
    let (read_half, write_half) = tokio::io::split(stream);
    let conn = Arc::new(Mutex::new(IrcConnection {
        conn_id: conn_id.to_string(), nick: cfg.nick.clone(),
        connected: false, lag_ms: None,
        channels: HashMap::new(), writer: Box::new(write_half),
        message_tags: false,
    }));

    state.connections.insert(conn_id.to_string(), conn.clone());
    state.conn_owners.insert(conn_id.to_string(), username.to_string());

    let send = |evt: ServerEvent| state.send_to_user(username, evt);

    // SASL method selection — refuse SASL PLAIN over non-TLS to prevent cleartext credential leak
    let sasl_method: Option<SaslMethod> = if cfg.sasl_external {
        Some(SaslMethod::External)
    } else if let Some(ref sc) = cfg.sasl_plain {
        if !cfg.tls {
            warn!("[{}] SASL PLAIN disabled — TLS is off, credentials would travel in cleartext", conn_id);
            send(ServerEvent::IrcMessage {
                conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                text: "⚠ SASL PLAIN disabled — cannot send credentials over an unencrypted connection. Enable TLS or use SASL EXTERNAL.".into(),
                ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, prefix: None,
            });
            None
        } else {
            Some(SaslMethod::Plain { account: sc.account.clone(), password: sc.password.clone() })
        }
    } else { None };

    let use_sasl        = sasl_method.is_some();
    let mut sasl_state  = SaslState::Idle;
    // IRCv3 state
    let mut available_caps: Vec<String> = Vec::new();
    let mut echo_message_enabled = false;
    info!("[{}] SASL config: method={:?} use_sasl={}", conn_id, sasl_method.as_ref().map(|m| match m { SaslMethod::External => "EXTERNAL", SaslMethod::Plain{..} => "PLAIN" }), use_sasl);
    let mut last_pong   = Instant::now();
    let mut ping_out    = false;
    // S4: track nick collision count
    let mut nick_retries = 0u32;

    // Registration — always request CAP LS 302 to negotiate IRCv3 caps
    {
        let mut c = conn.lock().await;
        if let Some(ref pass) = cfg.password {
            c.send_raw(&format!("PASS {}\r\n", strip_crlf(pass))).await?;
        }
        c.send_raw("CAP LS 302\r\n").await?;
        if use_sasl {
            sasl_state = SaslState::CapLsSent;
        }
        c.send_raw(&format!("NICK {}\r\n", strip_crlf(&cfg.nick))).await?;
        c.send_raw(&format!("USER {} 0 * :{}\r\n", strip_crlf(&cfg.username), strip_crlf(&cfg.realname))).await?;
    }

    let mut reader     = BufReader::new(read_half).lines();
    let mut registered = false;
    // S3: bounded names accumulation buffer
    let mut names_buf: HashMap<String, Vec<String>> = HashMap::with_capacity(32);
    let mut ping_ticker = tokio::time::interval(PING_INTERVAL);

    loop {
        tokio::select! {
            // ── Heartbeat ─────────────────────────────────────────────────
            _ = ping_ticker.tick() => {
                if ping_out && last_pong.elapsed() > PONG_TIMEOUT {
                    warn!("[{}] PONG timeout, triggering reconnect", conn_id);
                    conn.lock().await.connected = false;
                    return Err(anyhow::anyhow!("PONG timeout — server unresponsive"));
                }
                if registered {
                    let ts = chrono::Utc::now().timestamp_millis() as u64;
                    conn.lock().await.send_raw(&format!("PING :hb-{}\r\n", ts)).await?;
                    ping_out = true;
                }
            }

            // ── Incoming line ──────────────────────────────────────────────
            res = timeout(READ_TIMEOUT, reader.next_line()) => {
                let line = match res {
                    Err(_)          => return Err(anyhow::anyhow!("Read timeout")),
                    Ok(Ok(Some(l))) => l,
                    Ok(Ok(None))    => return Ok(()), // clean server close
                    Ok(Err(e))      => return Err(e.into()),
                };
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.is_empty() { continue; }
                // S7: reject extremely long lines to prevent memory exhaustion
                if line.len() > MAX_IRC_LINE_LEN {
                    warn!("[{}] Dropping oversized IRC line ({} bytes)", conn_id, line.len());
                    continue;
                }

                let p  = parse_irc(&line);
                // Prefer IRCv3 server-time tag when available
                let ts = p.tags.get("time")
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|dt| dt.timestamp())
                    .unwrap_or_else(|| chrono::Utc::now().timestamp());

                match p.command.as_str() {

                    "PING" => {
                        let tok = p.params.last().cloned().unwrap_or_default();
                        conn.lock().await.send_raw(&format!("PONG :{}\r\n", tok)).await?;
                    }
                    "PONG" => {
                        let tok = p.params.last().cloned().unwrap_or_default();
                        last_pong = Instant::now();
                        ping_out  = false;
                        if tok.starts_with("hb-") {
                            if let Ok(sent) = tok[3..].parse::<u64>() {
                                let ms = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(sent);
                                conn.lock().await.lag_ms = Some(ms);
                                send(ServerEvent::LagUpdate { conn_id: conn_id.to_string(), ms });
                            }
                        }
                    }

                    // ── CAP / SASL ───────────────────────────────────────
                    "CAP" => {
                        let sub  = p.params.get(1).map(|s| s.as_str()).unwrap_or("");
                        // CAP LS 302 may split across multiple lines — last param has caps
                        // For multiline: params = [nick, "LS", "*", caps] (more coming) or [nick, "LS", caps] (final)
                        let is_multiline = p.params.get(2).map(|s| s.as_str()) == Some("*");
                        let caps = if is_multiline {
                            p.params.get(3).cloned().unwrap_or_default()
                        } else {
                            p.params.last().cloned().unwrap_or_default()
                        };
                        match sub {
                            "LS" => {
                                // Accumulate available caps across multiline responses
                                for cap in caps.split_whitespace() {
                                    let cap_name = cap.split('=').next().unwrap_or(cap);
                                    available_caps.push(cap_name.to_string());
                                }
                                // If multiline (*), wait for more LS lines
                                if is_multiline { continue; }

                                // All caps received — request the ones we want
                                let wanted: &[&str] = &[
                                    "away-notify", "account-notify", "extended-join",
                                    "server-time", "multi-prefix", "cap-notify",
                                    "message-tags", "batch", "echo-message",
                                    "invite-notify", "setname", "account-tag",
                                    "userhost-in-names", "chghost", "labeled-response",
                                    "draft/typing", "typing",
                                    "standard-replies",
                                ];
                                let mut req: Vec<&str> = Vec::new();
                                for w in wanted {
                                    // Skip caps the user has disabled for this network
                                    if cfg.disabled_caps.iter().any(|d| d == w) { continue; }
                                    if available_caps.iter().any(|c| c == w) {
                                        req.push(w);
                                    }
                                }
                                // Note: echo_message_enabled and message_tags are set in CAP ACK handler, not here
                                // Request IRCv3 caps first (without sasl)
                                if !req.is_empty() {
                                    let req_str = req.join(" ");
                                    info!("[{}] Requesting CAPs: {}", conn_id, req_str);
                                    conn.lock().await.send_raw(&format!("CAP REQ :{}\r\n", req_str)).await?;
                                }
                                // SASL — request separately to avoid batch rejection
                                if use_sasl && available_caps.iter().any(|c| c == "sasl") {
                                    conn.lock().await.send_raw("CAP REQ :sasl\r\n").await?;
                                    sasl_state = SaslState::CapReqSent;
                                } else if use_sasl {
                                    warn!("[{}] Server has no sasl cap", conn_id);
                                    sasl_state = SaslState::Done;
                                    send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: "Server does not support SASL".into() });
                                    if req.is_empty() { conn.lock().await.send_raw("CAP END\r\n").await?; }
                                } else if req.is_empty() {
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                }
                                available_caps.clear();
                            }
                            "ACK" => {
                                info!("[{}] CAP ACK: {}", conn_id, caps);
                                // L43: Set capability flags on ACK, not on REQ
                                if caps.contains("echo-message") { echo_message_enabled = true; }
                                if caps.contains("message-tags") { conn.lock().await.message_tags = true; }
                                if caps.contains("sasl") && sasl_state == SaslState::CapReqSent {
                                    // SASL cap accepted — start authentication
                                    let method = match &sasl_method {
                                        Some(SaslMethod::External)     => "EXTERNAL",
                                        Some(SaslMethod::Plain { .. }) => "PLAIN",
                                        None                            => "PLAIN",
                                    };
                                    conn.lock().await.send_raw(&format!("AUTHENTICATE {}\r\n", method)).await?;
                                    sasl_state = SaslState::AuthenticateSent;
                                } else if !caps.contains("sasl") && !use_sasl {
                                    // Non-SASL caps ACKed and no SASL needed
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                }
                                // If SASL is pending (CapReqSent/AuthenticateSent), don't send CAP END yet
                            }
                            "NAK" => {
                                warn!("[{}] CAP NAK: {}", conn_id, caps);
                                if use_sasl && caps.contains("sasl") {
                                    sasl_state = SaslState::Failed("CAP NAK".into());
                                    send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: "SASL capability rejected".into() });
                                }
                                conn.lock().await.send_raw("CAP END\r\n").await?;
                            }
                            "NEW" => {
                                // cap-notify: server advertises new caps
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
                                    if cfg.disabled_caps.iter().any(|d| d == cap_name) { continue; }
                                    if wanted.contains(&cap_name) {
                                        req.push(cap_name);
                                    }
                                }
                                if !req.is_empty() {
                                    let req_str = req.join(" ");
                                    conn.lock().await.send_raw(&format!("CAP REQ :{}\r\n", req_str)).await?;
                                }
                            }
                            "DEL" => {
                                info!("[{}] CAP DEL: {}", conn_id, caps);
                                if caps.contains("echo-message") {
                                    echo_message_enabled = false;
                                }
                            }
                            _ => {}
                        }
                    }

                    "AUTHENTICATE" => {
                        if p.params.first().map(|s| s.as_str()) == Some("+")
                            && sasl_state == SaslState::AuthenticateSent
                        {
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
                            info!("[{}] SASL AUTHENTICATE response: {}", conn_id, if response == "+" { "+" } else { "<redacted>" });
                            conn.lock().await.send_raw(&format!("AUTHENTICATE {}\r\n", response)).await?;
                        }
                    }

                    "900" => {
                        let account = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: true, message: format!("Logged in as {}", account) });
                    }
                    "903" => {
                        sasl_state = SaslState::Done;
                        conn.lock().await.send_raw("CAP END\r\n").await?;
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: true, message: "SASL authentication successful".into() });
                    }
                    "902" | "904" | "905" | "906" | "907" => {
                        let reason = p.params.last().cloned().unwrap_or_else(|| "SASL failed".into());
                        sasl_state = SaslState::Failed(reason.clone());
                        conn.lock().await.send_raw("CAP END\r\n").await?;
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: reason });
                    }

                    // ── Welcome ──────────────────────────────────────────
                    "001" => {
                        registered = true;
                        last_pong  = Instant::now();
                        let actual_nick = {
                            let mut c = conn.lock().await;
                            c.connected = true;
                            c.nick.clone()
                        };
                        send(ServerEvent::Connected { conn_id: conn_id.to_string(), server: cfg.server.clone(), nick: actual_nick });
                        // Send OPER if configured
                        if let (Some(login), Some(pass)) = (&cfg.oper_login, &cfg.oper_pass) {
                            if !login.is_empty() && !pass.is_empty() {
                                conn.lock().await.send_raw(&format!("OPER {} {}\r\n", strip_crlf(login), strip_crlf(pass))).await?;
                            }
                        }
                        // Auto-identify with NickServ
                        if cfg.auto_identify {
                            if let Some(ref pass) = cfg.nickserv_pass {
                                if !pass.is_empty() {
                                    conn.lock().await.send_raw(&format!("PRIVMSG NickServ :IDENTIFY {}\r\n", strip_crlf(pass))).await?;
                                }
                            }
                        }
                        for ch in &cfg.auto_join {
                            let safe = strip_crlf(ch);
                            if !safe.is_empty() {
                                conn.lock().await.send_raw(&format!("JOIN {}\r\n", safe)).await?;
                            }
                        }
                    }

                    // S4: bounded nick collision retry
                    "432" | "433" | "436" => {
                        nick_retries += 1;
                        if nick_retries > MAX_NICK_RETRIES {
                            return Err(anyhow::anyhow!("Nick collision: exhausted {} retries", MAX_NICK_RETRIES));
                        }
                        let mut c = conn.lock().await;
                        // Truncate to 28 chars before appending to stay within limits
                        let base = if c.nick.len() > 28 { c.nick[..28].to_string() } else { c.nick.clone() };
                        let new_nick = format!("{}_{}", base, nick_retries);
                        c.nick = new_nick.clone();
                        c.send_raw(&format!("NICK {}\r\n", new_nick)).await?;
                    }

                    "PRIVMSG" => {
                        let from   = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let text   = p.params.get(1).cloned().unwrap_or_default();
                        let user_nick = { conn.lock().await.nick.clone() };
                        // echo-message: if server echoes our own PRIVMSG, skip it here —
                        // the Send handler already broadcasts IrcEcho for multi-device sync
                        // Don't suppress echo for batch messages (chathistory/+H playback)
                        let in_batch = p.tags.contains_key("batch");
                        if echo_message_enabled && from == user_nick && !in_batch {
                            if let Some(ref pfx) = p.prefix {
                                if pfx.contains('!') {
                                    continue;
                                }
                            }
                        }
                        // Reply to CTCP VERSION
                        if text == "\x01VERSION\x01" {
                            conn.lock().await.send_raw(&format!(
                                "NOTICE {} :\x01VERSION CryptIRC v0.9.0 - Made by gh0st - Visit irc.twistednet.org #dev #twisted\x01\r\n",
                                from
                            )).await?;
                            continue;
                        }
                        let (kind, clean) = if text.starts_with("\x01ACTION ") && text.ends_with('\x01') {
                            (MessageKind::Action, text[8..text.len()-1].to_string())
                        } else { (MessageKind::Privmsg, text) };
                        // Route PMs to sender's nick, not our own nick
                        let display_target = if target.starts_with(['#','&']) { target.clone() } else { from.clone() };
                        state.logger.append(username, conn_id, &display_target, ts, &from, &clean, kind_str(&kind)).await;
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: from.clone(), target: display_target.clone(), text: clean.clone(), ts, kind, prefix: p.prefix.clone() });
                        // Push notification for DMs and mentions
                        if from != user_nick {
                            state.notifier.maybe_notify(
                                username, &user_nick, conn_id, &cfg.label, &display_target, &from, &clean
                            ).await;
                        }
                    }
                    "NOTICE" => {
                        let from   = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let text   = p.params.get(1).cloned().unwrap_or_default();
                        info!("[{}] NOTICE: from={} target={} text={}", conn_id, from, target, &text[..text.len().min(120)]);
                        // Route notices to sender's nick (e.g. NickServ), not our own nick
                        // Server notices (no prefix or from server hostname) go to status
                        let display_target = if target.starts_with(['#','&']) {
                            target.clone()
                        } else if from == "*" || from.contains('.') || p.prefix.is_none() {
                            "status".to_string()
                        } else {
                            from.clone()
                        };
                        state.logger.append(username, conn_id, &display_target, ts, &from, &text, "notice").await;
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from, target: display_target, text, ts, kind: MessageKind::Notice, prefix: None });
                    }

                    "JOIN" => {
                        let nick    = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        // IRCv3 extended-join: JOIN #channel account :realname
                        let account  = p.params.get(1).cloned().unwrap_or_default();
                        let realname = p.params.get(2).cloned().unwrap_or_default();
                        // Also check account-tag
                        let account = if account.is_empty() || account == "*" {
                            p.tags.get("account").cloned().unwrap_or_default()
                        } else if account == "*" { String::new() } else { account };
                        {
                            let mut c = conn.lock().await;
                            if nick == c.nick {
                                c.channels.entry(channel.clone()).or_insert(ChannelState { topic: String::new(), names: vec![] });
                                c.send_raw(&format!("NAMES {}\r\n", channel)).await?;
                            } else if let Some(ch) = c.channels.get_mut(&channel) {
                                if ch.names.len() < NAMES_BUF_MAX_PER_CHAN { ch.names.push(nick.clone()); }
                            }
                        }
                        send(ServerEvent::IrcJoinEx {
                            conn_id: conn_id.to_string(), nick, channel,
                            account, realname, ts,
                        });
                    }
                    "PART" => {
                        let nick    = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let reason  = p.params.get(1).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; if nick == c.nick { c.channels.remove(&channel); } else if let Some(ch) = c.channels.get_mut(&channel) { ch.names.retain(|n| strip_pfx(n) != nick); } }
                        send(ServerEvent::IrcPart { conn_id: conn_id.to_string(), nick, channel, reason, ts });
                    }
                    "QUIT" => {
                        let nick   = nick_from_prefix(&p.prefix);
                        let reason = p.params.get(0).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; for ch in c.channels.values_mut() { ch.names.retain(|n| strip_pfx(n) != nick); } }
                        send(ServerEvent::IrcQuit { conn_id: conn_id.to_string(), nick, reason, ts });
                    }
                    "NICK" => {
                        let old = nick_from_prefix(&p.prefix);
                        let new = p.params.get(0).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; if old == c.nick { c.nick = new.clone(); } for ch in c.channels.values_mut() { for n in ch.names.iter_mut() { if strip_pfx(n) == old { let pfx: String = n.chars().take_while(|c| "@+~&%".contains(*c)).collect(); *n = format!("{}{}", pfx, new); } } } }
                        send(ServerEvent::IrcNick { conn_id: conn_id.to_string(), old, new, ts });
                    }
                    "CHGHOST" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let new_host = p.params.get(1).cloned().unwrap_or_else(|| p.params.get(0).cloned().unwrap_or_default());
                        let c = conn.lock().await;
                        let chans: Vec<String> = c.channels.iter()
                            .filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n) == nick))
                            .map(|(name, _)| name.clone())
                            .collect();
                        drop(c);
                        for ch in &chans {
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(), from: "*".into(), target: ch.clone(),
                                text: format!("*** {} has changed hostname to {}", nick, new_host),
                                ts, kind: MessageKind::Notice,
                                prefix: None,
                            });
                        }
                        if chans.is_empty() {
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                                text: format!("*** {} has changed hostname to {}", nick, new_host),
                                ts, kind: MessageKind::Notice,
                                prefix: None,
                            });
                        }
                    }
                    // ── IRCv3: away-notify ───────────────────────────
                    "AWAY" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let message = p.params.get(0).cloned().unwrap_or_default();
                        let is_away = !message.is_empty();
                        send(ServerEvent::IrcAway {
                            conn_id: conn_id.to_string(), nick: nick.clone(),
                            away: is_away, message: message.clone(), ts,
                        });
                    }
                    // ── IRCv3: account-notify ────────────────────────
                    "ACCOUNT" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let account = p.params.get(0).cloned().unwrap_or_default();
                        let logged_in = account != "*";
                        send(ServerEvent::IrcAccount {
                            conn_id: conn_id.to_string(), nick: nick.clone(),
                            account: if logged_in { account.clone() } else { String::new() }, ts,
                        });
                    }
                    // ── IRCv3: invite-notify ─────────────────────────
                    "INVITE" => {
                        let from = nick_from_prefix(&p.prefix);
                        let target_nick = p.params.get(0).cloned().unwrap_or_default();
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcInvite {
                            conn_id: conn_id.to_string(), from: from.clone(),
                            target: target_nick.clone(), channel: channel.clone(), ts,
                        });
                    }
                    // ── IRCv3: setname ───────────────────────────────
                    "SETNAME" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let realname = p.params.get(0).cloned().unwrap_or_default();
                        send(ServerEvent::IrcSetname {
                            conn_id: conn_id.to_string(), nick: nick.clone(),
                            realname: realname.clone(), ts,
                        });
                    }
                    // ── IRCv3: TAGMSG (typing indicators, reactions) ─
                    "TAGMSG" => {
                        let from = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        // Check for typing indicator (+typing or +draft/typing tag)
                        if let Some(typing_state) = p.tags.get("+typing").or_else(|| p.tags.get("+draft/typing")) {
                            let our_nick = conn.lock().await.nick.clone();
                            if from != our_nick {
                                let display_target = if target.starts_with(['#','&']) { target } else { from.clone() };
                                send(ServerEvent::IrcTyping {
                                    conn_id: conn_id.to_string(), nick: from,
                                    target: display_target,
                                    state: typing_state.clone(), // "active", "paused", or "done"
                                });
                            }
                        }
                    }
                    // ── IRCv3: BATCH ─────────────────────────────────
                    "BATCH" => {
                        // +ref opens a batch, -ref closes it
                        // For now, just log — individual messages within batches
                        // are handled normally via their own handlers
                        let ref_tag = p.params.get(0).cloned().unwrap_or_default();
                        let batch_type = p.params.get(1).cloned().unwrap_or_default();
                        if ref_tag.starts_with('+') {
                            info!("[{}] BATCH opened: {} type={}", conn_id, ref_tag, batch_type);
                        } else {
                            info!("[{}] BATCH closed: {}", conn_id, ref_tag);
                        }
                    }
                    // ── IRCv3: standard-replies (FAIL/WARN/NOTE) ─────
                    "FAIL" | "WARN" | "NOTE" => {
                        let command = p.params.get(0).cloned().unwrap_or_default();
                        let code = p.params.get(1).cloned().unwrap_or_default();
                        let context = p.params.get(2).cloned().unwrap_or_default();
                        let description = p.params.last().cloned().unwrap_or_default();
                        let level = p.command.as_str();
                        let msg = format!("[{}] {} {} — {}: {}", level, command, code, context, description);
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: "status".into(), text: msg, ts,
                            kind: MessageKind::Notice,
                            prefix: None,
                        });
                    }
                    // ── IRCv3: Monitor numerics ──────────────────────
                    // 730 RPL_MONONLINE, 731 RPL_MONOFFLINE
                    "730" => {
                        let nicks_str = p.params.last().cloned().unwrap_or_default();
                        for entry in nicks_str.split(',') {
                            let nick = entry.split('!').next().unwrap_or(entry).trim().to_string();
                            if !nick.is_empty() {
                                send(ServerEvent::IrcMonitorOnline {
                                    conn_id: conn_id.to_string(), nick, ts,
                                });
                            }
                        }
                    }
                    "731" => {
                        let nicks_str = p.params.last().cloned().unwrap_or_default();
                        for entry in nicks_str.split(',') {
                            let nick = entry.trim().to_string();
                            if !nick.is_empty() {
                                send(ServerEvent::IrcMonitorOffline {
                                    conn_id: conn_id.to_string(), nick, ts,
                                });
                            }
                        }
                    }
                    // 732 RPL_MONLIST, 733 RPL_ENDOFMONLIST — just pass through
                    "732" | "733" => {
                        let text = p.params[1..].join(" ");
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: "status".into(), text, ts,
                            kind: MessageKind::Notice,
                            prefix: None,
                        });
                    }
                    // 734 ERR_MONLISTFULL
                    "734" => {
                        let text = p.params.last().cloned().unwrap_or("Monitor list full".into());
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: "status".into(), text, ts,
                            kind: MessageKind::Notice,
                            prefix: None,
                        });
                    }

                    "KICK" => {
                        let by      = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let kicked  = p.params.get(1).cloned().unwrap_or_default();
                        let reason  = p.params.get(2).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; if kicked == c.nick { c.channels.remove(&channel); } else if let Some(ch) = c.channels.get_mut(&channel) { ch.names.retain(|n| strip_pfx(n) != kicked); } }
                        send(ServerEvent::IrcKick { conn_id: conn_id.to_string(), channel, kicked, by, reason, ts });
                    }
                    "TOPIC" => {
                        let set_by  = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let topic   = p.params.get(1).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&channel) { ch.topic = topic.clone(); } }
                        send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by, ts });
                    }
                    "332" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let topic   = p.params.get(2).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&channel) { ch.topic = topic.clone(); } }
                        send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by: String::new(), ts });
                    }

                    // S3: bounded names accumulation
                    "353" => {
                        let channel = p.params.get(2).cloned().unwrap_or_default();
                        if names_buf.len() < NAMES_BUF_MAX_CHANNELS {
                            let names: Vec<String> = p.params.get(3).cloned().unwrap_or_default()
                                .split_whitespace()
                                // userhost-in-names: strip !user@host from entries like @nick!user@host
                                .map(|s| {
                                    if let Some(bang) = s.find('!') { s[..bang].to_string() }
                                    else { s.to_string() }
                                })
                                .collect();
                            let entry = names_buf.entry(channel).or_default();
                            for n in names {
                                if entry.len() < NAMES_BUF_MAX_PER_CHAN { entry.push(n); }
                            }
                        }
                    }
                    "366" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let names   = names_buf.remove(&channel).unwrap_or_default();
                        { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&channel) { ch.names = names.clone(); } }
                        send(ServerEvent::IrcNames { conn_id: conn_id.to_string(), channel, names });
                    }
                    "MODE" => {
                        let setter = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let modes  = p.params[1..].join(" ");
                        // Route non-channel modes (user modes) to status window
                        let display_target = if target.starts_with(['#','&','+','!']) {
                            target.clone()
                        } else {
                            "status".to_string()
                        };
                        let display = if setter.is_empty() || setter.contains('.') {
                            modes.clone()
                        } else {
                            format!("{}|{}", setter, modes)
                        };
                        send(ServerEvent::IrcMode { conn_id: conn_id.to_string(), target: display_target, modes: display, ts });
                    }
                    // 311-318 = WHOIS replies — route to nick's query buffer
                    "311" => { // RPL_WHOISUSER: nick user host * :realname
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let user = p.params.get(2).cloned().unwrap_or_default();
                        let host = p.params.get(3).cloned().unwrap_or_default();
                        let real = p.params.get(5).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("{}!{}@{} ({})", p.params.get(1).cloned().unwrap_or_default(), user, host, real), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "312" => { // RPL_WHOISSERVER
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params[2..].join(" ");
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Server: {}", text), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "313" => { // RPL_WHOISOPERATOR
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "317" => { // RPL_WHOISIDLE
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let idle: u64 = p.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let signon: i64 = p.params.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let idle_str = if idle >= 3600 { format!("{}h {}m {}s", idle/3600, (idle%3600)/60, idle%60) } else if idle >= 60 { format!("{}m {}s", idle/60, idle%60) } else { format!("{}s", idle) };
                        let signon_str = chrono::DateTime::from_timestamp(signon, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Idle: {} | Signon: {}", idle_str, signon_str), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "318" => { // RPL_ENDOFWHOIS
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "End of WHOIS".into(), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "319" => { // RPL_WHOISCHANNELS
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let chans = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Channels: {}", chans), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "330" => { // RPL_WHOISACCOUNT (logged in as)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let account = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Logged in as: {}", account), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "338" => { // RPL_WHOISACTUALLY (actual host/IP)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params[2..].join(" ");
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Actually: {}", text), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "671" => { // RPL_WHOISSECURE
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "Using secure connection (TLS)".into(), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    // Additional WHOIS numerics — route to nick's query buffer
                    "301" => { // RPL_AWAY
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let msg = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Away: {}", msg), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "307" => { // RPL_WHOISREGNICK
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or("is a registered nick".into());
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "378" => { // RPL_WHOISHOST (connecting from)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "379" => { // RPL_WHOISMODES
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "320" => { // RPL_WHOISSPECIAL (identified, bot, etc)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, prefix: None });
                    }
                    "275" | "276" => { // RPL_WHOISCERTFP — TLS certificate fingerprint
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Certificate: {}", text), ts, kind: MessageKind::Notice, prefix: None });
                    }
                    // 367 = RPL_BANLIST — one entry in the ban list
                    "367" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let mask    = p.params.get(2).cloned().unwrap_or_default();
                        let set_by  = p.params.get(3).cloned().unwrap_or_default();
                        send(ServerEvent::IrcBanEntry {
                            conn_id: conn_id.to_string(), channel, mask, set_by, ts,
                        });
                    }
                    // 368 = RPL_ENDOFBANLIST
                    "368" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcBanEnd { conn_id: conn_id.to_string(), channel });
                    }
                    // 348 = RPL_EXCEPTLIST (exempt list entry)
                    "348" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let mask    = p.params.get(2).cloned().unwrap_or_default();
                        let set_by  = p.params.get(3).cloned().unwrap_or_default();
                        send(ServerEvent::IrcBanEntry {
                            conn_id: conn_id.to_string(), channel, mask, set_by, ts,
                        });
                    }
                    // 349 = RPL_ENDOFEXCEPTLIST
                    "349" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcBanEnd { conn_id: conn_id.to_string(), channel });
                    }
                    // 321 = RPL_LISTSTART — ignore
                    "321" => {}
                    // 322 = RPL_LIST — channel list entry
                    "322" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let users: u32 = p.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let topic = p.params.get(3).cloned().unwrap_or_default();
                        send(ServerEvent::IrcListEntry {
                            conn_id: conn_id.to_string(), channel, users, topic,
                        });
                    }
                    // 323 = RPL_LISTEND
                    "323" => {
                        send(ServerEvent::IrcListEnd { conn_id: conn_id.to_string() });
                    }
                    // 364 = RPL_LINKS
                    "364" => {
                        let server = p.params.get(1).cloned().unwrap_or_default();
                        let hub = p.params.get(2).cloned().unwrap_or_default();
                        let info = p.params.get(3).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "links".into(),
                            target: "status".into(),
                            text: format!("\x02{}\x02 → {} ({})", server, hub, info),
                            ts, kind: MessageKind::Notice,
                            prefix: None,
                        });
                    }
                    // 365 = RPL_ENDOFLINKS
                    "365" => {
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "links".into(),
                            target: "status".into(),
                            text: "End of /LINKS".into(),
                            ts, kind: MessageKind::Notice,
                            prefix: None,
                        });
                    }
                    // Forward unhandled numerics (whois, lusers, motd, etc.) as status messages
                    cmd if cmd.chars().all(|c| c.is_ascii_digit()) => {
                        let text = if p.params.len() > 1 {
                            p.params[1..].join(" ")
                        } else {
                            p.params.join(" ")
                        };
                        if !text.is_empty() {
                            state.logger.append(username, conn_id, "status", ts, "*", &text, "notice").await;
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(),
                                from: "*".to_string(),
                                target: "status".to_string(),
                                text,
                                ts,
                                kind: MessageKind::Notice,
                                prefix: None,
                            });
                        }
                    }
                    // Forward any other unhandled commands to status
                    _ => {
                        let text = if p.params.len() > 1 {
                            p.params[1..].join(" ")
                        } else if !p.params.is_empty() {
                            p.params.join(" ")
                        } else {
                            p.command.clone()
                        };
                        if !text.is_empty() {
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(),
                                from: nick_from_prefix(&p.prefix),
                                target: "status".to_string(),
                                text,
                                ts,
                                kind: MessageKind::Notice,
                                prefix: None,
                            });
                        }
                    }
                }
            }
        }
    }
}

// ─── IRC line parser ──────────────────────────────────────────────────────────

struct IrcLine {
    prefix: Option<String>,
    command: String,
    params: Vec<String>,
    tags: HashMap<String, String>,
}

fn parse_irc(line: &str) -> IrcLine {
    let mut rest = line;
    // IRCv3 message tags: @key=value;key2=value2
    let mut tags = HashMap::new();
    if rest.starts_with('@') {
        let (tag_str, r) = rest[1..].split_once(' ').unwrap_or((&rest[1..], ""));
        for pair in tag_str.split(';') {
            if let Some((k, v)) = pair.split_once('=') {
                // Unescape IRCv3 tag values: \: -> ; \s -> space \\ -> \ \r \n
                let v = v.replace("\\:", ";").replace("\\s", " ")
                         .replace("\\r", "\r").replace("\\n", "\n")
                         .replace("\\\\", "\\");
                tags.insert(k.to_string(), v);
            } else if !pair.is_empty() {
                tags.insert(pair.to_string(), String::new());
            }
        }
        rest = r;
    }
    let mut prefix = None;
    if rest.starts_with(':') {
        let (p, r) = rest[1..].split_once(' ').unwrap_or((&rest[1..], ""));
        prefix = Some(p.to_string()); rest = r;
    }
    let mut params = Vec::new();
    let (cmd_part, mut remaining) = rest.split_once(' ').unwrap_or((rest, ""));
    while !remaining.is_empty() {
        if remaining.starts_with(':') { params.push(remaining[1..].to_string()); break; }
        match remaining.split_once(' ') {
            Some((t, r)) => { params.push(t.to_string()); remaining = r; }
            None         => { params.push(remaining.to_string()); break; }
        }
    }
    IrcLine { prefix, command: cmd_part.to_uppercase(), params, tags }
}

fn nick_from_prefix(p: &Option<String>) -> String {
    p.as_deref().and_then(|s| s.split('!').next()).unwrap_or("*").to_string()
}

fn strip_pfx(n: &str) -> &str { let s = n.trim_start_matches(|c: char| "@+~&%".contains(c)); if s.is_empty() { n } else { s } }
fn kind_str(k: &MessageKind) -> &'static str {
    match k { MessageKind::Privmsg => "privmsg", MessageKind::Notice => "notice", MessageKind::Action => "action" }
}
