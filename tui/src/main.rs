//! cryptirc-tui — a terminal client for CryptIRC.
//!
//! ## Why it talks to the web process, not the daemon
//!
//! `irc-core` accepts exactly ONE IPC client: `ipc_server.rs` holds a single
//! `current_client` slot and a new `Attach` REPLACES the previous one. A TUI
//! wired straight to `irc-core.sock` would therefore kick the browser off (and
//! be kicked off by it) forever.
//!
//! So this speaks the same WebSocket protocol the browser speaks, to the
//! `cryptirc` web process. That process already owns the daemon's single slot
//! and already fans every event out to ALL of a user's sessions
//! (`send_to_user`), so web and terminal run side by side with no changes to
//! either the daemon or the server. It also inherits everything the web process
//! provides for free: the same login, the vault, encrypted logs, and the
//! server-side bots.
//!
//! Config: ~/.config/cryptirc-tui/config.toml (server/username/password), or
//! CLI flags, or CRYPTIRC_* env vars. Password is prompted for if absent and
//! never required to be on disk.

mod proto;
mod app;
mod ui;
mod theme;

use anyhow::{anyhow, bail, Context, Result};
use crossterm::event::{
    DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton,
    MouseEventKind,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use futures_util::{SinkExt, StreamExt};
use ratatui::prelude::*;
use std::io::stdout;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMsg;

use app::{App, Line, LineKind, Prompt, PromptKind};
use proto::*;

struct Config {
    base: String,       // e.g. https://frozen.gh0st.boo/cryptirc
    username: String,
    password: String,
    theme: String,
}

fn need_val(args: &[String], i: usize, flag: &str) -> Result<String> {
    args.get(i).cloned().filter(|v| !v.is_empty())
        .ok_or_else(|| anyhow!("{} needs a value", flag))
}

fn load_config() -> Result<Config> {
    let mut base = std::env::var("CRYPTIRC_URL").unwrap_or_default();
    let mut username = std::env::var("CRYPTIRC_USER").unwrap_or_default();
    let mut password = std::env::var("CRYPTIRC_PASS").unwrap_or_default();
    let mut theme_name = std::env::var("CRYPTIRC_THEME").unwrap_or_default();

    // A config file is optional; parsed with a deliberately tiny key=value
    // reader so this crate does not pull a TOML dependency for three fields.
    if let Some(dir) = dirs::config_dir() {
        let p = dir.join("cryptirc-tui").join("config.toml");
        #[cfg(unix)]
        if let Ok(md) = std::fs::metadata(&p) {
            use std::os::unix::fs::PermissionsExt;
            // This file may hold the account password, which unlocks the web
            // session, the encrypted logs, the notepad and the password safe.
            if md.permissions().mode() & 0o077 != 0 {
                eprintln!("warning: {} is group/world-readable — chmod 600 it", p.display());
            }
        }
        if let Ok(text) = std::fs::read_to_string(&p) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('[') { continue; }
                let Some((k, v)) = line.split_once('=') else { continue };
                let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                match k.trim() {
                    "server" | "url" => if base.is_empty() { base = v },
                    "username" | "user" => if username.is_empty() { username = v },
                    "password" | "pass" => if password.is_empty() { password = v },
                    "theme" => if theme_name.is_empty() { theme_name = v },
                    _ => {}
                }
            }
        }
    }

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            // A missing value must ERROR, not silently blank the setting — that
            // turned `--server` (value forgotten) into "no server URL" while also
            // wiping a working CRYPTIRC_URL.
            "-s" | "--server" => { i += 1; base = need_val(&args, i, "--server")?; }
            "-u" | "--user"   => { i += 1; username = need_val(&args, i, "--user")?; }
            "-p" | "--pass"   => { i += 1; password = need_val(&args, i, "--pass")?; }
            "-t" | "--theme"  => { i += 1; theme_name = need_val(&args, i, "--theme")?; }
            "-h" | "--help"   => {
                println!("cryptirc-tui — terminal client for CryptIRC\n\n\
                    USAGE: cryptirc-tui [-s <url>] [-u <user>] [-p <pass>]\n\n\
                    Config file: ~/.config/cryptirc-tui/config.toml\n  \
                    server   = \"https://host/cryptirc\"\n  username = \"you\"\n  password = \"…\"   # optional; prompted if omitted\n\n\
                    Env: CRYPTIRC_URL, CRYPTIRC_USER, CRYPTIRC_PASS\n\n\
                    KEYS  Alt+1..9 / Alt+←→ or Ctrl+N/P  switch buffer · PgUp/PgDn scroll\n      \
                    Tab complete nick · Up/Down history · Alt+B/N toggle panels · Ctrl+C quit\n      \
                    Mouse: click a buffer or nick, wheel to scroll\n\n\
                    COMMANDS  /join /part /msg /query /me /close /buffer /clear /connect\n            \
                    /disconnect /vault /theme /quit\n            \
                    bots: /w /ud /wiki /define /crypto /wtime /cc /joke /qotd /fact\n            \
                    /8ball /roll /coin /q /seen /tell /note /bots /ai /aido\n            \
                    anything else is sent to IRC verbatim (/nick /whois /topic /mode /kick …)\n\n\
                    THEMES  /theme list · /theme <name> (saved to your config)");
                std::process::exit(0);
            }
            other if other.starts_with('-') => bail!("unknown option {} — see --help", other),
            _ => {}
        }
        i += 1;
    }

    if base.is_empty() { bail!("no server URL — pass --server, set CRYPTIRC_URL, or write ~/.config/cryptirc-tui/config.toml (see --help)"); }
    let base = base.trim_end_matches('/').to_string();
    if base.starts_with("http://") {
        // The password and session token cross the network in the clear.
        eprintln!("warning: {} is not HTTPS — your password and session token are sent unencrypted", base);
    }
    if username.is_empty() { bail!("no username — pass --user or set CRYPTIRC_USER"); }
    if password.is_empty() {
        // Prompted, so a password never has to live in a file or in shell history.
        password = rpassword::prompt_password(format!("password for {}: ", username))
            .context("reading password")?;
    }
    Ok(Config { base, username, password, theme: theme_name })
}

/// Log in over HTTP and return the session token the WebSocket needs.
async fn login(cfg: &Config) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?;
    let resp = client
        .post(format!("{}/auth/login", cfg.base))
        .json(&serde_json::json!({ "username": cfg.username, "password": cfg.password }))
        .send().await
        .with_context(|| format!("connecting to {}", cfg.base))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // The server answers a wrong password and an unverified account with the
        // SAME generic message on purpose (anti-enumeration) — pass it through
        // rather than guessing at a friendlier one that might be wrong.
        let msg = serde_json::from_str::<serde_json::Value>(&body).ok()
            .and_then(|v| v.get("message").and_then(|m| m.as_str()).map(str::to_string))
            .unwrap_or_else(|| format!("HTTP {}", status));
        if body.contains("captcha_required") && body.contains("true") {
            bail!("{} — a captcha is required after repeated failures; log in via the web app once to clear it", msg);
        }
        bail!("login failed: {}", msg);
    }
    let v: serde_json::Value = serde_json::from_str(&body).context("login response was not JSON")?;
    v.get("token").and_then(|t| t.as_str()).map(str::to_string)
        .ok_or_else(|| anyhow!("login response contained no token"))
}

fn ws_url(base: &str) -> Result<String> {
    let u = if let Some(rest) = base.strip_prefix("https://") { format!("wss://{}", rest) }
        else if let Some(rest) = base.strip_prefix("http://") { format!("ws://{}", rest) }
        else { bail!("server URL must start with http:// or https://") };
    Ok(format!("{}/ws", u))
}

enum Wire { Event(ServerEvent), Closed(String) }

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = load_config()?;
    eprint!("logging in… ");
    let token = login(&cfg).await?;
    eprintln!("ok");
    let url = ws_url(&cfg.base)?;

    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<ClientMessage>();
    let (tx_in, mut rx_in) = mpsc::unbounded_channel::<Wire>();

    // ── WebSocket pump. Owns the socket; the UI never touches it directly. ──
    {
        let token = token.clone();
        let url = url.clone();
        tokio::spawn(async move {
            let (stream, _) = match tokio_tungstenite::connect_async(&url).await {
                Ok(s) => s,
                Err(e) => { let _ = tx_in.send(Wire::Closed(format!("connect failed: {}", e))); return; }
            };
            let (mut sink, mut src) = stream.split();
            // The server sends auth_required first and drops us after 5s of
            // silence, so send the token immediately rather than waiting for it.
            let _ = sink.send(WsMsg::Text(serde_json::to_string(&ClientMessage::Auth { token }).unwrap())).await;
            loop {
                tokio::select! {
                    out = rx_out.recv() => {
                        let Some(msg) = out else { break };
                        if let Ok(j) = serde_json::to_string(&msg) {
                            if sink.send(WsMsg::Text(j)).await.is_err() { break; }
                        }
                    }
                    inc = src.next() => {
                        match inc {
                            Some(Ok(WsMsg::Text(t))) => {
                                match serde_json::from_str::<ServerEvent>(&t) {
                                    Ok(ev) => { if tx_in.send(Wire::Event(ev)).is_err() { break; } }
                                    // An unparseable frame must never kill the client.
                                    Err(_) => continue,
                                }
                            }
                            Some(Ok(WsMsg::Ping(p))) => { let _ = sink.send(WsMsg::Pong(p)).await; }
                            Some(Ok(WsMsg::Close(_))) | None => {
                                let _ = tx_in.send(Wire::Closed("server closed the connection".into()));
                                break;
                            }
                            Some(Err(e)) => {
                                let _ = tx_in.send(Wire::Closed(format!("socket error: {}", e)));
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
    }

    // ── Terminal setup. Everything after this point MUST restore the terminal
    // on the way out, including on panic — a raw-mode terminal left behind is
    // an unusable shell.
    // Every step is individually best-effort on the way out: if one fails the
    // others must still run, or the user is left in a raw-mode alternate screen
    // with no cursor and an unusable shell.
    fn restore() {
        let _ = disable_raw_mode();
        let _ = execute!(stdout(), LeaveAlternateScreen, DisableMouseCapture, DisableBracketedPaste, crossterm::cursor::Show);
    }
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| { restore(); default_hook(info); }));

    enable_raw_mode()?;
    // Bracketed paste: without it a multi-line paste is delivered as N Enter
    // presses, i.e. N separate PRIVMSGs at terminal speed — an instant flood
    // that earns an Excess Flood kill or a k-line.
    if let Err(e) = execute!(stdout(), EnterAlternateScreen, EnableMouseCapture, EnableBracketedPaste) {
        restore(); return Err(e.into());
    }
    let mut term = match Terminal::new(CrosstermBackend::new(stdout())) {
        Ok(t) => t,
        Err(e) => { restore(); return Err(e.into()); }
    };

    let mut app = App::new(cfg.username.clone());
    if !cfg.theme.is_empty() {
        if let Some(t) = theme::get(&cfg.theme) { app.theme = t; }
    }
    let res = run(&mut term, &mut app, tx_out, &mut rx_in).await;

    restore();
    let _ = term.show_cursor();
    if let Err(e) = res { eprintln!("cryptirc-tui: {}", e); std::process::exit(1); }
    Ok(())
}

async fn run<B: Backend>(
    term: &mut Terminal<B>,
    app: &mut App,
    tx: mpsc::UnboundedSender<ClientMessage>,
    rx: &mut mpsc::UnboundedReceiver<Wire>,
) -> Result<()> {
    let mut events = EventStream::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    app.status = "connecting…".into();
    let mut last_input = std::time::Instant::now();
    let mut is_idle = false;
    const IDLE_AFTER: Duration = Duration::from_secs(600);
    // Ctrl+C is consumed by crossterm in raw mode, so SIGINT is not the concern —
    // but `kill`, a systemd stop, or a session logout (SIGHUP) would otherwise
    // terminate us with raw mode still on and wreck the user's terminal.
    #[cfg(unix)]
    let (mut sigterm, mut sighup) = {
        use tokio::signal::unix::{signal, SignalKind};
        (signal(SignalKind::terminate())?, signal(SignalKind::hangup())?)
    };
    // A connection can half-open (laptop sleep, NAT timeout) with no bytes in
    // either direction — neither side pings. Without a deadline the client shows
    // "connected" while every message the user types is silently lost.
    let mut last_frame = std::time::Instant::now();
    let mut wire_open = true;

    loop {
        term.draw(|f| ui::draw(f, app))?;
        if app.should_quit { return Ok(()); }

        tokio::select! {
            _ = ticker.tick() => {
                // Report idle so the server sends push notifications to the
                // user's phone instead of assuming this session is watching.
                if !is_idle && last_input.elapsed() >= IDLE_AFTER {
                    is_idle = true;
                    let _ = tx.send(ClientMessage::Idle {});
                }
                // Neither side sends WebSocket pings, so a half-open socket is
                // otherwise undetectable for ~15 minutes of TCP retries while the
                // user types into the void.
                if wire_open && last_frame.elapsed() > Duration::from_secs(120) {
                    wire_open = false;
                    app.status = "connection stalled — no data for 2 minutes; press Ctrl+C and restart".into();
                    for (_, v) in app.connected.iter_mut() { *v = false; }
                }
            }
            _ = sigterm.recv() => { app.should_quit = true; }
            _ = sighup.recv() => { app.should_quit = true; }
            wire = rx.recv(), if wire_open => {
                match wire {
                    Some(Wire::Event(ev)) => { last_frame = std::time::Instant::now(); handle_event(app, ev); }
                    Some(Wire::Closed(why)) => {
                        app.status = format!("disconnected: {} — press Ctrl+C to quit", why);
                        for (_, v) in app.connected.iter_mut() { *v = false; }
                        // The pump has already exited, so the next recv() returns
                        // None. Close the branch here or that generic message
                        // overwrites this specific reason a frame later.
                        wire_open = false;
                    }
                    // The pump has exited and dropped its sender. Returning here
                    // would tear the screen down before the user could read WHY,
                    // and a closed receiver yields Ready(None) forever — so
                    // disable this branch instead of spinning on it.
                    None => {
                        wire_open = false;
                        app.status = "connection closed — press Ctrl+C to quit".into();
                        for (_, v) in app.connected.iter_mut() { *v = false; }
                    }
                }
                // Drain anything else already queued before repainting, so a
                // burst (a State snapshot plus history) costs one frame, not N.
                while let Ok(w) = rx.try_recv() {
                    if let Wire::Event(ev) = w { handle_event(app, ev); }
                }
                ensure_history(app, &tx);
            }
            Some(Ok(ev)) = events.next() => {
                match ev {
                    Event::Key(k) if k.kind == KeyEventKind::Press => {
                        last_input = std::time::Instant::now();
                        if is_idle { is_idle = false; let _ = tx.send(ClientMessage::Active {}); }
                        let before = app.current;
                        handle_key(app, k, &tx);
                        if app.current != before { ensure_history(app, &tx); }
                        maybe_page_history(app, &tx);
                    }
                    // Paste goes into the input buffer, never straight to the wire.
                    // Newlines become spaces so a pasted block is ONE message the
                    // user can still edit or think better of.
                    Event::Paste(text) => {
                        last_input = std::time::Instant::now();
                        if is_idle { is_idle = false; let _ = tx.send(ClientMessage::Active {}); }
                        let flat: String = text.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
                        for c in flat.chars() { app.insert(c); }
                    }
                    Event::Mouse(m) => {
                        let before = app.current;
                        handle_mouse(app, m);
                        maybe_page_history(app, &tx);
                        if app.current != before {
                            last_input = std::time::Instant::now();
                            if is_idle { is_idle = false; let _ = tx.send(ClientMessage::Active {}); }
                            ensure_history(app, &tx);
                        }
                    }
                    Event::Resize(_, _) => {}
                    _ => {}
                }
            }
        }
    }
}

// ── Event handling ──────────────────────────────────────────────────────────

/// Ask the server for scrollback the first time a buffer is shown. Guarded by
/// `history_asked` so flipping back and forth does not re-request it — the web
/// client's equivalent lacked that guard and produced an infinite fetch/render
/// loop (see project_cryptirc_messages_inbox_loop), which is worth not repeating.
fn ensure_history(app: &mut App, tx: &mpsc::UnboundedSender<ClientMessage>) {
    let Some(b) = app.buffers.get_mut(app.current) else { return };
    if b.history_asked || b.target.is_empty() { return; }
    b.history_asked = true;
    let _ = tx.send(ClientMessage::GetLogs {
        conn_id: b.conn_id.clone(), target: b.target.clone(),
        limit: Some(200), before: None,
    });
}

/// Fetch the page BEFORE the oldest line we hold, when the user scrolls to the
/// top. Without this only the most recent 200 lines were ever reachable.
fn maybe_page_history(app: &mut App, tx: &mpsc::UnboundedSender<ClientMessage>) {
    let Some(b) = app.buffers.get_mut(app.current) else { return };
    if b.target.is_empty() || b.lines.is_empty() { return; }
    // Only at the very top, and only once per page (history_asked is re-armed
    // when the page lands).
    if b.scroll + 1 < b.total_rows.max(b.lines.len()) { return; }
    if !b.history_asked { return; }             // a fetch is already outstanding
    let oldest = b.lines.iter().map(|l| l.ts).min().unwrap_or(0);
    if oldest == 0 { return; }
    b.history_asked = false;                    // re-armed; the reply sets it back
    let _ = tx.send(ClientMessage::GetLogs {
        conn_id: b.conn_id.clone(), target: b.target.clone(),
        limit: Some(200), before: Some(oldest),
    });
}

/// Raise the vault passphrase prompt. The vault gates decryption of the stored
/// network credentials, so until it is open the server cannot dial IRC and the
/// client has nothing to show.
fn ask_vault(app: &mut App) {
    if app.prompt.is_some() { return; }
    app.prompt = Some(Prompt {
        label: "vault passphrase:".into(), value: String::new(),
        masked: true, kind: PromptKind::Vault,
    });
    app.status = "vault is locked — unlock to connect to IRC".into();
}

fn status_line(app: &mut App, conn_id: &str, target: &str, text: String) {
    // Label the network buffer with its conn_id if we have not seen a State for
    // it yet — otherwise a Connected/Disconnected arriving first mints a nameless
    // row in the buffer list.
    let i = app.buf_index(conn_id, target, Some(conn_id));
    app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(), text, kind: LineKind::Status, id: 0 }, false);
}

fn handle_event(app: &mut App, ev: ServerEvent) {
    match ev {
        ServerEvent::AuthRequired {} => {}   // token was sent up front
        ServerEvent::AuthOk { username } => {
            app.username = username;
            app.status = "connected".into();
        }
        ServerEvent::AuthFailed { message } => {
            app.status = format!("auth failed: {}", message);
        }
        ServerEvent::VaultLocked {} => {
            app.vault_unlocked = false;
            ask_vault(app);
        }
        ServerEvent::VaultUnlocked { .. } => {
            app.vault_unlocked = true;
            app.prompt = None;
            app.status = "vault unlocked".into();
            // Logs are encrypted, so any history requested while the vault was
            // locked came back empty. Re-arm those buffers rather than leaving
            // them blank for the rest of the session.
            for b in app.buffers.iter_mut() {
                if b.lines.is_empty() { b.history_asked = false; }
            }
        }
        ServerEvent::VaultError { message } => {
            app.status = format!("vault: {}", message);
            if let Some(p) = &mut app.prompt { p.value.clear(); }
        }
        ServerEvent::State { networks, vault_unlocked } => {
            app.vault_unlocked = vault_unlocked;
            // ⚠️ The server sends `VaultLocked` ONLY in reply to an explicit
            // LockVault — never on connect. So the locked state is communicated
            // solely by this flag, and keying the prompt off the event meant it
            // never appeared: the client sat there showing "[vault locked]" and,
            // because a locked vault means the server holds no live connections,
            // every network came back with zero channels. It looked like the TUI
            // wasn't using the same account.
            if vault_unlocked { app.prompt = None; } else { ask_vault(app); }
            for n in networks {
                let cid = n.config.id.clone();
                let label = if n.config.label.is_empty() { cid.clone() } else { n.config.label.clone() };
                app.nicks.insert(cid.clone(), n.nick.clone());
                app.connected.insert(cid.clone(), n.connected);
                app.lag.insert(cid.clone(), n.lag_ms);
                // Status buffer for the network itself.
                app.buf_index(&cid, "", Some(&label));
                for ch in &n.channels {
                    let i = app.buf_index(&cid, &ch.name, Some(&ch.name));
                    if let Some(b) = app.buffers.get_mut(i) {
                        b.topic = ch.topic.clone();
                        b.names = ch.names.clone();
                        b.label = ch.name.clone();
                    }
                }
                // Drop channel buffers the server no longer lists — this is what
                // catches a part done from ANOTHER client (the web app), where we
                // never see an IrcPart for ourselves.
                //
                // ⚠️ ONLY when this network is genuinely connected AND the vault is
                // open. A locked vault makes user_network_states report every
                // network with an EMPTY channel list, so pruning unconditionally
                // would wipe every channel the moment the vault re-locks.
                if vault_unlocked && n.connected {
                    let keep: Vec<String> = n.channels.iter().map(|c| c.name.to_lowercase()).collect();
                    let doomed: Vec<usize> = app.buffers.iter().enumerate()
                        .filter(|(_, b)| b.conn_id == cid && b.is_channel()
                            && !keep.contains(&b.target.to_lowercase()))
                        .map(|(i, _)| i).collect();
                    // Remove back-to-front so earlier indices stay valid.
                    for i in doomed.into_iter().rev() { app.remove_buffer(i); }
                }
            }
        }
        ServerEvent::IrcMessage { conn_id, from, target, text, ts, kind, msg_id, replayed } => {
            let our = app.our_nick(&conn_id).to_string();
            // A PM routes to a buffer named after the SENDER, not after us.
            let buf_target = if target.starts_with(['#', '&', '+', '!']) { target.clone() } else { from.clone() };
            let i = app.buf_index(&conn_id, &buf_target, None);
            // Case-INSENSITIVE: live events carry "Action"/"Notice" (MessageKind has
            // no rename_all) while history carries "action"/"notice".
            let lk = if kind.eq_ignore_ascii_case("action") { LineKind::Action }
                else if kind.eq_ignore_ascii_case("notice") { LineKind::Notice }
                else { LineKind::Msg };
            // Highlight on our nick, word-boundary style so a short nick does not
            // match inside every other word. Replayed history never highlights.
            let hl = !replayed && text.to_lowercase().split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                .any(|w| w == our.to_lowercase());
            app.add_line_ex(i, Line { ts, from, text, kind: lk, id: msg_id },
                hl || !buf_target.starts_with(['#','&','+','!']), replayed);
        }
        ServerEvent::IrcEcho { conn_id, from, target, text, ts, kind, msg_id } => {
            let i = app.buf_index(&conn_id, &target, None);
            let lk = if kind.eq_ignore_ascii_case("action") { LineKind::Action } else { LineKind::Own };
            app.add_line(i, Line { ts, from, text, kind: lk, id: msg_id }, false);
        }
        ServerEvent::IrcJoin { conn_id, nick, channel, ts } => {
            let i = app.buf_index(&conn_id, &channel, Some(&channel));
            let our = app.our_nick(&conn_id).to_string();
            if !nick.eq_ignore_ascii_case(&our) {
                if let Some(b) = app.buffers.get_mut(i) {
                    if !b.names.iter().any(|n| n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&nick)) {
                        b.names.push(nick.clone());
                    }
                }
            }
            app.add_line(i, Line { ts, from: String::new(), text: format!("{} has joined {}", nick, channel), kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcPart { conn_id, nick, channel, reason, ts } => {
            // OUR OWN part closes the window — we are not in that channel any
            // more, so leaving it in the buffer list is just clutter you cannot
            // act on. (Anyone else's part only updates the member list.)
            if app.our_nick(&conn_id).eq_ignore_ascii_case(&nick) {
                if let Some(i) = app.find_buf(&conn_id, &channel) { app.remove_buffer(i); }
                return;
            }
            let i = app.buf_index(&conn_id, &channel, Some(&channel));
            if let Some(b) = app.buffers.get_mut(i) {
                b.names.retain(|n| !n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&nick));
            }
            let r = if reason.is_empty() { String::new() } else { format!(" ({})", reason) };
            app.add_line(i, Line { ts, from: String::new(), text: format!("{} has left {}{}", nick, channel, r), kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcQuit { conn_id, nick, reason, ts } => {
            // A quit affects every channel the user shared with us.
            let r = if reason.is_empty() { String::new() } else { format!(" ({})", reason) };
            let idxs: Vec<usize> = app.buffers.iter().enumerate()
                .filter(|(_, b)| b.conn_id == conn_id && b.is_channel()
                    && b.names.iter().any(|n| n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&nick)))
                .map(|(i, _)| i).collect();
            for i in idxs {
                if let Some(b) = app.buffers.get_mut(i) {
                    b.names.retain(|n| !n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&nick));
                }
                app.add_line(i, Line { ts, from: String::new(), text: format!("{} has quit{}", nick, r), kind: LineKind::Status, id: 0 }, false);
            }
        }
        ServerEvent::IrcNick { conn_id, old, new, ts } => {
            let our = app.our_nick(&conn_id).to_string();
            if old.eq_ignore_ascii_case(&our) { app.nicks.insert(conn_id.clone(), new.clone()); }
            let idxs: Vec<usize> = app.buffers.iter().enumerate()
                .filter(|(_, b)| b.conn_id == conn_id && b.is_channel()
                    && b.names.iter().any(|n| n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&old)))
                .map(|(i, _)| i).collect();
            for i in idxs {
                if let Some(b) = app.buffers.get_mut(i) {
                    for n in b.names.iter_mut() {
                        let pfx_len = n.len() - n.trim_start_matches(['~','&','@','%','+']).len();
                        if n[pfx_len..].eq_ignore_ascii_case(&old) { *n = format!("{}{}", &n[..pfx_len], new); }
                    }
                }
                app.add_line(i, Line { ts, from: String::new(), text: format!("{} is now known as {}", old, new), kind: LineKind::Status, id: 0 }, false);
            }
        }
        ServerEvent::IrcTopic { conn_id, channel, topic, ts } => {
            let i = app.buf_index(&conn_id, &channel, Some(&channel));
            if let Some(b) = app.buffers.get_mut(i) { b.topic = topic.clone(); }
            app.add_line(i, Line { ts, from: String::new(), text: format!("topic: {}", topic), kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcNames { conn_id, channel, names } => {
            let i = app.buf_index(&conn_id, &channel, Some(&channel));
            if let Some(b) = app.buffers.get_mut(i) { b.names = names; }
        }
        ServerEvent::IrcMode { conn_id, target, modes, ts } => {
            let i = app.buf_index(&conn_id, &target, None);
            app.add_line(i, Line { ts, from: String::new(), text: format!("mode/{} {}", target, modes), kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcKick { conn_id, channel, kicked, by, reason, ts } => {
            let i = app.buf_index(&conn_id, &channel, Some(&channel));
            if let Some(b) = app.buffers.get_mut(i) {
                b.names.retain(|n| !n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&kicked));
            }
            let r = if reason.is_empty() { String::new() } else { format!(" ({})", reason) };
            // Highlight only when WE were the one kicked.
            let us = app.our_nick(&conn_id).eq_ignore_ascii_case(&kicked);
            app.add_line(i, Line { ts, from: String::new(), text: format!("{} was kicked by {}{}", kicked, by, r), kind: LineKind::Status, id: 0 }, us);
            // Being kicked leaves the channel just as surely as parting — but keep
            // the buffer so the user can actually SEE why they vanished; it will be
            // pruned by the next State snapshot if they do not rejoin.
        }
        ServerEvent::Connected { conn_id, nick, server } => {
            app.connected.insert(conn_id.clone(), true);
            if !nick.is_empty() { app.nicks.insert(conn_id.clone(), nick.clone()); }
            let msg = match (server.is_empty(), nick.is_empty()) {
                (false, false) => format!("connected to {} as {}", server, nick),
                (true, false)  => format!("connected as {}", nick),
                _ => "connected".to_string(),
            };
            status_line(app, &conn_id, "", msg);
        }
        ServerEvent::Disconnected { conn_id, reason } => {
            app.connected.insert(conn_id.clone(), false);
            let r = if reason.is_empty() { "connection closed".to_string() } else { reason };
            status_line(app, &conn_id, "", format!("disconnected: {}", r));
        }
        ServerEvent::Connecting { conn_id } => status_line(app, &conn_id, "", "connecting…".into()),
        ServerEvent::Reconnecting { conn_id, delay_secs } => {
            app.connected.insert(conn_id.clone(), false);
            status_line(app, &conn_id, "", format!("reconnecting in {}s", delay_secs));
        }
        ServerEvent::LagUpdate { conn_id, ms } => { app.lag.insert(conn_id, Some(ms)); }
        ServerEvent::LogLines { conn_id, target, lines } => {
            let i = app.buf_index(&conn_id, &target, None);
            let our = app.our_nick(&conn_id).to_string();
            // History PREPENDS: it is older than whatever is already on screen.
            let mut hist: Vec<Line> = lines.into_iter().map(|l| {
                let kind = match l.kind.as_str() {
                    "action" => LineKind::Action,
                    "notice" => LineKind::Notice,
                    _ if l.from.eq_ignore_ascii_case(&our) => LineKind::Own,
                    _ => LineKind::Msg,
                };
                Line { ts: l.ts, from: l.from, text: l.text, kind, id: l.id }
            }).collect();
            if let Some(b) = app.buffers.get_mut(i) {
                b.history_asked = true;         // this fetch is done
                let existing: std::collections::HashSet<u64> =
                    b.lines.iter().filter(|l| l.id != 0).map(|l| l.id).collect();
                hist.retain(|l| l.id == 0 || !existing.contains(&l.id));
                let n = hist.len();
                hist.extend(b.lines.drain(..));
                b.lines = hist;
                // Anchor on what the user was reading. `scroll` is in ROWS and we
                // do not know the wrap width here, so approximate one row per
                // prepended message; the renderer re-clamps on the next frame.
                if b.scroll > 0 { b.scroll += n; }
            }
        }
        ServerEvent::Error { message } => {
            app.status = message.clone();
            // Only render into a buffer that already exists — otherwise an early
            // error (before any State arrives) mints a permanent unnamed buffer.
            if let Some((cid, tgt)) = app.cur().map(|b| (b.conn_id.clone(), b.target.clone())) {
                let i = app.buf_index(&cid, &tgt, None);
                app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(), text: message, kind: LineKind::Error, id: 0 }, false);
            }
        }
        ServerEvent::BotResult { bot, text } => {
            // Private to us — render in the active buffer, exactly as the web
            // client does, and never send it to the channel.
            if let Some((cid, tgt)) = app.cur().map(|b| (b.conn_id.clone(), b.target.clone())) {
                let i = app.buf_index(&cid, &tgt, None);
                // Name the bot, so /w and /ai answers are distinguishable when
                // several land in the same buffer.
                let label = if bot.is_empty() { "🤖".to_string() } else { format!("🤖 {}", bot) };
                app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(),
                    text: format!("{} {}", label, text), kind: LineKind::Status, id: 0 }, false);
            } else {
                app.status = text;
            }
        }
        ServerEvent::Unknown => {}
    }
}

fn handle_key(app: &mut App, k: KeyEvent, tx: &mpsc::UnboundedSender<ClientMessage>) {
    // A modal prompt owns the keyboard while it is up.
    if let Some(p) = &mut app.prompt {
        // Ctrl+C must always quit — the vault prompt is the FIRST thing shown, so
        // without this the only way out was to guess Esc-then-Ctrl+C.
        if k.code == KeyCode::Char('c') && k.modifiers.contains(KeyModifiers::CONTROL) {
            app.should_quit = true;
            return;
        }
        match k.code {
            KeyCode::Enter => {
                let v = std::mem::take(&mut p.value);
                match p.kind {
                    PromptKind::Vault => { let _ = tx.send(ClientMessage::UnlockVault { passphrase: v }); }
                }
                app.status = "unlocking…".into();
            }
            KeyCode::Esc => {
                app.prompt = None;
                app.status = "vault left locked — IRC will not connect. /vault to retry".into();
            }
            KeyCode::Backspace => { p.value.pop(); }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => p.value.push(c),
            _ => {}
        }
        return;
    }

    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    let alt = k.modifiers.contains(KeyModifiers::ALT);
    // Any key other than Tab ends a completion cycle. This MUST exclude Tab —
    // clearing it unconditionally here ran before the Tab arm below, so every
    // press restarted from the first candidate and cycling never worked.
    if k.code != KeyCode::Tab { app.complete_state = None; }

    match k.code {
        KeyCode::Char('c') if ctrl => { app.should_quit = true; }
        KeyCode::Char('n') if ctrl => app.next_buffer(),
        KeyCode::Char('p') if ctrl => app.prev_buffer(),
        KeyCode::Char('b') if alt  => app.show_buflist = !app.show_buflist,
        KeyCode::Char('n') if alt  => app.show_nicklist = !app.show_nicklist,
        // Alt+1..9 jumps to a buffer, exactly like weechat/irssi.
        KeyCode::Char(c) if alt && c.is_ascii_digit() => {
            app.switch_to_display(c.to_digit(10).unwrap() as usize);
        }
        KeyCode::Right if alt => app.next_buffer(),
        KeyCode::Left  if alt => app.prev_buffer(),
        KeyCode::PageUp   => app.scroll_by(10),
        KeyCode::PageDown => app.scroll_by(-10),
        KeyCode::Home if ctrl => app.scroll_to_top(),
        KeyCode::End  if ctrl => app.scroll_to_bottom(),
        KeyCode::Up   => app.history_up(),
        KeyCode::Down => app.history_down(),
        KeyCode::Left  => app.move_left(),
        KeyCode::Right => app.move_right(),
        KeyCode::Home => app.cursor = 0,
        KeyCode::End  => app.cursor = app.input.len(),
        KeyCode::Backspace => app.backspace(),
        KeyCode::Delete => app.delete(),
        KeyCode::Tab => { app.complete_nick(); return; }   // keep cycle state
        KeyCode::Enter => {
            let text = app.take_input();
            if !text.trim().is_empty() { submit(app, text, tx); }
        }
        // Alt-modified keys are shortcuts, not text: without this guard any
        // unhandled Alt+letter typed its literal character into the message.
        KeyCode::Char(c) if !ctrl && !alt => app.insert(c),
        _ => {}
    }
}

fn handle_mouse(app: &mut App, m: crossterm::event::MouseEvent) {
    match m.kind {
        MouseEventKind::ScrollUp => app.scroll_by(3),
        MouseEventKind::ScrollDown => app.scroll_by(-3),
        MouseEventKind::Down(MouseButton::Left) => {
            // Buffer list: hit targets were recorded by the renderer, so this can
            // never disagree with what is actually on screen.
            if let Some(&(_, idx)) = app.buflist_hits.iter().find(|(row, _)| *row == m.row) {
                // Only if the click was inside the list's column.
                if m.column < 20 { app.switch_to(idx); }
            }
        }
        _ => {}
    }
}

/// Persist the chosen theme into the config file, creating it if needed and
/// rewriting an existing `theme =` line in place so the rest of the user's
/// config (server, username, password) is preserved untouched.
fn save_theme_pref(name: &str) -> Result<()> {
    let Some(dir) = dirs::config_dir() else { bail!("no config dir") };
    let dir = dir.join("cryptirc-tui");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("config.toml");
    // ONLY a missing file may be treated as empty. Any other read error (bad
    // permissions, non-UTF-8, EIO) previously became "" and the rewrite then
    // clobbered the user's server/username/PASSWORD while reporting success.
    let existing = match std::fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => bail!("cannot read config: {}", e),
    };
    // Never turn a symlinked config (dotfiles repos) into a regular file.
    let path = match std::fs::symlink_metadata(&path) {
        Ok(md) if md.file_type().is_symlink() => std::fs::canonicalize(&path)?,
        _ => path,
    };
    let mut out: Vec<String> = Vec::new();
    let mut replaced = false;
    for line in existing.lines() {
        if line.trim_start().starts_with("theme") && line.contains('=') {
            out.push(format!("theme = \"{}\"", name));
            replaced = true;
        } else {
            out.push(line.to_string());
        }
    }
    if !replaced { out.push(format!("theme = \"{}\"", name)); }
    let body = out.join("\n") + "\n";
    // Write via a temp file + rename so an interrupted write cannot truncate a
    // config that holds the user's password.
    let tmp = path.with_extension("toml.tmp");
    {
        // Create at 0600 FROM THE START — writing first and chmod'ing after left
        // the password world-readable for a window, and a failed chmod would have
        // renamed a 0644 file containing it into place.
        use std::io::Write;
        let mut f = {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            { use std::os::unix::fs::OpenOptionsExt; o.mode(0o600); }
            o.open(&tmp)?
        };
        f.write_all(body.as_bytes())?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        let _ = std::fs::remove_file(&tmp);   // never leave the password lying around
        return Err(e.into());
    }
    Ok(())
}

/// Send one of the owner's private bot commands. `conn_id`/`channel` are always
/// supplied — the bots that don't need them ignore them, and the ones that do
/// (quotedb/seen/tell/note) break without them.
fn bot_query(tx: &mpsc::UnboundedSender<ClientMessage>, bot: &str, query: &str, conn_id: &str, channel: &str) {
    let _ = tx.send(ClientMessage::BotQuery {
        bot: bot.to_string(),
        query: query.trim().to_string(),
        conn_id: conn_id.to_string(),
        channel: channel.to_string(),
    });
}

/// Turn a line of user input into protocol messages.
fn submit(app: &mut App, text: String, tx: &mpsc::UnboundedSender<ClientMessage>) {
    let Some(b) = app.cur() else { app.status = "no buffer".into(); return };
    let conn_id = b.conn_id.clone();
    let target = b.target.clone();

    if !text.starts_with('/') {
        if target.is_empty() {
            app.status = "this is a server buffer — /join a channel or /msg someone".into();
            return;
        }
        // The server echoes this back to every session including ours, and that
        // echo is what renders it — so nothing is added locally. Matches the web
        // client and means a failed send does not leave a phantom line.
        let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG {} :{}", target, text) });
        return;
    }

    let body = &text[1..];
    let (cmd, rest) = match body.split_once(' ') {
        Some((c, r)) => (c.to_lowercase(), r.trim().to_string()),
        None => (body.to_lowercase(), String::new()),
    };

    match cmd.as_str() {
        "quit" | "exit" => app.should_quit = true,
        "close" | "wc" => {
            // A channel has to be PARTED, not just hidden — otherwise the next
            // State snapshot recreates it and the window comes straight back.
            // (The GUI does exactly this split.)
            if !target.is_empty() && target.starts_with(['#','&','+','!']) {
                let _ = tx.send(ClientMessage::PartChannel { conn_id, channel: target });
            } else if app.buffers.len() > 1 {
                app.remove_buffer(app.current);
            }
        }
        "buffer" | "b" => {
            if let Ok(n) = rest.trim().parse::<usize>() {
                app.switch_to_display(n);
            } else if !rest.is_empty() {
                if let Some(i) = app.buffers.iter().position(|b| b.label.eq_ignore_ascii_case(rest.trim())) {
                    app.switch_to(i);
                }
            }
        }
        "join" | "j" => {
            let mut it = rest.split_whitespace();
            let Some(ch0) = it.next() else { app.status = "usage: /join #channel [key]".into(); return };
            // Prefix '#' like the GUI. Without it the local buffer is not a
            // channel, so the State prune can never clean it up and it sits in
            // the list forever looking like a DM.
            let ch_owned = if ch0.starts_with(['#','&','+','!']) { ch0.to_string() } else { format!("#{}", ch0) };
            let ch = ch_owned.as_str();
            let key = it.next().map(str::to_string);
            let _ = tx.send(ClientMessage::JoinChannel { conn_id: conn_id.clone(), channel: ch.to_string(), key });
            let i = app.buf_index(&conn_id, ch, Some(ch));
            app.switch_to(i);
        }
        "part" | "leave" => {
            let ch = if rest.is_empty() { target.clone() } else { rest.clone() };
            if ch.is_empty() { app.status = "usage: /part [#channel]".into(); return; }
            let _ = tx.send(ClientMessage::PartChannel { conn_id, channel: ch });
        }
        "msg" | "query" => {
            let Some((who, body)) = rest.split_once(' ') else {
                // Bare /msg <nick> just opens the buffer.
                if !rest.is_empty() {
                    let i = app.buf_index(&conn_id, rest.trim(), None);
                    app.switch_to(i);
                } else { app.status = "usage: /msg <nick> [message]".into(); }
                return;
            };
            let i = app.buf_index(&conn_id, who, None);
            app.switch_to(i);
            let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG {} :{}", who, body) });
        }
        "me" => {
            if target.is_empty() || rest.is_empty() { app.status = "usage: /me <action>".into(); return; }
            let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG {} :\x01ACTION {}\x01", target, rest) });
        }
        "clear" => { if let Some(b) = app.cur_mut() { b.lines.clear(); b.scroll = 0; } }
        // ── The owner's private bot commands. These are NOT raw IRC: they go over
        // the WS as `bot_query` and the answer comes back privately as BotResult,
        // matching the web client's dispatch byte for byte (see its slash-command
        // switch). Passing them through as raw IRC — which is what happened before
        // — just made the ircd answer "Unknown command".
        //
        // Note the deliberate aliases the GUI uses to dodge real IRC verbs:
        // /wtime (because /time is CTCP TIME) and /qotd (because /quote is /raw).
        "w" | "weather"   => bot_query(tx, "weather", &rest, &conn_id, &target),
        "ud"              => bot_query(tx, "ud", &rest, &conn_id, &target),
        "wiki"            => bot_query(tx, "wiki", &rest, &conn_id, &target),
        "define" | "dict" => bot_query(tx, "define", &rest, &conn_id, &target),
        "crypto" | "price"=> bot_query(tx, "crypto", &rest, &conn_id, &target),
        "wtime"           => bot_query(tx, "time", &rest, &conn_id, &target),
        "cc" | "currency" => bot_query(tx, "cc", &rest, &conn_id, &target),
        "joke"            => bot_query(tx, "joke", "", &conn_id, &target),
        "qotd"            => bot_query(tx, "quote", "", &conn_id, &target),
        "fact"            => bot_query(tx, "fact", "", &conn_id, &target),
        "coin" | "flip"   => bot_query(tx, "coin", "", &conn_id, &target),
        "8ball"           => bot_query(tx, "eightball", &rest, &conn_id, &target),
        "roll"            => bot_query(tx, "roll", &rest, &conn_id, &target),
        "q" | "quotedb"   => bot_query(tx, "quotedb", &rest, &conn_id, &target),
        "seen"            => bot_query(tx, "seen", &rest, &conn_id, &target),
        "tell"            => bot_query(tx, "tell", &rest, &conn_id, &target),
        "note" | "notes"  => bot_query(tx, "note", &rest, &conn_id, &target),
        // The server has no "help" bot — the GUI opens a local panel. Print the
        // roster here instead of sending a query that answers "unknown bot".
        "bots" | "cmds" => {
            if let Some((cid, tgt)) = app.cur().map(|b| (b.conn_id.clone(), b.target.clone())) {
                let i = app.buf_index(&cid, &tgt, None);
                for row in [
                    "bots: /w /ud /wiki /define /crypto /wtime /cc /joke /qotd /fact",
                    "      /8ball /roll /coin /q /seen /tell /note /ai /aido",
                    "irc:  /join /part /msg /me /nick /topic /kick /ban /op /voice /mode",
                    "      /invite /away /back /notice /cycle /ns /cs /identify /raw",
                    "app:  /buffer /close /clear /theme /vault /connect /disconnect /quit",
                ] {
                    app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(),
                        text: row.to_string(), kind: LineKind::Status, id: 0 }, false);
                }
            }
        }
        "ai"              => bot_query(tx, "ai", &rest, &conn_id, &target),
        "aido" => {
            if target.is_empty() || !target.starts_with(['#','&','+','!']) {
                app.status = "/aido works in a channel".into();
            } else if rest.trim().is_empty() {
                app.status = "usage: /aido <what to do>".into();
            } else {
                let _ = tx.send(ClientMessage::AiDo { conn_id, target, query: rest });
            }
        }
        "vault" | "unlock" => ask_vault(app),
        "theme" | "themes" => {
            let arg = rest.trim();
            if arg.is_empty() || arg.eq_ignore_ascii_case("list") {
                let names = theme::names();
                app.status = format!("{} themes — /theme <name>", names.len());
                let cur = app.theme.name.to_string();
                // Print the roster into the buffer in readable rows rather than
                // one 50-name line that wraps into mush.
                if let Some((cid, tgt)) = app.cur().map(|b| (b.conn_id.clone(), b.target.clone())) {
                    let i = app.buf_index(&cid, &tgt, None);
                    for chunk in names.chunks(6) {
                        let row = chunk.iter()
                            .map(|n| if *n == cur { format!("[{}]", n) } else { n.to_string() })
                            .collect::<Vec<_>>().join("  ");
                        app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(),
                            text: row, kind: LineKind::Status, id: 0 }, false);
                    }
                }
            } else if let Some(t) = theme::get(arg) {
                let name = t.name;
                app.theme = t;
                match save_theme_pref(name) {
                    Ok(()) => app.status = format!("theme: {} (saved)", name),
                    // Not fatal — the theme still applies for this session.
                    Err(e) => app.status = format!("theme: {} (not saved: {})", name, e),
                }
            } else {
                app.status = format!("no theme '{}' — /theme list", arg);
            }
        }
        // These were advertised in --help but unimplemented: they fell through to
        // the raw passthrough and were sent to IRC as a literal "connect" line.
        "connect" => { let _ = tx.send(ClientMessage::Connect { id: conn_id }); app.status = "connecting…".into(); }
        "disconnect" => {
            let reason = if rest.trim().is_empty() { None } else { Some(rest.trim().to_string()) };
            let _ = tx.send(ClientMessage::Disconnect { id: conn_id, reason });
        }
        "help" => {
            app.status = "keys: Alt+1..9 buffers · PgUp/PgDn scroll · Tab complete · Ctrl+C quit — commands are passed to IRC".into();
        }
        // ── Commands whose trailing parameter is multi-word MUST be built with a
        // leading ':' or the ircd stops at the first space. Passing these through
        // verbatim looked fine and was quietly wrong: `/kick bob being rude`
        // became KICK <chan=bob> <user=being>, kicking the wrong person from the
        // wrong channel. Each of these mirrors the web client's own construction.
        "topic" => {
            if target.is_empty() { app.status = "/topic works in a channel".into(); }
            else if rest.is_empty() { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("TOPIC {}", target) }); }
            else { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("TOPIC {} :{}", target, rest) }); }
        }
        "kick" => {
            let mut it = rest.splitn(2, ' ');
            match it.next().filter(|w| !w.is_empty()) {
                None => app.status = "usage: /kick <nick> [reason]".into(),
                Some(who) => {
                    let why = it.next().unwrap_or("").trim();
                    let why = if why.is_empty() { "Kicked" } else { why };
                    let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("KICK {} {} :{}", target, who, why) });
                }
            }
        }
        "away" => {
            let r = if rest.trim().is_empty() { "Away".to_string() } else { rest.clone() };
            let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("AWAY :{}", r) });
            app.status = format!("away: {}", r);
        }
        "back" | "unaway" => {
            let _ = tx.send(ClientMessage::Send { conn_id, raw: "AWAY".into() });
            app.status = "back".into();
        }
        "notice" => {
            match rest.split_once(' ') {
                Some((to, msg)) if !msg.trim().is_empty() =>
                    { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("NOTICE {} :{}", to, msg) }); }
                _ => app.status = "usage: /notice <target> <message>".into(),
            }
        }
        // Status-mode helpers. These are not IRC verbs — the GUI expands each to a
        // MODE on the current channel, so sending them raw just earned "Unknown
        // command". Multiple nicks are allowed, as in the GUI.
        "op" | "deop" | "voice" | "devoice" | "halfop" | "dehalfop" => {
            let (sign, letter) = match cmd.as_str() {
                "op" => ('+', 'o'), "deop" => ('-', 'o'),
                "voice" => ('+', 'v'), "devoice" => ('-', 'v'),
                "halfop" => ('+', 'h'), _ => ('-', 'h'),
            };
            let nicks: Vec<&str> = rest.split_whitespace().collect();
            if target.is_empty() || nicks.is_empty() {
                app.status = format!("usage: /{} <nick> [nick2…] (in a channel)", cmd);
            } else {
                // One MODE per nick keeps us under every server's MODE-parameter
                // limit without having to know what that limit is.
                for nk in nicks {
                    let _ = tx.send(ClientMessage::Send { conn_id: conn_id.clone(),
                        raw: format!("MODE {} {}{} {}", target, sign, letter, nk) });
                }
            }
        }
        "ban" | "unban" => {
            let sign = if cmd == "ban" { '+' } else { '-' };
            let mask = rest.trim();
            if target.is_empty() || mask.is_empty() { app.status = format!("usage: /{} <nick|mask>", cmd); }
            else {
                // A bare nick becomes a mask, matching the GUI.
                let m = if mask.contains(['!', '@']) { mask.to_string() } else { format!("{}!*@*", mask) };
                let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("MODE {} {}b {}", target, sign, m) });
            }
        }
        "mode" => {
            // `/mode +o bob` means the current channel; `/mode #x +o bob` names it.
            let first = rest.split_whitespace().next().unwrap_or("");
            let line = if first.starts_with(['#','&','+','!']) && !first.starts_with("+") {
                format!("MODE {}", rest)
            } else if rest.trim().is_empty() {
                format!("MODE {}", target)
            } else {
                format!("MODE {} {}", target, rest)
            };
            let _ = tx.send(ClientMessage::Send { conn_id, raw: line });
        }
        "invite" => {
            let who = rest.trim();
            if who.is_empty() { app.status = "usage: /invite <nick>".into(); }
            else { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("INVITE {} {}", who, target) }); }
        }
        "slap" => {
            let who = rest.trim();
            let who = if who.is_empty() { "themselves" } else { who };
            let _ = tx.send(ClientMessage::Send { conn_id,
                raw: format!("PRIVMSG {} :\x01ACTION slaps {} around a bit with a large trout\x01", target, who) });
        }
        "say" => {
            if target.is_empty() || rest.is_empty() { app.status = "usage: /say <message>".into(); }
            else { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG {} :{}", target, rest) }); }
        }
        "ns" | "nickserv" => { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG NickServ :{}", rest) }); }
        "cs" | "chanserv" => { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG ChanServ :{}", rest) }); }
        "identify" | "id" => { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("PRIVMSG NickServ :IDENTIFY {}", rest) }); }
        "cycle" | "rejoin" => {
            let ch = if rest.trim().is_empty() { target.clone() } else { rest.trim().to_string() };
            if ch.is_empty() { app.status = "/cycle works in a channel".into(); }
            else {
                let _ = tx.send(ClientMessage::PartChannel { conn_id: conn_id.clone(), channel: ch.clone() });
                let _ = tx.send(ClientMessage::JoinChannel { conn_id, channel: ch, key: None });
            }
        }
        // /raw and /quote send the line exactly as typed — the escape hatch for
        // anything this client does not model.
        "raw" | "quote" => { let _ = tx.send(ClientMessage::Send { conn_id, raw: rest.clone() }); }

        // Anything still unrecognised goes to the server as typed. That covers
        // /whois, /nick, /list, /motd, /oper and every other single-token verb.
        _ => {
            let _ = tx.send(ClientMessage::Send { conn_id, raw: body.to_string() });
        }
    }
}
