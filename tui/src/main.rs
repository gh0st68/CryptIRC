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
mod sanitize;

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

use app::{wide_fold, App, CaseMap, Line, LineKind, PendingCycle, PendingJoin, Prompt, PromptKind, JOIN_GRACE};
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
        // Printed straight to the terminal by main()'s error path — strip any
        // control sequences a hostile or MITM'd server put in it.
        let msg = sanitize::clean(&msg).into_owned();
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

/// `Alive` is any frame that is not an event (a pong, a ping, an unparseable
/// text frame): proof the socket still carries data, used by the stall check.
enum Wire { Event(ServerEvent), Alive, Closed(String), Dropped(u64) }

/// r6 (codex P2 tui/src/app.rs:239, main.rs:203): the pump → UI queue is bounded. When the UI
/// falls behind, chat lines (IrcMessage) are dropped and counted — the user gets one notice
/// with the count and finds them in the history — while every other event waits for room
/// (backpressure on the socket), so state is never lost and memory stays bounded.
const WIRE_QUEUE: usize = 4096;

fn droppable(ev: &ServerEvent) -> bool { matches!(ev, ServerEvent::IrcMessage { .. } | ServerEvent::LagUpdate { .. }) }

/// Hand one frame to the UI (see WIRE_QUEUE). Err = the UI is gone.
async fn forward(tx: &mpsc::Sender<Wire>, w: Wire, dropped: &mut u64) -> Result<(), ()> {
    use tokio::sync::mpsc::error::TrySendError;
    if *dropped > 0 {
        match tx.try_send(Wire::Dropped(*dropped)) {
            Ok(()) => *dropped = 0,
            Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => return Err(()),
        }
    }
    let soft = match &w { Wire::Event(ev) => droppable(ev), Wire::Alive => true, _ => false };
    if soft {
        match tx.try_send(w) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(w)) => { if matches!(w, Wire::Event(ServerEvent::IrcMessage { .. })) { *dropped += 1; } Ok(()) }
            Err(TrySendError::Closed(_)) => Err(()),
        }
    } else {
        tx.send(w).await.map_err(|_| ())
    }
}

/// How often the pump pings the server. axum answers WebSocket pings itself, so
/// this works with every CryptIRC server version and needs no server change;
/// the pong is what keeps an otherwise silent (no networks, vault locked)
/// session from looking stalled.
const PING_EVERY: Duration = Duration::from_secs(30);
/// No frame of any kind for this long means the socket is probably half-open.
const STALL_AFTER: Duration = Duration::from_secs(120);

#[tokio::main]
async fn main() -> Result<()> {
    let cfg = load_config()?;
    eprint!("logging in… ");
    let token = login(&cfg).await?;
    eprintln!("ok");
    let url = ws_url(&cfg.base)?;

    let (tx_out, mut rx_out) = mpsc::unbounded_channel::<ClientMessage>();
    let (tx_in, mut rx_in) = mpsc::channel::<Wire>(WIRE_QUEUE);

    // ── WebSocket pump. Owns the socket; the UI never touches it directly. ──
    {
        let token = token.clone();
        let url = url.clone();
        tokio::spawn(async move {
            let (stream, _) = match tokio_tungstenite::connect_async(&url).await {
                Ok(s) => s,
                Err(e) => { let _ = tx_in.send(Wire::Closed(format!("connect failed: {}", e))).await; return; }
            };
            let (mut sink, mut src) = stream.split();
            // The server sends auth_required first and drops us after 5s of
            // silence, so send the token immediately rather than waiting for it.
            let _ = sink.send(WsMsg::Text(serde_json::to_string(&ClientMessage::Auth { token }).unwrap())).await;
            // Keep-alive. Neither side used to ping, so a session with nothing to
            // say (vault locked, no networks up) was indistinguishable from a dead
            // one and the stall check killed it. The first tick fires at once.
            let mut ping = tokio::time::interval(PING_EVERY);
            ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ping.tick().await;
            let mut dropped: u64 = 0;
            loop {
                tokio::select! {
                    out = rx_out.recv() => {
                        let Some(msg) = out else { break };
                        if let Ok(j) = serde_json::to_string(&msg) {
                            if let Err(e) = sink.send(WsMsg::Text(j)).await {
                                let _ = tx_in.send(Wire::Closed(format!("socket error: {}", e))).await;
                                break;
                            }
                        }
                    }
                    _ = ping.tick() => {
                        if let Err(e) = sink.send(WsMsg::Ping(Vec::new())).await {
                            let _ = tx_in.send(Wire::Closed(format!("socket error: {}", e))).await;
                            break;
                        }
                    }
                    inc = src.next() => {
                        match inc {
                            Some(Ok(WsMsg::Text(t))) => {
                                match serde_json::from_str::<ServerEvent>(&t) {
                                    Ok(ev) => { if forward(&tx_in, Wire::Event(ev), &mut dropped).await.is_err() { break; } }
                                    // An unparseable frame must never kill the client
                                    // — but it does prove the socket is alive.
                                    Err(_) => { if forward(&tx_in, Wire::Alive, &mut dropped).await.is_err() { break; } }
                                }
                            }
                            Some(Ok(WsMsg::Ping(p))) => {
                                let _ = sink.send(WsMsg::Pong(p)).await;
                                if forward(&tx_in, Wire::Alive, &mut dropped).await.is_err() { break; }
                            }
                            Some(Ok(WsMsg::Close(_))) | None => {
                                let _ = tx_in.send(Wire::Closed("server closed the connection".into())).await;
                                break;
                            }
                            Some(Err(e)) => {
                                let _ = tx_in.send(Wire::Closed(format!("socket error: {}", e))).await;
                                break;
                            }
                            // Pong (the answer to our keep-alive), binary, raw frames.
                            Some(Ok(_)) => { if forward(&tx_in, Wire::Alive, &mut dropped).await.is_err() { break; } }
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
    rx: &mut mpsc::Receiver<Wire>,
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
    // Set while the socket looks stalled: the per-network connected flags from
    // just before we greyed them out, restored the moment any frame arrives.
    let mut stalled: Option<std::collections::HashMap<String, bool>> = None;

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
                expire_pending_cycles(app);
                app.pending_joins.retain(|p| p.asked.elapsed() <= JOIN_GRACE);
                // A half-open socket is otherwise undetectable for ~15 minutes of
                // TCP retries while the user types into the void. The pump pings
                // every PING_EVERY, so on a healthy socket some frame (at least the
                // pong) always arrives well inside STALL_AFTER. This only WARNS:
                // receiving stays on, so a socket that was merely slow recovers by
                // itself instead of being silently disabled for good.
                if wire_open && stalled.is_none() && last_frame.elapsed() > STALL_AFTER {
                    stalled = Some(app.connected.clone());
                    app.status = "connection stalled — no data from the server for 2 minutes (still waiting; Ctrl+C to quit)".into();
                    for (_, v) in app.connected.iter_mut() { *v = false; }
                }
            }
            _ = sigterm.recv() => { app.should_quit = true; }
            _ = sighup.recv() => { app.should_quit = true; }
            wire = rx.recv(), if wire_open => {
                if matches!(wire, Some(Wire::Event(_)) | Some(Wire::Alive) | Some(Wire::Dropped(_))) {
                    last_frame = std::time::Instant::now();
                    if let Some(prev) = stalled.take() {
                        // Put back what we greyed out; events in this batch then
                        // update it as normal.
                        for (k, v) in prev { app.connected.insert(k, v); }
                        app.status = "connection recovered".into();
                    }
                }
                match wire {
                    Some(Wire::Event(ev)) => { handle_event(app, ev); }
                    Some(Wire::Alive) => {}
                    Some(Wire::Dropped(n)) => note_dropped(app, n),
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
                    match w {
                        Wire::Event(ev) => { last_frame = std::time::Instant::now(); handle_event(app, ev); }
                        Wire::Alive => { last_frame = std::time::Instant::now(); }
                        Wire::Dropped(n) => { last_frame = std::time::Instant::now(); note_dropped(app, n); }
                        Wire::Closed(why) => {
                            app.status = format!("disconnected: {} — press Ctrl+C to quit", why);
                            for (_, v) in app.connected.iter_mut() { *v = false; }
                            wire_open = false;
                            break;
                        }
                    }
                }
                ensure_history(app, &tx);
                for m in app.outbox.drain(..) { let _ = tx.send(m); }
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
                    // Paste goes to whichever input has focus, never straight to
                    // the wire. While the vault prompt is up that is the prompt —
                    // routing it to the chat line instead sent an empty unlock and
                    // left the passphrase in the chat input for the next Enter to
                    // post to a channel.
                    Event::Paste(text) => {
                        last_input = std::time::Instant::now();
                        if is_idle { is_idle = false; let _ = tx.send(ClientMessage::Active {}); }
                        handle_paste(app, &text);
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
        limit: Some(200), before: None, before_id: None,
        status_view: status_view_for(&b.target),
    });
}

/// GetLogs' optional `status_view`. The server keeps its own output (MOTD,
/// numerics, server notices, AWAY/back lines) in the log named "status" — the
/// same log a DM with a user whose nick is `status` (any case: the server
/// merges case variants) reads. A query buffer only ever wants that user's
/// conversation. The network buffer (target "") never fetches history.
fn status_view_for(target: &str) -> Option<String> {
    target.eq_ignore_ascii_case("status").then(|| "query".to_string())
}

/// The client-side half of the same split, for servers older than 0.5.8 that
/// ignore `status_view` (and harmless on newer ones, which already filtered):
/// the rule of the server's StatusView::Query (src/logs.rs) — PRIVMSG/ACTION
/// lines, and NOTICEs sent by `status` itself — minus anything server-origin.
/// A missing kind is a PRIVMSG, as the server's own parser reads it.
fn is_status_query_line(l: &LogLine) -> bool {
    if is_server_origin(&l.from) { return false; }
    let kind = l.kind.to_ascii_lowercase();
    match kind.as_str() {
        "" | "privmsg" | "action" => true,
        "notice" => l.from.eq_ignore_ascii_case("status"),
        _ => false,
    }
}

/// Fetch the page BEFORE the oldest line we hold, when the user scrolls to the
/// top. Without this only the most recent 200 lines were ever reachable.
fn maybe_page_history(app: &mut App, tx: &mpsc::UnboundedSender<ClientMessage>) {
    let Some(b) = app.buffers.get_mut(app.current) else { return };
    if b.target.is_empty() || b.lines.is_empty() { return; }
    // Only at the very top, and only once per page (page_pending clears when
    // the page lands).
    if b.scroll + 1 < b.total_rows.max(b.lines.len()) { return; }
    if !b.history_asked || b.page_pending || b.history_end { return; }
    let oldest = b.lines.iter().map(|l| l.ts).min().unwrap_or(0);
    if oldest == 0 { return; }
    // The exact cursor: the lowest id among the lines of that oldest second. The
    // server then pages by id inside the second instead of resending all of it
    // (capped), which left holes when one second held more lines than the cap.
    // Lines without an id (pre-v0.3.0 history, local status lines) cannot be a
    // cursor; with none left, the whole-second form is used as before.
    let before_id = b.lines.iter().filter(|l| l.ts == oldest && l.id != 0).map(|l| l.id).min();
    b.page_pending = true;
    let _ = tx.send(ClientMessage::GetLogs {
        conn_id: b.conn_id.clone(), target: b.target.clone(),
        limit: Some(200), before: Some(oldest), before_id,
        status_view: status_view_for(&b.target),
    });
}

/// A channel name (the TUI's channel test everywhere: /kick, /close, /cycle, …).
fn is_channel_name(t: &str) -> bool { t.starts_with(['#', '&', '+', '!']) }

/// Raise the vault passphrase prompt. The vault gates decryption of the stored
/// network credentials, so until it is open the server cannot dial IRC and the
/// client has nothing to show.
fn ask_vault(app: &mut App) {
    // A "vault unlocked elsewhere" prompt that is still up becomes the passphrase prompt
    // again (the vault was locked again); anything typed into it is discarded.
    if app.prompt.as_ref().is_some_and(|p| p.kind == PromptKind::VaultUnlockedElsewhere) { app.prompt = None; }
    if app.prompt.is_some() { return; }
    app.prompt = Some(Prompt {
        label: "vault passphrase:".into(), value: String::new(),
        masked: true, kind: PromptKind::Vault,
    });
    app.status = "vault is locked — unlock to connect to IRC".into();
}

/// A State says the vault is unlocked (see the State arm).
fn vault_unlocked_by_state(app: &mut App) {
    let Some(p) = &mut app.prompt else { return };
    if p.kind != PromptKind::Vault || app.unlock_submitted { return; }
    p.value.clear();
    p.kind = PromptKind::VaultUnlockedElsewhere;
    p.label = "vault unlocked in another session — Enter/Esc to close (anything typed here is discarded):".into();
    app.status = "the vault was unlocked in another session — the passphrase prompt was closed without sending anything".into();
}

/// r8 (codex P2 tui/src/main.rs:874): the member-list bounds of the server (irc.rs
/// NAMES_BUF_MAX_PER_CHAN / NAMES_ENTRY_MAX_BYTES) for a window's list grown by live JOINs.
const MAX_NAMES_PER_WINDOW: usize = 4096;
const MAX_NAME_BYTES: usize = 96;

/// r9: a nick for display, at most MAX_NAME_BYTES (on a char boundary) + "…".
fn clip_name(s: &str) -> String {
    if s.len() <= MAX_NAME_BYTES { return s.to_string(); }
    let mut end = MAX_NAME_BYTES;
    while !s.is_char_boundary(end) { end -= 1; }
    format!("{}…", &s[..end])
}

/// r6: the pump dropped `n` chat lines because the UI fell behind (see WIRE_QUEUE).
fn note_dropped(app: &mut App, n: u64) {
    let text = format!("⚠ {} incoming message(s) were not shown — this client fell behind; they are in the history (reopen the window or scroll up)", n);
    app.status = text.clone();
    let idx = app.current;
    app.add_line(idx, Line { ts: chrono::Utc::now().timestamp(), from: String::new(), text, kind: LineKind::Status, id: 0 }, false);
}

fn status_line(app: &mut App, conn_id: &str, target: &str, text: String) {
    // Label the network buffer with its conn_id if we have not seen a State for
    // it yet — otherwise a Connected/Disconnected arriving first mints a nameless
    // row in the buffer list.
    let i = app.buf_index(conn_id, target, Some(conn_id));
    app.add_line(i, Line { ts: chrono::Utc::now().timestamp(), from: String::new(), text, kind: LineKind::Status, id: 0 }, false);
}

/// Which buffer an `irc_message` belongs in. The server has ALREADY routed it
/// (../src/irc.rs): `target` is the channel, the sender's nick for a private
/// message, the queried nick for WHOIS replies (sent with from "*"), or the
/// literal "status" for server output (MOTD, numerics, server notices).
/// Re-routing every non-channel target to `from` sent WHOIS and server output
/// into a pseudo-DM named "*" (or after the server).
///
/// "status" is NOT trusted on its own: `status` is a legal nick, and a private
/// message from that user arrives with target "status" too (target = sender).
/// So the network buffer ("" here) is used only when `from` is server-origin,
/// exactly the values irc.rs uses for its own lines: "*" (no prefix, numerics,
/// WHOIS), a server name (contains '.'; nicks cannot), or the "links" relay of
/// 364/365. A real nick gets its own query buffer instead, so it can never pass
/// for server output.
/// One fallback stays: a target that is our OWN nick still goes to the sender.
fn display_buffer(target: &str, from: &str, our_nick: &str) -> String {
    if target == "status" {
        if is_server_origin(from) { return String::new(); }
        // Our own notice to a user called "status" (no echo-message) keeps its
        // recipient; anyone else goes to their own buffer.
        return if from.eq_ignore_ascii_case(our_nick) { target.to_string() } else { from.to_string() };
    }
    if target.starts_with(['#', '&', '+', '!']) { return target.to_string(); }
    let real_sender = !is_server_origin(from) && !from.eq_ignore_ascii_case(our_nick);
    if real_sender && (target.is_empty() || target.eq_ignore_ascii_case(our_nick)) {
        return from.to_string();
    }
    target.to_string()
}

/// A `from` that src/irc.rs only ever uses for lines the SERVER produced.
fn is_server_origin(from: &str) -> bool {
    from.is_empty() || from == "*" || from.contains('.') || from == "links"
}

/// How long a /cycle waits for its State before it is dropped (it must never
/// fire minutes later on some unrelated snapshot).
const CYCLE_WAIT: Duration = Duration::from_secs(15);

/// Carry out the /cycle requests that were waiting for this State: PART, then
/// JOIN with the key the server holds for the channel right now. The server
/// handles one socket's frames in order, so the JOIN's key is saved again after
/// the PART has forgotten it.
fn run_pending_cycles(app: &mut App, networks: &[NetworkState]) {
    for p in std::mem::take(&mut app.pending_cycles) {
        if p.asked.elapsed() > CYCLE_WAIT { continue; }
        let Some(n) = networks.iter().find(|n| n.config.id == p.conn_id) else {
            app.status = format!("/cycle {}: that network is gone", p.channel);
            continue;
        };
        // A JoinChannel is a no-op without a live connection, while the PART
        // would still drop the channel (and its key) from auto-join.
        if !n.connected {
            app.status = format!("/cycle {}: not connected", p.channel);
            continue;
        }
        // The saved key that is THIS channel's under the network's CASEMAPPING (codex P2
        // tui/src/main.rs:615, agy P2, w3-ops V3O-2): on an ascii server `#x[y]` and
        // `#x{y}` are different channels, and sending one's key for the other leaked it.
        let key = match saved_channel_key(&n.config.channel_keys, &p.channel, app.casemap.get(&p.conn_id).copied()) {
            Ok(k) => k.map(str::to_string),
            Err(stored) => {
                app.status = format!("/cycle {}: its saved key is stored as {} and this network's case mapping is unknown — use /part, then /join {} <key>", p.channel, stored, p.channel);
                continue;
            }
        };
        // Locked vault: the key is still the encrypted blob. Sending it would fail
        // the JOIN, and the PART would remove the real key.
        if key.as_deref().is_some_and(is_enc_blob) {
            app.status = format!("/cycle {}: unlock the vault first (its saved key is still encrypted)", p.channel);
            continue;
        }
        app.outbox.push(ClientMessage::PartChannel { conn_id: p.conn_id.clone(), channel: p.channel.clone() });
        app.outbox.push(ClientMessage::JoinChannel { conn_id: p.conn_id, channel: p.channel, key });
    }
}

/// Drop /cycle requests whose State never came (run from the 1 s ticker).
fn expire_pending_cycles(app: &mut App) {
    let before = app.pending_cycles.len();
    app.pending_cycles.retain(|p| p.asked.elapsed() <= CYCLE_WAIT);
    if app.pending_cycles.len() != before { app.status = "/cycle cancelled: no reply from the server".into(); }
}

/// The key the server has saved for `channel`, found the way the server finds it
/// (src/irc.rs existing_key_slot): the lowercased name, else an entry that is the same
/// channel under the network's CASEMAPPING `cm` — the entry PartChannel deletes.
/// `cm` unknown (an older server that does not say, and no 005 seen): Err(stored name)
/// when only an entry under ANOTHER spelling could match (`#x{y}` vs a stored `#x[y]`),
/// because on an ascii server that is a different channel's key and on an RFC1459 one
/// the same channel's — the caller refuses rather than guess.
fn saved_channel_key<'a>(keys: &'a std::collections::HashMap<String, String>, channel: &str, cm: Option<CaseMap>) -> Result<Option<&'a str>, String> {
    if let Some(k) = keys.get(&channel.to_lowercase()) { return Ok(Some(k.as_str())); }
    match cm {
        Some(cm) => {
            let folded = cm.fold(channel);
            Ok(keys.iter().find(|(k, _)| cm.fold(k) == folded).map(|(_, v)| v.as_str()))
        }
        None => {
            let folded = CaseMap::Rfc1459.fold(channel);
            match keys.keys().find(|k| CaseMap::Rfc1459.fold(k) == folded) {
                Some(stored) => Err(stored.clone()),
                None => Ok(None),
            }
        }
    }
}

/// The CASEMAPPING token of a 005 (ISUPPORT) line as the server forwards it to the
/// status window ("… CASEMAPPING=ascii … are supported by this server").
fn casemapping_in_isupport(text: &str) -> Option<CaseMap> {
    text.split(' ').find_map(|t| {
        let (k, v) = t.split_once('=')?;
        k.eq_ignore_ascii_case("CASEMAPPING").then(|| CaseMap::from_token(v))
    })
}

/// A still-encrypted vault value, by the server's own test (AppState::is_enc_blob):
/// "enc:" followed by standard base64 of at least 28 bytes (nonce + tag). A real
/// key that merely starts with "enc:" does not pass.
fn is_enc_blob(s: &str) -> bool {
    let Some(b64) = s.strip_prefix("enc:") else { return false };
    let body = b64.trim_end_matches('=');
    let pad = b64.len() - body.len();
    if b64.len() % 4 != 0 || pad > 2 { return false; }
    if !body.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'+' || c == b'/') { return false; }
    b64.len() / 4 * 3 - pad >= 28
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
            app.unlock_submitted = false;
            // Our own submission completed (VaultUnlocked goes only to the socket that sent
            // the passphrase). A "vault unlocked elsewhere" prompt stays until Enter/Esc.
            if app.prompt.as_ref().is_some_and(|p| p.kind == PromptKind::Vault) { app.prompt = None; }
            app.status = "vault unlocked".into();
            // Logs are encrypted, so any history requested while the vault was
            // locked came back empty. Re-arm those buffers rather than leaving
            // them blank for the rest of the session.
            for b in app.buffers.iter_mut() {
                if b.lines.is_empty() { b.history_asked = false; }
                b.history_end = false;   // a locked-vault page came back empty
            }
        }
        ServerEvent::VaultError { message } => {
            app.unlock_submitted = false;
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
            //
            // r5 (codex P2 tui/src/main.rs:706 HIGH): an unlocked State used to close the
            // passphrase prompt whatever its state — so when another session unlocked the
            // vault just before this user pasted the passphrase, the paste and the Enter went
            // to the chat line and the passphrase was posted to the channel. Now: a prompt
            // whose submission is in flight waits for its own answer (VaultUnlocked /
            // VaultError); an unsubmitted one turns into a masked "unlocked elsewhere" prompt
            // that still captures input, discards it, and closes on Enter/Esc.
            if vault_unlocked { vault_unlocked_by_state(app); } else { ask_vault(app); }
            for n in &networks {
                if let Some(cm) = n.casemapping.as_deref() { app.casemap.insert(n.config.id.clone(), CaseMap::from_token(cm)); }
            }
            run_pending_cycles(app, &networks);
            for n in networks {
                let cid = n.config.id.clone();
                let label = if n.config.label.is_empty() { cid.clone() } else { n.config.label.clone() };
                app.nicks.insert(cid.clone(), n.nick.clone());
                app.connected.insert(cid.clone(), n.connected);
                app.lag.insert(cid.clone(), n.lag_ms);
                // Status buffer for the network itself.
                app.buf_index(&cid, "", Some(&label));
                // r6: the channels we are in (see App::event_buf). A locked vault reports none;
                // keep the last known set then.
                if vault_unlocked {
                    app.joined.insert(cid.clone(), n.channels.iter().map(|c| wide_fold(&c.name)).collect());
                }
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
                //
                // agy P2 tui/src/main.rs:708: compared under the widest fold (the server may
                // list `#chan{1}` for a window opened as `#chan[1]` on an RFC1459 network — a
                // stale window kept is harmless, a live one closed is not), and never a channel
                // whose /join is still awaiting the server's confirmation (a State taken in
                // between does not list it yet).
                if vault_unlocked && n.connected {
                    let keep: std::collections::HashSet<String> = n.channels.iter().map(|c| wide_fold(&c.name)).collect();
                    let doomed: Vec<usize> = app.buffers.iter().enumerate()
                        .filter(|(_, b)| b.conn_id == cid && b.is_channel()
                            && !keep.contains(&wide_fold(&b.target)) && !app.join_pending(&cid, &b.target))
                        .map(|(i, _)| i).collect();
                    // Remove back-to-front so earlier indices stay valid.
                    for i in doomed.into_iter().rev() { app.remove_buffer(i); }
                }
            }
        }
        ServerEvent::IrcMessage { conn_id, from, target, text, ts, kind, msg_id, replayed } => {
            // The server's 005 lines reach the status window: learn its CASEMAPPING (for
            // /cycle's key lookup) when an older server's State does not carry it.
            if target == "status" && is_server_origin(&from) && text.contains("CASEMAPPING=") {
                if let Some(cm) = casemapping_in_isupport(&text) { app.casemap.insert(conn_id.clone(), cm); }
            }
            let our = app.our_nick(&conn_id).to_string();
            let buf_target = display_buffer(&target, &from, &our);
            let hint = if buf_target.is_empty() { Some(conn_id.as_str()) } else { None };
            // r6: a NEW window from an incoming line is capped per network (App::event_buf).
            let (i, overflowed) = app.event_buf(&conn_id, &buf_target, hint);
            let text = if overflowed { format!("[{}] {}", buf_target, text) } else { text };
            // Case-INSENSITIVE: live events carry "Action"/"Notice" (MessageKind has
            // no rename_all) while history carries "action"/"notice".
            let lk = if kind.eq_ignore_ascii_case("action") { LineKind::Action }
                else if kind.eq_ignore_ascii_case("notice") { LineKind::Notice }
                else { LineKind::Msg };
            // Highlight on our nick, word-boundary style so a short nick does not
            // match inside every other word. Replayed history never highlights.
            let hl = !replayed && text.to_lowercase().split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                .any(|w| w == our.to_lowercase());
            // A real private message is a highlight. Server output is not: the
            // status buffer, and WHOIS replies (from "*") in a nick's buffer.
            let is_pm = !buf_target.is_empty() && !buf_target.starts_with(['#','&','+','!']) && !is_server_origin(&from);
            app.add_line_ex(i, Line { ts, from, text, kind: lk, id: msg_id }, hl || is_pm, replayed);
        }
        ServerEvent::IrcEcho { conn_id, from, target, text, ts, kind, msg_id } => {
            // r7 (codex P2 tui/src/main.rs:861): a bot's echo can name any nick that triggered
            // it — a new window through the capped path like any incoming line.
            let (i, ov) = app.event_buf(&conn_id, &target, None);
            let text = if ov { format!("[{}] {}", target, text) } else { text };
            let lk = if kind.eq_ignore_ascii_case("action") { LineKind::Action } else { LineKind::Own };
            app.add_line(i, Line { ts, from, text, kind: lk, id: msg_id }, false);
        }
        ServerEvent::IrcJoin { conn_id, nick, channel, ts }
        | ServerEvent::IrcJoinEx { conn_id, nick, channel, ts, .. } => {
            let our = app.our_nick(&conn_id).to_string();
            if nick.eq_ignore_ascii_case(&our) { app.confirm_join(&conn_id, &channel); }
            // r7 (codex P2 tui/src/main.rs:861): a JOIN the user did not ask for (a server-forced
            // or spoofed self-JOIN, churned with self-KICKs) opens a window only within the cap.
            let (i, ov) = app.event_buf(&conn_id, &channel, Some(&channel));
            if ov {
                app.add_line(i, Line { ts, from: String::new(), text: format!("[{}] {} has joined {}", channel, nick, channel), kind: LineKind::Status, id: 0 }, false);
                return;
            }
            if !nick.eq_ignore_ascii_case(&our) {
                if let Some(b) = app.buffers.get_mut(i) {
                    // r8 (codex P2 tui/src/main.rs:874): bounded like the server's member list
                    // (count and entry size) — a stream of distinct JOINs can't grow it forever.
                    if b.names.len() < MAX_NAMES_PER_WINDOW && nick.len() <= MAX_NAME_BYTES
                        && !b.names.iter().any(|n| n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&nick))
                    {
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
            // r7: someone else's PART only matters in a window we have.
            let Some(i) = app.find_buf(&conn_id, &channel) else { return };
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
            // r9 (astra P2 tui/src/main.rs:930): the member-entry bound applies to renames too —
            // an oversized new nick leaves the list (as the server's own list does) and is
            // shown clipped, so renames can't grow the TUI past what JOINs may.
            let fits = new.len() <= MAX_NAME_BYTES;
            let shown = clip_name(&new);
            for i in idxs {
                if let Some(b) = app.buffers.get_mut(i) {
                    for n in b.names.iter_mut() {
                        let pfx_len = n.len() - n.trim_start_matches(['~','&','@','%','+']).len();
                        if fits && n[pfx_len..].eq_ignore_ascii_case(&old) { *n = format!("{}{}", &n[..pfx_len], new); }
                    }
                    if !fits { b.names.retain(|n| !n.trim_start_matches(['~','&','@','%','+']).eq_ignore_ascii_case(&old)); }
                }
                app.add_line(i, Line { ts, from: String::new(), text: format!("{} is now known as {}", old, shown), kind: LineKind::Status, id: 0 }, false);
            }
        }
        ServerEvent::IrcTopic { conn_id, channel, topic, ts } => {
            let (i, ov) = app.event_buf(&conn_id, &channel, Some(&channel));
            if ov { return; }
            if let Some(b) = app.buffers.get_mut(i) { b.topic = topic.clone(); }
            app.add_line(i, Line { ts, from: String::new(), text: format!("topic: {}", topic), kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcNames { conn_id, channel, names } => {
            let (i, ov) = app.event_buf(&conn_id, &channel, Some(&channel));
            if ov { return; }
            if let Some(b) = app.buffers.get_mut(i) { b.names = names; }
        }
        ServerEvent::IrcMode { conn_id, target, modes, ts } => {
            // User modes arrive with target "status" (the server's name for the
            // network buffer); that must not mint a "status" pseudo-DM.
            let buf = if target == "status" { "" } else { target.as_str() };
            // Name a not-yet-seen network buffer after its conn_id, as status_line() does.
            let (i, ov) = app.event_buf(&conn_id, buf, if buf.is_empty() { Some(conn_id.as_str()) } else { None });
            let text = if buf.is_empty() { format!("mode {}", modes) } else { format!("mode/{} {}", target, modes) };
            let text = if ov { format!("[{}] {}", target, text) } else { text };
            app.add_line(i, Line { ts, from: String::new(), text, kind: LineKind::Status, id: 0 }, false);
        }
        ServerEvent::IrcKick { conn_id, channel, kicked, by, reason, ts } => {
            // r7 (codex P2 tui/src/main.rs:861): the kicked-from window is kept (to show why),
            // so a window is only ever opened for it within the cap.
            let (i, ov) = app.event_buf(&conn_id, &channel, Some(&channel));
            if ov {
                app.add_line(i, Line { ts, from: String::new(), text: format!("[{}] {} was kicked by {}", channel, kicked, by), kind: LineKind::Status, id: 0 }, false);
                return;
            }
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
            // The server keeps its own output (numerics, server notices, AWAY
            // lines) in the log named "status", the same log a query with a user
            // called "status" (or "Status": the server merges case variants)
            // reads. Only that user's lines belong in this buffer; the network
            // buffer ("") never asks for history. 0.5.8+ servers already return
            // only those (status_view "query"); this keeps older ones in line.
            let lines: Vec<_> = if target.eq_ignore_ascii_case("status") {
                lines.into_iter().filter(is_status_query_line).collect()
            } else { lines };
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
                let was_page = std::mem::replace(&mut b.page_pending, false);
                let existing: std::collections::HashSet<u64> =
                    b.lines.iter().filter(|l| l.id != 0).map(|l| l.id).collect();
                // Log lines written before v0.3.0 have no id. A page always holds
                // the whole second at the cursor, which we already show, so those
                // lines need a content key: (ts, from, text), the same key the web
                // client uses. It is counted, not a set, so two identical lines
                // within one second both survive.
                let mut seen: std::collections::HashMap<(i64, String, String), usize> = std::collections::HashMap::new();
                for l in b.lines.iter().filter(|l| l.id == 0) {
                    *seen.entry((l.ts, l.from.clone(), l.text.clone())).or_default() += 1;
                }
                hist.retain(|l| {
                    if l.id != 0 { return !existing.contains(&l.id); }
                    match seen.get_mut(&(l.ts, l.from.clone(), l.text.clone())) {
                        Some(n) if *n > 0 => { *n -= 1; false }
                        _ => true,
                    }
                });
                let n = hist.len();
                if was_page && n == 0 { b.history_end = true; }
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
                // Multi-line answers (the AI's especially) get one row per line;
                // a raw newline inside a Span would tear the screen layout.
                let ts = chrono::Utc::now().timestamp();
                let mut first = true;
                for part in text.split('\n').map(|p| p.trim_end_matches('\r')).filter(|p| !p.trim().is_empty()) {
                    let t = if first { format!("{} {}", label, part) } else { format!("   {}", part) };
                    first = false;
                    app.add_line(i, Line { ts, from: String::new(), text: t, kind: LineKind::Status, id: 0 }, false);
                }
                if first {
                    app.add_line(i, Line { ts, from: String::new(), text: label, kind: LineKind::Status, id: 0 }, false);
                }
            } else {
                app.status = text;
            }
        }
        ServerEvent::Unknown => {}
    }
}

/// A bracketed paste. Goes to whichever input owns the keyboard: the modal
/// prompt while one is up, the chat line otherwise.
fn handle_paste(app: &mut App, text: &str) {
    if let Some(p) = &mut app.prompt {
        // A password manager often appends a newline; a line break is never part
        // of the passphrase.
        p.value.extend(text.chars().filter(|c| *c != '\n' && *c != '\r'));
        return;
    }
    // Newlines become spaces so a pasted block is ONE message the user can still
    // edit or think better of. Control characters are dropped (clipboard text is
    // untrusted and the input line is drawn to the terminal).
    let flat: String = text.chars().map(|c| if c == '\n' || c == '\r' { ' ' } else { c }).collect();
    for c in sanitize::clean(&flat).chars() { app.insert(c); }
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
                // An empty submit is never a real attempt (it is what a paste that
                // went astray used to produce) — don't spend an unlock on it.
                if p.value.is_empty() {
                    app.status = "type the vault passphrase, or Esc to leave it locked".into();
                    return;
                }
                let v = std::mem::take(&mut p.value);
                match p.kind {
                    PromptKind::Vault => {
                        let _ = tx.send(ClientMessage::UnlockVault { passphrase: v });
                        app.unlock_submitted = true;
                        app.status = "unlocking…".into();
                    }
                    // Unlocked elsewhere: nothing is sent; what was typed is dropped.
                    PromptKind::VaultUnlockedElsewhere => {
                        drop(v);
                        app.prompt = None;
                        app.status = "vault unlocked (in another session)".into();
                    }
                }
            }
            KeyCode::Esc => {
                let elsewhere = p.kind == PromptKind::VaultUnlockedElsewhere;
                app.prompt = None;
                app.status = if elsewhere { "vault unlocked (in another session)".into() }
                    else { "vault left locked — IRC will not connect. /vault to retry".into() };
            }
            KeyCode::Backspace => { p.value.pop(); }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) && !c.is_control() => p.value.push(c),
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
        KeyCode::Char(c) if !ctrl && !alt && !c.is_control() => app.insert(c),
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
    // No buffer at all = no network yet (an account without networks, or before
    // the first State arrives). Commands that need no network must still work
    // then; this guard used to block /quit and /vault as well.
    let (conn_id, target) = match app.cur() {
        Some(b) => (b.conn_id.clone(), b.target.clone()),
        None => {
            let cmd = text.strip_prefix('/').and_then(|b| b.split(' ').next()).unwrap_or("").to_lowercase();
            if !matches!(cmd.as_str(), "quit" | "exit" | "vault" | "unlock" | "theme" | "themes" | "help") {
                app.status = "no network yet — add one in the web app (/quit, /vault, /theme and /help work)".into();
                return;
            }
            (String::new(), String::new())
        }
    };

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
            // Until the server confirms it, a State snapshot does not list it (agy P2).
            app.pending_joins.retain(|p| !(p.conn_id == conn_id && p.channel.eq_ignore_ascii_case(ch)));
            app.pending_joins.push(PendingJoin { conn_id: conn_id.clone(), channel: ch.to_string(), asked: std::time::Instant::now() });
            let i = app.buf_index(&conn_id, ch, Some(ch));
            app.switch_to(i);
        }
        "part" | "leave" => {
            // r5 (agy P2 tui/src/main.rs:1234): a bare /part in a query or the network buffer
            // sent `PART <nick>` / `PART ` — it means the current CHANNEL only.
            if rest.is_empty() && !is_channel_name(&target) {
                app.status = "/part works in a channel (or: /part #channel) — /close closes this window".into();
                return;
            }
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
            // r5 (agy P2): a query buffer's target is a nick — `TOPIC bob` is not a topic.
            if !is_channel_name(&target) { app.status = "/topic works in a channel".into(); }
            else if rest.is_empty() { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("TOPIC {}", target) }); }
            else { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("TOPIC {} :{}", target, rest) }); }
        }
        "kick" => {
            let mut it = rest.splitn(2, ' ');
            match it.next().filter(|w| !w.is_empty()) {
                // KICK needs a channel. From a status or DM buffer it used to send
                // "KICK  nick :reason" (empty channel).
                _ if !target.starts_with(['#','&','+','!']) => app.status = "/kick works in a channel".into(),
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
            // r5: a channel buffer only (in a query this sent `MODE <nick> +o …`).
            if !is_channel_name(&target) || nicks.is_empty() {
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
            // r5 (agy P2 tui/src/main.rs:1411): a channel buffer only (in a query this sent
            // `MODE <nick> +b …`).
            if !is_channel_name(&target) { app.status = format!("/{} works in a channel", cmd); }
            else if mask.is_empty() { app.status = format!("usage: /{} <nick|mask>", cmd); }
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
            } else if target.is_empty() {
                // The network buffer has no channel to default to (this sent
                // "MODE  +i" with an empty target). An explicit nick target is
                // used as typed; bare modes mean our own user modes, as in irssi.
                if !first.is_empty() && !first.starts_with(['+', '-']) {
                    format!("MODE {}", rest)
                } else {
                    let me = app.nicks.get(&conn_id).map(|s| s.trim()).unwrap_or("");
                    if me.is_empty() { app.status = "usage: /mode <nick|#channel> [modes]".into(); return; }
                    if rest.is_empty() { format!("MODE {}", me) } else { format!("MODE {} {}", me, rest) }
                }
            } else if rest.trim().is_empty() {
                format!("MODE {}", target)
            } else {
                format!("MODE {} {}", target, rest)
            };
            let _ = tx.send(ClientMessage::Send { conn_id, raw: line });
        }
        "invite" => {
            // `/invite nick [#channel]`, the channel defaulting to this one, as
            // in the web client. Without either it used to send "INVITE nick "
            // with no channel from a status buffer.
            let mut it = rest.split_whitespace();
            let who = it.next().unwrap_or("");
            let ch = it.next().filter(|c| c.starts_with(['#','&','+','!']))
                .or_else(|| Some(target.as_str()).filter(|t| t.starts_with(['#','&','+','!'])));
            match (who.is_empty(), ch) {
                (true, _) => app.status = "usage: /invite <nick> [#channel]".into(),
                (false, None) => app.status = "usage: /invite <nick> #channel (or use it in a channel)".into(),
                (false, Some(ch)) => { let _ = tx.send(ClientMessage::Send { conn_id, raw: format!("INVITE {} {}", who, ch) }); }
            }
        }
        "slap" => {
            // A channel or a DM; the status buffer has no one to send it to (it
            // used to send "PRIVMSG  :..." with an empty target).
            if target.is_empty() { app.status = "/slap works in a channel or a query".into(); return; }
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
            // A named channel gets the same '#' default as /join.
            let ch = match rest.split_whitespace().next() {
                None => target.clone(),
                Some(c) if c.starts_with(['#','&','+','!']) => c.to_string(),
                Some(c) => format!("#{}", c),
            };
            if !ch.starts_with(['#','&','+','!']) { app.status = "/cycle works in a channel".into(); return; }
            // PartChannel makes the server forget the channel's saved key, and a
            // keyless JoinChannel then failed on a +k channel with the key already
            // gone. So the key is read first and sent with the rejoin. It is read
            // from a FRESH State: a +k set after we joined is saved server-side but
            // never pushed to us. The part/join pair goes out when that State
            // lands (see run_pending_cycles).
            let lc = ch.to_lowercase();
            if !app.pending_cycles.iter().any(|p| p.conn_id == conn_id && p.channel.to_lowercase() == lc) {
                app.pending_cycles.push(PendingCycle { conn_id, channel: ch.clone(), asked: std::time::Instant::now() });
            }
            let _ = tx.send(ClientMessage::GetState {});
            app.status = format!("cycling {}…", ch);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: KeyCode) -> KeyEvent { KeyEvent::new(c, KeyModifiers::NONE) }

    fn drain(rx: &mut mpsc::UnboundedReceiver<ClientMessage>) -> Vec<String> {
        let mut v = Vec::new();
        while let Ok(m) = rx.try_recv() { v.push(serde_json::to_string(&m).unwrap()); }
        v
    }

    #[test]
    fn paste_into_open_vault_prompt_goes_to_the_prompt() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = App::new("u".into());
        ask_vault(&mut app);
        handle_paste(&mut app, "hunter2secret\n");
        assert_eq!(app.input, "", "the passphrase must not land in the chat input");
        assert_eq!(app.prompt.as_ref().unwrap().value, "hunter2secret");
        handle_key(&mut app, key(KeyCode::Enter), &tx);
        let sent = drain(&mut rx);
        assert_eq!(sent, vec![r#"{"type":"unlock_vault","passphrase":"hunter2secret"}"#.to_string()]);
    }

    /// r5 (codex P2 tui/src/main.rs:706 HIGH): another session unlocking the vault while this
    /// prompt is up must never route the passphrase typed/pasted next into the chat line.
    #[test]
    fn unlock_elsewhere_never_routes_the_passphrase_to_chat() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = app_with_net();
        let locked = |u: bool| ev(&format!(r##"{{"type":"state","vault_unlocked":{},"networks":[{{"config":{{"id":"n1","label":"Net"}},"connected":true,"nick":"me","channels":[{{"name":"#t","topic":"","names":["@me"]}}]}}]}}"##, u));
        handle_event(&mut app, locked(false));
        assert!(app.prompt.as_ref().is_some_and(|p| p.kind == PromptKind::Vault));
        handle_paste(&mut app, "hunt");
        handle_event(&mut app, locked(true));            // unlocked by a browser meanwhile
        let p = app.prompt.as_ref().expect("prompt stays up");
        assert!(p.kind == PromptKind::VaultUnlockedElsewhere && p.value.is_empty() && p.masked);
        handle_paste(&mut app, "er2secret\n");           // the rest of the paste
        handle_key(&mut app, key(KeyCode::Enter), &tx);
        assert!(drain(&mut rx).is_empty(), "nothing sent — no unlock, no PRIVMSG");
        assert!(app.prompt.is_none() && app.input.is_empty(), "closed, chat line untouched");
        // Our own submission: an unlocked State before our VaultUnlocked keeps the prompt.
        handle_event(&mut app, locked(false));
        handle_paste(&mut app, "pw");
        handle_key(&mut app, key(KeyCode::Enter), &tx);
        assert_eq!(drain(&mut rx), vec![r#"{"type":"unlock_vault","passphrase":"pw"}"#.to_string()]);
        handle_event(&mut app, locked(true));
        assert!(app.prompt.as_ref().is_some_and(|p| p.kind == PromptKind::Vault), "waits for its own answer");
        handle_event(&mut app, ServerEvent::VaultUnlocked { e2e_enc_key: String::new() });
        assert!(app.prompt.is_none());
        // A wrong passphrase keeps the prompt for another try.
        handle_event(&mut app, locked(false));
        handle_paste(&mut app, "bad"); handle_key(&mut app, key(KeyCode::Enter), &tx); drain(&mut rx);
        handle_event(&mut app, ServerEvent::VaultError { message: "Incorrect passphrase".into() });
        handle_event(&mut app, locked(true));             // then someone else unlocks
        assert!(app.prompt.as_ref().is_some_and(|p| p.kind == PromptKind::VaultUnlockedElsewhere));
    }

    #[test]
    fn empty_vault_submit_is_not_sent() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = App::new("u".into());
        ask_vault(&mut app);
        handle_key(&mut app, key(KeyCode::Enter), &tx);
        assert!(drain(&mut rx).is_empty());
        assert!(app.prompt.is_some(), "prompt stays up");
    }

    #[test]
    fn paste_into_chat_line_is_flattened_and_sanitised() {
        let mut app = App::new("u".into());
        handle_paste(&mut app, "one\ntwo\x1b]0;PWN\x07 three\u{202E}x");
        assert_eq!(app.input, "one two]0;PWN threex");
        assert_eq!(app.cursor, app.input.len());
    }

    fn ev(json: &str) -> ServerEvent { serde_json::from_str(json).expect(json) }

    /// A connected network "n1" (our nick "me") with a status buffer, #t and a
    /// DM with bob; #t is current.
    fn app_with_net() -> App {
        let mut app = App::new("u".into());
        handle_event(&mut app, ev(r##"{"type":"state","vault_unlocked":true,"networks":[{"config":{"id":"n1","label":"Net"},"connected":true,"nick":"me","channels":[{"name":"#t","topic":"","names":["@me","alice"]}]}]}"##));
        let i = app.buf_index("n1", "#t", None);
        app.switch_to(i);
        app
    }
    fn targets(app: &App) -> Vec<String> { app.buffers.iter().map(|b| b.target.clone()).collect() }
    fn texts(app: &App, conn: &str, target: &str) -> Vec<String> {
        app.find_buf(conn, target).map(|i| app.buffers[i].lines.iter().map(|l| l.text.clone()).collect()).unwrap_or_default()
    }
    fn run(app: &mut App, line: &str) -> Vec<String> {
        let (tx, mut rx) = mpsc::unbounded_channel();
        submit(app, line.to_string(), &tx);
        drain(&mut rx)
    }

    #[test]
    fn live_join_ex_reaches_scrollback_and_nick_list() {
        let mut app = app_with_net();
        // The exact shape src/irc.rs emits for every JOIN (no extended-join: account/realname empty).
        handle_event(&mut app, ev(r##"{"type":"irc_join_ex","conn_id":"n1","nick":"bob","channel":"#t","account":"","realname":"","ts":7}"##));
        // With extended-join.
        handle_event(&mut app, ev(r##"{"type":"irc_join_ex","conn_id":"n1","nick":"carol","channel":"#T","account":"carol","realname":"Carol C","ts":8}"##));
        let i = app.find_buf("n1", "#t").unwrap();
        assert!(app.buffers[i].names.iter().any(|n| n == "bob"));
        assert!(app.buffers[i].names.iter().any(|n| n == "carol"));
        assert_eq!(texts(&app, "n1", "#t"), vec!["bob has joined #t", "carol has joined #T"]);
        // The older irc_join shape still works.
        handle_event(&mut app, ev(r##"{"type":"irc_join","conn_id":"n1","nick":"dave","channel":"#t","ts":9}"##));
        assert!(app.buffers[i].names.iter().any(|n| n == "dave"));
        assert_eq!(texts(&app, "n1", "#t").last().unwrap(), "dave has joined #t");
    }

    #[test]
    fn server_routed_messages_keep_their_target() {
        let mut app = app_with_net();
        // WHOIS reply: from "*", target = the queried nick.
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"*","target":"bob","text":"bob!u@h (Bob)","kind":"Notice","ts":1}"##));
        // MOTD / numerics: from "*" or the server name, target "status".
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"*","target":"status","text":"- motd line","kind":"Notice","ts":2}"##));
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"irc.example.net","target":"status","text":"*** server notice","kind":"Notice","ts":3}"##));
        // A user mode change: target "status".
        handle_event(&mut app, ev(r##"{"type":"irc_mode","conn_id":"n1","target":"status","modes":"+Zi","ts":4}"##));
        // A private message, already routed to the sender by the server.
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"alice","target":"alice","text":"hi","kind":"Privmsg","msg_id":11,"ts":5}"##));
        // Compatibility: a PM whose target is our own nick still goes to the sender.
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"zed","target":"me","text":"yo","kind":"Privmsg","msg_id":12,"ts":6}"##));
        let t = targets(&app);
        assert!(!t.iter().any(|x| x == "*" || x == "status" || x == "irc.example.net" || x == "me"), "pseudo-buffers: {:?}", t);
        assert_eq!(texts(&app, "n1", "bob"), vec!["bob!u@h (Bob)"]);
        assert_eq!(texts(&app, "n1", ""), vec!["- motd line", "*** server notice", "mode +Zi"]);
        assert_eq!(texts(&app, "n1", "alice"), vec!["hi"]);
        assert_eq!(texts(&app, "n1", "zed"), vec!["yo"]);
        // The WHOIS buffer is not a highlight; a real PM is.
        assert_eq!(app.buffers[app.find_buf("n1", "bob").unwrap()].activity, 1);
        assert_eq!(app.buffers[app.find_buf("n1", "alice").unwrap()].activity, 2);
        // Channel messages are untouched.
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"alice","target":"#t","text":"chan","kind":"Privmsg","msg_id":13,"ts":7}"##));
        assert_eq!(texts(&app, "n1", "#t"), vec!["chan"]);
    }

    #[test]
    fn only_server_origin_lines_reach_the_status_buffer() {
        let mut app = app_with_net();
        // Server output: from "*", a server name (has a dot), and the 364/365 "links" relay.
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"*","target":"status","text":"numeric","kind":"Notice","ts":1}"##));
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"irc.example.net","target":"status","text":"server notice","kind":"Notice","ts":2}"##));
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"links","target":"status","text":"End of /LINKS","kind":"Notice","ts":3}"##));
        // A user literally called "status": the server sends target = sender = "status".
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"status","target":"status","text":"fake server line","kind":"Privmsg","msg_id":21,"ts":4,"prefix":"status!u@h"}"##));
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"status","target":"status","text":"fake notice","kind":"Notice","msg_id":22,"ts":5}"##));
        // Any other real nick the server filed under "status" (e.g. an unhandled command).
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"mallory","target":"status","text":"odd command","kind":"Notice","ts":6}"##));
        // Our own NOTICE to the user "status" (no echo-message).
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"me","target":"status","text":"my notice","kind":"Notice","ts":7}"##));
        // A dotted sender in a PM is routed by the server to that name, not to "status".
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"svc.example","target":"svc.example","text":"dotted","kind":"Privmsg","msg_id":23,"ts":8}"##));
        assert_eq!(texts(&app, "n1", ""), vec!["numeric", "server notice", "End of /LINKS"]);
        assert_eq!(texts(&app, "n1", "status"), vec!["fake server line", "fake notice", "my notice"]);
        assert_eq!(texts(&app, "n1", "mallory"), vec!["odd command"]);
        assert_eq!(texts(&app, "n1", "svc.example"), vec!["dotted"]);
        // Its history: the server's own lines in the shared "status" log stay out.
        let v = serde_json::json!({"type": "log_lines", "conn_id": "n1", "target": "status", "lines": [
            {"id": 1, "ts": 1, "from": "*", "text": "- motd -", "kind": "notice"},
            {"id": 2, "ts": 1, "from": "irc.example.net", "text": "server notice", "kind": "notice"},
            {"id": 3, "ts": 2, "from": "status", "text": "older dm", "kind": "privmsg"},
            {"id": 4, "ts": 3, "from": "me", "text": "my reply", "kind": "privmsg"}]});
        handle_event(&mut app, serde_json::from_value(v).unwrap());
        assert_eq!(texts(&app, "n1", "status"), vec!["older dm", "my reply", "fake server line", "fake notice", "my notice"]);
        // The user "status" is a real DM: a highlight, like any private message.
        assert_eq!(app.buffers[app.find_buf("n1", "status").unwrap()].activity, 2);
        assert_eq!(app.buffers[app.find_buf("n1", "").unwrap()].activity, 1);
    }

    #[test]
    fn status_line_before_any_state_gets_a_named_buffer() {
        let mut app = App::new("u".into());
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n9","from":"*","target":"status","text":"early","kind":"Notice","ts":1}"##));
        assert_eq!(app.buffers.len(), 1);
        assert_eq!(app.buffers[0].target, "");
        assert_eq!(app.buffers[0].label, "n9");
    }

    #[test]
    fn app_commands_work_with_no_buffer() {
        let mut app = App::new("u".into());
        assert!(app.buffers.is_empty());
        assert!(run(&mut app, "/vault").is_empty());
        assert!(app.prompt.is_some(), "/vault opens the prompt");
        app.prompt = None;
        assert!(run(&mut app, "/help").is_empty());
        assert!(app.status.starts_with("keys:"));
        // Anything that needs a network sends nothing (no frame with an empty conn_id).
        assert!(run(&mut app, "/connect").is_empty());
        assert!(run(&mut app, "/raw PRIVMSG x :y").is_empty());
        assert!(run(&mut app, "hello").is_empty());
        assert!(app.status.starts_with("no network yet"));
        assert!(!app.should_quit);
        assert!(run(&mut app, "/quit").is_empty());
        assert!(app.should_quit);
        let mut app = App::new("u".into());
        run(&mut app, "/EXIT");
        assert!(app.should_quit);
    }

    #[test]
    fn incoming_lines_open_at_most_the_cap_then_overflow() {
        // r6 (codex P2 tui/src/app.rs:239): a flood of private messages from unique nicks.
        let mut app = app_with_net();
        let msg = |from: &str, target: &str, text: &str| ev(&format!(r##"{{"type":"irc_message","conn_id":"n1","from":"{}","target":"{}","text":"{}","kind":"Privmsg","ts":1}}"##, from, target, text));
        handle_event(&mut app, msg("friend", "me", "hello"));          // a real conversation, before the flood
        for k in 0..(crate::app::MAX_AUTO_BUFFERS_PER_NET + 50) {
            handle_event(&mut app, msg(&format!("flood{k}"), "me", "spam"));
            handle_event(&mut app, msg(&format!("flood{k}"), &format!("#junk{k}"), "spam"));   // channels we are not in
        }
        let auto = app.buffers.iter().filter(|b| b.conn_id == "n1" && !b.target.is_empty() && b.target != "#t").count();
        assert!(auto <= crate::app::MAX_AUTO_BUFFERS_PER_NET + 1, "{auto} windows");
        let ov = texts(&app, "n1", crate::app::OVERFLOW_BUF);
        assert!(ov.iter().any(|t| t.starts_with("too many new conversations")), "one notice in the overflow window");
        assert_eq!(ov.iter().filter(|t| t.starts_with("too many new conversations")).count(), 1);
        assert!(ov.iter().any(|t| t == "[flood249] spam") && ov.iter().any(|t| t == "[#junk249] spam"), "{:?}", &ov[ov.len().saturating_sub(3)..]);
        // Known windows keep receiving; the joined channel is never counted or redirected.
        handle_event(&mut app, msg("friend", "me", "after the flood"));
        assert!(texts(&app, "n1", "friend").contains(&"after the flood".to_string()));
        handle_event(&mut app, msg("alice", "#t", "channel line"));
        assert!(texts(&app, "n1", "#t").contains(&"channel line".to_string()));
        // Opening a window yourself is never refused.
        run(&mut app, "/msg newbuddy hi");
        assert!(app.find_buf("n1", "newbuddy").is_some());
        // Every window is reachable exactly once in the display order.
        let mut seen = app.display_order.clone(); seen.sort_unstable(); seen.dedup();
        assert_eq!(seen.len(), app.buffers.len());
    }

    #[test]
    fn self_join_kick_churn_and_bot_echoes_stay_within_the_cap() {
        // r7 (codex P2 tui/src/main.rs:861): server-forced self-JOIN + self-KICK of fresh
        // channels, and bot echoes to fresh nicks.
        let mut app = app_with_net();
        let total = crate::app::MAX_AUTO_BUFFERS_PER_NET + 100;
        for k in 0..total {
            handle_event(&mut app, ev(&format!(r##"{{"type":"irc_join","conn_id":"n1","nick":"me","channel":"#forced{k}","ts":1}}"##)));
            handle_event(&mut app, ev(&format!(r##"{{"type":"irc_kick","conn_id":"n1","channel":"#forced{k}","kicked":"me","by":"op","reason":"x","ts":1}}"##)));
            handle_event(&mut app, ev(&format!(r##"{{"type":"irc_echo","conn_id":"n1","from":"me","target":"asker{k}","text":"bot reply","kind":"Privmsg","ts":1,"msg_id":0}}"##)));
        }
        let auto = app.buffers.iter().filter(|b| b.conn_id == "n1" && !b.target.is_empty() && b.target != "#t").count();
        assert!(auto <= crate::app::MAX_AUTO_BUFFERS_PER_NET + 1, "{auto} windows");
        let ov = texts(&app, "n1", crate::app::OVERFLOW_BUF);
        assert!(ov.iter().any(|t| t.starts_with(&format!("[#forced{}]", total - 1))) && ov.iter().any(|t| t.starts_with(&format!("[asker{}]", total - 1))));
        // A JOIN the user asked for still opens its window past the cap.
        run(&mut app, "/join #wanted");
        handle_event(&mut app, ev(r##"{"type":"irc_join","conn_id":"n1","nick":"me","channel":"#wanted","ts":1}"##));
        assert!(app.find_buf("n1", "#wanted").is_some());
    }

    #[test]
    fn live_joins_cannot_grow_a_member_list_without_bound() {
        // r8 (codex P2 tui/src/main.rs:874): distinct JOINs into one channel, plus oversized nicks.
        let mut app = app_with_net();
        for k in 0..(MAX_NAMES_PER_WINDOW + 500) {
            handle_event(&mut app, ev(&format!(r##"{{"type":"irc_join","conn_id":"n1","nick":"j{k}","channel":"#t","ts":1}}"##)));
        }
        handle_event(&mut app, ev(&format!(r##"{{"type":"irc_join","conn_id":"n1","nick":"{}","channel":"#t","ts":1}}"##, "x".repeat(MAX_NAME_BYTES + 1))));
        let b = &app.buffers[app.find_buf("n1", "#t").unwrap()];
        assert!(b.names.len() <= MAX_NAMES_PER_WINDOW, "{}", b.names.len());
        assert!(b.names.iter().all(|n| n.len() <= MAX_NAME_BYTES));
    }

    #[test]
    fn renames_obey_the_member_entry_bound() {
        // r9 (astra P2 tui/src/main.rs:930): an oversized NICK leaves the member list and is shown
        // clipped; a normal rename still renames.
        let mut app = app_with_net();
        let huge = "z".repeat(8000);
        handle_event(&mut app, ev(&format!(r##"{{"type":"irc_nick","conn_id":"n1","old":"alice","new":"{}","ts":1}}"##, huge)));
        let b = &app.buffers[app.find_buf("n1", "#t").unwrap()];
        assert!(b.names.iter().all(|n| n.len() <= MAX_NAME_BYTES), "{:?}", b.names.iter().map(|n| n.len()).collect::<Vec<_>>());
        assert!(!b.names.iter().any(|n| n.contains("alice")), "the renamed member left the list");
        assert!(b.lines.iter().all(|l| l.text.len() < MAX_NAME_BYTES + 64), "the status line is clipped");
        handle_event(&mut app, ev(r##"{"type":"irc_nick","conn_id":"n1","old":"me","new":"me2","ts":1}"##));
        let b = &app.buffers[app.find_buf("n1", "#t").unwrap()];
        assert!(b.names.iter().any(|n| n == "@me2"), "{:?}", b.names);
    }

    #[test]
    fn rebuild_order_places_every_window_once() {
        let mut app = App::new("u".into());
        for n in 0..3 {
            let net = format!("n{n}");
            app.buf_index(&net, "", Some(&net));
            for k in 0..1500 { app.buffers.push(crate::app::Buffer::test_new(&net, &format!("{}{k}", if k % 2 == 0 { "#c" } else { "nick" }))); }
        }
        // A second network buffer for one connection (orphan) is still reachable.
        app.buffers.push(crate::app::Buffer::test_new("n1", ""));
        let t = std::time::Instant::now();
        app.rebuild_order();
        let took = t.elapsed();
        let mut seen = app.display_order.clone(); seen.sort_unstable(); seen.dedup();
        assert_eq!(seen.len(), app.buffers.len(), "a permutation of every window");
        assert_eq!(app.buffers[app.display_order[0]].target, "", "network window first");
        assert!(took < std::time::Duration::from_millis(500), "{took:?} for {} windows", app.buffers.len());
    }

    #[test]
    fn next_and_previous_follow_the_list_on_screen() {
        // r6 (agy P2 tui/src/app.rs:409): storage order differs from the displayed order.
        let mut app = App::new("u".into());
        for (c, t) in [("n2", ""), ("n1", ""), ("n1", "zed"), ("n2", "#b"), ("n1", "#a"), ("n2", "#a")] {
            app.buf_index(c, t, Some(if t.is_empty() { c } else { t }));
        }
        let shown: Vec<(String, String)> = app.display_order.iter().map(|&i| (app.buffers[i].conn_id.clone(), app.buffers[i].target.clone())).collect();
        app.switch_to(app.display_order[0]);
        let mut walked = Vec::new();
        for _ in 0..shown.len() { let b = app.cur().unwrap(); walked.push((b.conn_id.clone(), b.target.clone())); app.next_buffer(); }
        assert_eq!(walked, shown, "Ctrl+N walks the list on screen");
        assert_eq!(app.current, app.display_order[0], "and wraps");
        app.prev_buffer();
        assert_eq!(app.current, *app.display_order.last().unwrap(), "Ctrl+P wraps backwards");
    }

    #[tokio::test]
    async fn the_event_queue_drops_chat_lines_when_full_but_never_state() {
        let (tx, mut rx) = mpsc::channel::<Wire>(2);
        let mut dropped = 0u64;
        let m = || Wire::Event(ev(r##"{"type":"irc_message","conn_id":"n1","from":"x","target":"me","text":"hi","kind":"Privmsg","ts":1}"##));
        for _ in 0..5 { forward(&tx, m(), &mut dropped).await.unwrap(); }
        assert_eq!(dropped, 3, "two queued, three dropped and counted");
        for _ in 0..2 { assert!(matches!(rx.recv().await, Some(Wire::Event(ServerEvent::IrcMessage { .. })))); }
        // A state event waits for room instead of being dropped; the count is reported first.
        forward(&tx, Wire::Event(ev(r##"{"type":"state","vault_unlocked":true,"networks":[]}"##)), &mut dropped).await.unwrap();
        assert!(matches!(rx.recv().await, Some(Wire::Dropped(3))));
        assert!(matches!(rx.recv().await, Some(Wire::Event(ServerEvent::State { .. }))));
        assert_eq!(dropped, 0);
    }

    #[test]
    fn channel_only_commands_refuse_query_and_network_buffers() {
        // r5 (agy P2): /topic, /ban, /unban, bare /part (and the /op family) in a query sent
        // TOPIC/MODE/PART to the nick.
        let mut app = app_with_net();
        for buf in ["bob", ""] {
            let i = if buf.is_empty() { app.find_buf("n1", "").unwrap() } else { app.buf_index("n1", buf, None) };
            app.switch_to(i);
            assert!(run(&mut app, "/topic").is_empty());
            assert!(run(&mut app, "/topic new topic").is_empty());
            assert_eq!(app.status, "/topic works in a channel");
            assert!(run(&mut app, "/ban spammer").is_empty());
            assert_eq!(app.status, "/ban works in a channel");
            assert!(run(&mut app, "/unban spammer").is_empty());
            assert!(run(&mut app, "/op alice").is_empty());
            assert!(run(&mut app, "/part").is_empty());
            assert!(app.status.starts_with("/part works in a channel"));
            // Naming the channel still works from anywhere.
            assert_eq!(run(&mut app, "/part #t"), vec![r##"{"type":"part_channel","conn_id":"n1","channel":"#t"}"##]);
        }
        // In a channel, unchanged.
        let c = app.find_buf("n1", "#t").unwrap();
        app.switch_to(c);
        assert_eq!(run(&mut app, "/topic"), vec![r##"{"type":"send","conn_id":"n1","raw":"TOPIC #t"}"##]);
        assert_eq!(run(&mut app, "/topic hi there"), vec![r##"{"type":"send","conn_id":"n1","raw":"TOPIC #t :hi there"}"##]);
        assert_eq!(run(&mut app, "/ban spammer"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #t +b spammer!*@*"}"##]);
        assert_eq!(run(&mut app, "/unban a!b@c"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #t -b a!b@c"}"##]);
        assert_eq!(run(&mut app, "/op alice"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #t +o alice"}"##]);
        assert_eq!(run(&mut app, "/part"), vec![r##"{"type":"part_channel","conn_id":"n1","channel":"#t"}"##]);
    }

    #[test]
    fn kick_slap_invite_never_send_an_empty_target() {
        let mut app = app_with_net();
        // Status buffer.
        let s = app.find_buf("n1", "").unwrap();
        app.switch_to(s);
        assert!(run(&mut app, "/kick bob being rude").is_empty());
        assert_eq!(app.status, "/kick works in a channel");
        assert!(run(&mut app, "/slap bob").is_empty());
        assert!(run(&mut app, "/invite bob").is_empty());
        // Naming the channel works anywhere, as in the web client.
        assert_eq!(run(&mut app, "/invite bob #x"), vec![r##"{"type":"send","conn_id":"n1","raw":"INVITE bob #x"}"##]);
        // In a channel, unchanged.
        let c = app.find_buf("n1", "#t").unwrap();
        app.switch_to(c);
        assert_eq!(run(&mut app, "/kick bob being rude"), vec![r##"{"type":"send","conn_id":"n1","raw":"KICK #t bob :being rude"}"##]);
        assert_eq!(run(&mut app, "/kick bob"), vec![r##"{"type":"send","conn_id":"n1","raw":"KICK #t bob :Kicked"}"##]);
        assert_eq!(run(&mut app, "/kick"), Vec::<String>::new());
        assert_eq!(app.status, "usage: /kick <nick> [reason]");
        assert_eq!(run(&mut app, "/slap bob"), vec!["{\"type\":\"send\",\"conn_id\":\"n1\",\"raw\":\"PRIVMSG #t :\\u0001ACTION slaps bob around a bit with a large trout\\u0001\"}".to_string()]);
        assert_eq!(run(&mut app, "/invite bob"), vec![r##"{"type":"send","conn_id":"n1","raw":"INVITE bob #t"}"##]);
        assert_eq!(run(&mut app, "/invite bob #other"), vec![r##"{"type":"send","conn_id":"n1","raw":"INVITE bob #other"}"##]);
        // In a DM: /slap is fine, /kick is not.
        let d = app.buf_index("n1", "bob", None);
        app.switch_to(d);
        assert_eq!(run(&mut app, "/slap").len(), 1);
        assert!(run(&mut app, "/kick bob").is_empty());
    }

    fn page(app: &mut App, lines: &[(u64, i64, &str, &str)]) {
        let lines: Vec<serde_json::Value> = lines.iter().map(|(id, ts, from, text)|
            serde_json::json!({"id": id, "ts": ts, "from": from, "text": text, "kind": "privmsg"})).collect();
        let v = serde_json::json!({"type": "log_lines", "conn_id": "n1", "target": "#t", "lines": lines});
        handle_event(app, serde_json::from_value(v).unwrap());
    }

    #[test]
    fn paging_does_not_duplicate_idless_boundary_lines() {
        let mut app = app_with_net();
        // Page 1 (newest): pre-v0.3.0 lines have id 0. Two identical lines in second 100.
        page(&mut app, &[(0, 100, "a", "dup"), (0, 100, "a", "dup"), (0, 100, "b", "x"), (0, 101, "a", "new")]);
        // Page 2 (before=100): older lines PLUS the whole boundary second again.
        page(&mut app, &[(0, 98, "a", "old1"), (0, 99, "a", "old2"), (0, 99, "a", "old2"),
                         (0, 100, "a", "dup"), (0, 100, "a", "dup"), (0, 100, "b", "x")]);
        let got: Vec<(i64, String)> = app.buffers[app.find_buf("n1", "#t").unwrap()].lines.iter()
            .map(|l| (l.ts, l.text.clone())).collect();
        assert_eq!(got, vec![(98, "old1".into()), (99, "old2".into()), (99, "old2".into()),
                             (100, "dup".into()), (100, "dup".into()), (100, "x".into()), (101, "new".into())]);
        // A boundary second that only partly overlaps keeps the new copy.
        page(&mut app, &[(0, 97, "a", "older"), (0, 98, "a", "old1"), (0, 98, "a", "old1")]);
        let n_old1 = app.buffers[app.find_buf("n1", "#t").unwrap()].lines.iter().filter(|l| l.text == "old1").count();
        assert_eq!(n_old1, 2, "the server had two old1 lines; we held one");
        // Lines with ids are still deduped by id.
        page(&mut app, &[(5, 96, "a", "with-id")]);
        page(&mut app, &[(4, 95, "a", "with-id-older"), (5, 96, "a", "with-id")]);
        let n = app.buffers[app.find_buf("n1", "#t").unwrap()].lines.iter().filter(|l| l.text == "with-id").count();
        assert_eq!(n, 1);
    }

    #[test]
    fn a_page_in_flight_does_not_trigger_a_second_initial_fetch() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = app_with_net();
        ensure_history(&mut app, &tx);                                // initial fetch for #t
        assert_eq!(drain(&mut rx).len(), 1);
        page(&mut app, &[(0, 100, "a", "only")]);                     // its reply: one line, all on screen
        maybe_page_history(&mut app, &tx);                            // a key press at the top
        let sent = drain(&mut rx);
        assert_eq!(sent.len(), 1);
        assert!(sent[0].contains(r#""before":100"#), "{:?}", sent);
        // Any wire event runs ensure_history; it must not re-send the initial fetch.
        handle_event(&mut app, ev(r##"{"type":"lag_update","conn_id":"n1","ms":3}"##));
        ensure_history(&mut app, &tx);
        maybe_page_history(&mut app, &tx);                            // nor a second page
        assert!(drain(&mut rx).is_empty());
        // The page lands with nothing new (only the boundary second): the start is
        // reached, so further key presses at the top stop asking.
        page(&mut app, &[(0, 100, "a", "only")]);
        maybe_page_history(&mut app, &tx);
        assert!(drain(&mut rx).is_empty());
        // Unlocking the vault re-arms it.
        handle_event(&mut app, ev(r##"{"type":"vault_unlocked"}"##));
        maybe_page_history(&mut app, &tx);
        assert_eq!(drain(&mut rx).len(), 1);
    }

    #[test]
    fn get_logs_sends_status_view_only_for_a_status_query_and_stays_old_shaped_otherwise() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = app_with_net();
        ensure_history(&mut app, &tx);
        // Byte-identical to the frame every older server has always received.
        assert_eq!(drain(&mut rx), vec![r##"{"type":"get_logs","conn_id":"n1","target":"#t","limit":200,"before":null}"##]);
        for nick in ["status", "Status", "STATUS"] {
            let mut app = app_with_net();   // buffers are case-insensitive: one app per spelling
            let i = app.buf_index("n1", nick, None);
            app.switch_to(i);
            ensure_history(&mut app, &tx);
            assert_eq!(drain(&mut rx), vec![format!(r##"{{"type":"get_logs","conn_id":"n1","target":"{}","limit":200,"before":null,"status_view":"query"}}"##, nick)]);
        }
        // A nick that merely contains "status" is a normal query.
        let i = app.buf_index("n1", "status2", None);
        app.switch_to(i);
        ensure_history(&mut app, &tx);
        assert!(!drain(&mut rx)[0].contains("status_view"));
    }

    fn scroll_to_top(app: &mut App) { let c = app.current; app.buffers[c].scroll = usize::MAX / 2; }

    #[test]
    fn paging_sends_the_exact_id_cursor_of_the_oldest_second() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let mut app = app_with_net();
        ensure_history(&mut app, &tx);
        drain(&mut rx);
        page(&mut app, &[(41, 100, "a", "x"), (40, 100, "a", "y"), (42, 100, "b", "z"), (50, 101, "a", "new")]);
        scroll_to_top(&mut app);
        maybe_page_history(&mut app, &tx);
        assert_eq!(drain(&mut rx), vec![r##"{"type":"get_logs","conn_id":"n1","target":"#t","limit":200,"before":100,"before_id":40}"##]);
        // An id-less oldest second (pre-v0.3.0 history) keeps the whole-second form.
        let mut app = app_with_net();
        ensure_history(&mut app, &tx);
        drain(&mut rx);
        page(&mut app, &[(0, 90, "a", "old"), (51, 91, "a", "newer")]);
        scroll_to_top(&mut app);
        maybe_page_history(&mut app, &tx);
        assert_eq!(drain(&mut rx), vec![r##"{"type":"get_logs","conn_id":"n1","target":"#t","limit":200,"before":90}"##]);
        // A status query pages with both fields.
        let i = app.buf_index("n1", "Status", None);
        app.switch_to(i);
        ensure_history(&mut app, &tx);
        drain(&mut rx);
        let v = serde_json::json!({"type": "log_lines", "conn_id": "n1", "target": "Status", "lines": [
            {"id": 7, "ts": 70, "from": "Status", "text": "dm", "kind": "privmsg"}]});
        handle_event(&mut app, serde_json::from_value(v).unwrap());
        maybe_page_history(&mut app, &tx);
        assert_eq!(drain(&mut rx), vec![r##"{"type":"get_logs","conn_id":"n1","target":"Status","limit":200,"before":70,"before_id":7,"status_view":"query"}"##]);
    }

    #[test]
    fn status_query_history_keeps_only_that_users_conversation_in_any_case() {
        // What an OLD server (no status_view) returns for a DM with "Status": the
        // whole merged status log, incl. other users' AWAY lines and the MOTD.
        let mut app = app_with_net();
        let v = serde_json::json!({"type": "log_lines", "conn_id": "n1", "target": "Status", "lines": [
            {"id": 1, "ts": 1, "from": "*", "text": "- motd -", "kind": "notice"},
            {"id": 2, "ts": 2, "from": "awayer", "text": "awayer is away: gone fishing", "kind": "away"},
            {"id": 3, "ts": 3, "from": "awayer", "text": "awayer is back", "kind": "back"},
            {"id": 4, "ts": 4, "from": "quitter", "text": "quitter has quit", "kind": "quit"},
            {"id": 5, "ts": 5, "from": "Status", "text": "hi from Status", "kind": "privmsg"},
            {"id": 6, "ts": 6, "from": "me", "text": "my reply", "kind": "privmsg"},
            {"id": 7, "ts": 7, "from": "Status", "text": "waves", "kind": "action"},
            {"id": 8, "ts": 8, "from": "Status", "text": "a notice", "kind": "notice"},
            {"id": 9, "ts": 9, "from": "mallory", "text": "not theirs", "kind": "notice"},
            {"id": 10, "ts": 10, "from": "Status", "text": "no kind field"}]});
        handle_event(&mut app, serde_json::from_value(v).unwrap());
        assert_eq!(texts(&app, "n1", "Status"), vec!["hi from Status", "my reply", "waves", "a notice", "no kind field"]);
        // Other targets are untouched by the filter.
        let v = serde_json::json!({"type": "log_lines", "conn_id": "n1", "target": "#t", "lines": [
            {"id": 11, "ts": 11, "from": "awayer", "text": "chan line", "kind": "away"}]});
        handle_event(&mut app, serde_json::from_value(v).unwrap());
        assert_eq!(texts(&app, "n1", "#t"), vec!["chan line"]);
    }

    fn state_with_keys(app: &mut App, connected: bool, keys: serde_json::Value) {
        state_with_keys_cm(app, connected, keys, Some("rfc1459"));
    }
    fn state_with_keys_cm(app: &mut App, connected: bool, keys: serde_json::Value, cm: Option<&str>) {
        let mut net = serde_json::json!({"config": {"id": "n1", "label": "Net", "channel_keys": keys},
            "connected": connected, "nick": "me", "channels": [{"name": "#t", "topic": "", "names": ["@me"]}, {"name": "#Key[X]", "topic": "", "names": ["@me"]}]});
        if let Some(cm) = cm { net["casemapping"] = serde_json::json!(cm); }
        let v = serde_json::json!({"type": "state", "vault_unlocked": true, "networks": [net]});
        handle_event(app, serde_json::from_value(v).unwrap());
    }

    fn cycled(app: &mut App) -> Vec<String> {
        app.outbox.drain(..).map(|m| serde_json::to_string(&m).unwrap()).collect()
    }

    /// r4 (codex P2 tui/src/main.rs:615, agy P2 HIGH, w3-ops V3O-2): which saved key /cycle
    /// sends follows the network's CASEMAPPING — never another channel's key.
    #[test]
    fn cycle_key_lookup_follows_the_network_casemapping() {
        let mut app = app_with_net();
        state_with_keys_cm(&mut app, true, serde_json::json!({}), Some("ascii"));
        let k = app.find_buf("n1", "#Key[X]").unwrap();
        app.switch_to(k);
        // ascii: #key{x}'s key belongs to a different channel.
        run(&mut app, "/cycle");
        state_with_keys_cm(&mut app, true, serde_json::json!({"#key{x}": "other"}), Some("ascii"));
        assert_eq!(cycled(&mut app)[1], r##"{"type":"join_channel","conn_id":"n1","channel":"#Key[X]","key":null}"##);
        // ...while the exact (lowercased) spelling is still found.
        run(&mut app, "/cycle");
        state_with_keys_cm(&mut app, true, serde_json::json!({"#key[x]": "mine", "#key{x}": "other"}), Some("ascii"));
        assert_eq!(cycled(&mut app)[1], r##"{"type":"join_channel","conn_id":"n1","channel":"#Key[X]","key":"mine"}"##);
        // rfc1459: the folded spelling is the same channel.
        run(&mut app, "/cycle");
        state_with_keys_cm(&mut app, true, serde_json::json!({"#key{x}": "k2"}), Some("rfc1459"));
        assert_eq!(cycled(&mut app)[1], r##"{"type":"join_channel","conn_id":"n1","channel":"#Key[X]","key":"k2"}"##);
        // Unknown (an older server, no 005 seen): refused with a reason, nothing sent.
        let mut old = app_with_net();
        state_with_keys_cm(&mut old, true, serde_json::json!({}), None);
        let k = old.find_buf("n1", "#Key[X]").unwrap();
        old.switch_to(k);
        run(&mut old, "/cycle");
        state_with_keys_cm(&mut old, true, serde_json::json!({"#key{x}": "k2"}), None);
        assert!(old.outbox.is_empty());
        assert!(old.status.contains("case mapping is unknown"), "{}", old.status);
        // ...but a 005 line seen live tells it.
        handle_event(&mut old, ev(r##"{"type":"irc_message","conn_id":"n1","from":"irc.example.net","target":"status","text":"CHANTYPES=# CASEMAPPING=ascii are supported by this server","ts":1,"kind":"Notice","msg_id":0}"##));
        assert_eq!(old.casemap.get("n1"), Some(&CaseMap::Ascii));
        run(&mut old, "/cycle");
        state_with_keys_cm(&mut old, true, serde_json::json!({"#key{x}": "k2"}), None);
        assert_eq!(cycled(&mut old)[1], r##"{"type":"join_channel","conn_id":"n1","channel":"#Key[X]","key":null}"##);
        // A user's message can't set it.
        let mut u = app_with_net();
        handle_event(&mut u, ev(r##"{"type":"irc_message","conn_id":"n1","from":"bob","target":"status","text":"CASEMAPPING=ascii","ts":1,"kind":"Privmsg","msg_id":0}"##));
        assert!(u.casemap.get("n1").is_none());
        // strict-rfc1459: [ ] fold, ~ ^ do not.
        let keys = std::collections::HashMap::from([("#a^".to_string(), "caret".to_string()), ("#b{c}".to_string(), "brace".to_string())]);
        assert_eq!(saved_channel_key(&keys, "#a~", Some(CaseMap::StrictRfc1459)), Ok(None));
        assert_eq!(saved_channel_key(&keys, "#B[C]", Some(CaseMap::StrictRfc1459)), Ok(Some("brace")));
        assert_eq!(saved_channel_key(&keys, "#a~", Some(CaseMap::Rfc1459)), Ok(Some("caret")));
        assert_eq!(saved_channel_key(&keys, "#a~", None), Err("#a^".to_string()));
    }

    /// r4 (agy P2 tui/src/main.rs:708): a State snapshot does not close a window whose
    /// channel the server lists under another RFC1459 spelling, nor one whose /join the
    /// server has not confirmed yet; it still closes a channel parted elsewhere.
    #[test]
    fn state_prune_spares_folded_names_and_pending_joins() {
        let mut app = app_with_net();
        // A /join in flight; a State (any reason) arrives before the server's JOIN.
        run(&mut app, "/join #new");
        handle_event(&mut app, ev(r##"{"type":"state","vault_unlocked":true,"networks":[{"config":{"id":"n1","label":"Net"},"connected":true,"nick":"me","channels":[{"name":"#t","topic":"","names":["@me"]}]}]}"##));
        assert!(app.find_buf("n1", "#new").is_some(), "the fresh /join window survives");
        assert_eq!(app.buffers[app.current].target, "#new", "and stays the active one");
        // The window was opened as #chan[1]; the server confirms and lists #chan{1}.
        run(&mut app, "/join #chan[1]");
        handle_event(&mut app, ev(r##"{"type":"irc_join_ex","conn_id":"n1","nick":"me","channel":"#chan{1}","account":"","realname":"","ts":3}"##));
        assert!(app.find_buf("n1", "#chan{1}").is_some());
        assert_eq!(targets(&app).iter().filter(|t| wide_fold(t) == "#chan{1}").count(), 1, "one window, server spelling: {:?}", targets(&app));
        handle_event(&mut app, ev(r##"{"type":"state","vault_unlocked":true,"networks":[{"config":{"id":"n1","label":"Net"},"connected":true,"nick":"me","channels":[{"name":"#t","topic":"","names":["@me"]},{"name":"#CHAN{1}","topic":"","names":["@me"]},{"name":"#new","topic":"","names":["@me"]}]}]}"##));
        assert!(app.find_buf("n1", "#chan{1}").is_some(), "a case/fold variant in the State is the same channel");
        // An expired /join that never happened, and a channel parted from another client, go.
        app.pending_joins.iter_mut().for_each(|p| p.asked -= JOIN_GRACE + Duration::from_secs(1));
        run(&mut app, "/join #never");
        app.pending_joins.iter_mut().filter(|p| p.channel == "#never").for_each(|p| p.asked -= JOIN_GRACE + Duration::from_secs(1));
        handle_event(&mut app, ev(r##"{"type":"state","vault_unlocked":true,"networks":[{"config":{"id":"n1","label":"Net"},"connected":true,"nick":"me","channels":[{"name":"#t","topic":"","names":["@me"]}]}]}"##));
        assert!(app.find_buf("n1", "#never").is_none());
        assert!(app.find_buf("n1", "#new").is_none());
        assert!(app.find_buf("n1", "#chan{1}").is_none());
        assert!(app.find_buf("n1", "#t").is_some());
    }

    #[test]
    fn cycle_rejoins_with_the_key_the_server_holds_now() {
        let mut app = app_with_net();
        // The State we already have knows no key (a +k set after we joined is
        // never pushed). /cycle asks for a fresh one and sends nothing else yet.
        assert_eq!(run(&mut app, "/cycle"), vec![r##"{"type":"get_state"}"##]);
        assert!(app.outbox.is_empty());
        state_with_keys(&mut app, true, serde_json::json!({"#t": "sekrit"}));
        let out: Vec<String> = app.outbox.drain(..).map(|m| serde_json::to_string(&m).unwrap()).collect();
        assert_eq!(out, vec![
            r##"{"type":"part_channel","conn_id":"n1","channel":"#t"}"##.to_string(),
            r##"{"type":"join_channel","conn_id":"n1","channel":"#t","key":"sekrit"}"##.to_string()]);
        assert!(app.pending_cycles.is_empty());
        // A later State does not cycle again.
        state_with_keys(&mut app, true, serde_json::json!({"#t": "sekrit"}));
        assert!(app.outbox.is_empty());
        // A keyless channel rejoins without a key, as before; a named channel gets '#'.
        assert_eq!(run(&mut app, "/cycle t"), vec![r##"{"type":"get_state"}"##]);
        state_with_keys(&mut app, true, serde_json::json!({}));
        let out: Vec<String> = app.outbox.drain(..).map(|m| serde_json::to_string(&m).unwrap()).collect();
        assert_eq!(out[1], r##"{"type":"join_channel","conn_id":"n1","channel":"#t","key":null}"##);
        // The key stored under an RFC1459 fold of the name (the slot PartChannel deletes).
        let k = app.find_buf("n1", "#Key[X]").unwrap();
        app.switch_to(k);
        run(&mut app, "/cycle");
        run(&mut app, "/cycle");   // a repeat while waiting is one cycle, not two
        state_with_keys(&mut app, true, serde_json::json!({"#key{x}": "k2"}));
        let out: Vec<String> = app.outbox.drain(..).map(|m| serde_json::to_string(&m).unwrap()).collect();
        assert_eq!(out, vec![
            r##"{"type":"part_channel","conn_id":"n1","channel":"#Key[X]"}"##.to_string(),
            r##"{"type":"join_channel","conn_id":"n1","channel":"#Key[X]","key":"k2"}"##.to_string()]);
    }

    #[test]
    fn cycle_refuses_when_it_would_lose_the_channel_or_its_key() {
        let mut app = app_with_net();
        // Locked vault: the key is still an encrypted blob.
        run(&mut app, "/cycle");
        let blob = format!("enc:{}", "A".repeat(40));
        state_with_keys(&mut app, true, serde_json::json!({"#t": blob}));
        assert!(app.outbox.is_empty());
        assert!(app.status.contains("unlock the vault"), "{}", app.status);
        // A real key that only starts with "enc:" is a key.
        run(&mut app, "/cycle");
        state_with_keys(&mut app, true, serde_json::json!({"#t": "enc:hunter2"}));
        assert_eq!(app.outbox.len(), 2);
        app.outbox.clear();
        // Not connected: JoinChannel would be a no-op while PART drops auto-join.
        run(&mut app, "/cycle");
        state_with_keys(&mut app, false, serde_json::json!({}));
        assert!(app.outbox.is_empty());
        assert!(app.status.contains("not connected"), "{}", app.status);
        // A State that never came: the request expires instead of firing later.
        run(&mut app, "/cycle");
        app.pending_cycles[0].asked -= CYCLE_WAIT + Duration::from_secs(1);
        expire_pending_cycles(&mut app);
        assert!(app.pending_cycles.is_empty());
        state_with_keys(&mut app, true, serde_json::json!({}));
        assert!(app.outbox.is_empty());
        // Not in a channel.
        let s = app.find_buf("n1", "").unwrap();
        app.switch_to(s);
        assert!(run(&mut app, "/cycle").is_empty());
        let d = app.buf_index("n1", "bob", None);
        app.switch_to(d);
        assert!(run(&mut app, "/cycle").is_empty());
        assert_eq!(app.status, "/cycle works in a channel");
    }

    #[test]
    fn mode_in_the_network_buffer_never_sends_an_empty_target() {
        let mut app = app_with_net();
        let s = app.find_buf("n1", "").unwrap();
        app.switch_to(s);
        assert_eq!(run(&mut app, "/mode +i"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE me +i"}"##]);
        assert_eq!(run(&mut app, "/mode -w"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE me -w"}"##]);
        assert_eq!(run(&mut app, "/mode"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE me"}"##]);
        assert_eq!(run(&mut app, "/mode bob"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE bob"}"##]);
        assert_eq!(run(&mut app, "/mode #x +m"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #x +m"}"##]);
        // No nick known yet for that network: refuse instead of guessing.
        app.nicks.insert("n1".into(), String::new());
        assert!(run(&mut app, "/mode +i").is_empty());
        assert_eq!(app.status, "usage: /mode <nick|#channel> [modes]");
        // In a channel, unchanged.
        app.nicks.insert("n1".into(), "me".into());
        let c = app.find_buf("n1", "#t").unwrap();
        app.switch_to(c);
        assert_eq!(run(&mut app, "/mode +m"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #t +m"}"##]);
        assert_eq!(run(&mut app, "/mode"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #t"}"##]);
        assert_eq!(run(&mut app, "/mode #x +o bob"), vec![r##"{"type":"send","conn_id":"n1","raw":"MODE #x +o bob"}"##]);
    }

    #[test]
    fn the_network_buffer_never_sends_text_or_actions_to_a_nick_called_status() {
        // The web client's status window used target "status", so typing there
        // messaged whoever holds that nick. Here the network buffer's target is
        // "", and nothing typed in it may reach anyone implicitly.
        let mut app = app_with_net();
        let s = app.find_buf("n1", "").unwrap();
        app.switch_to(s);
        assert_eq!(app.buffers[s].target, "");
        for line in ["hello there", "/me waves", "/say hi", "/slap bob", "/describe x"] {
            let sent = run(&mut app, line);
            assert!(sent.iter().all(|f| !f.contains("PRIVMSG") && !f.contains("NOTICE")), "{} sent {:?}", line, sent);
        }
        assert!(run(&mut app, "hello").is_empty());
        assert_eq!(app.status, "this is a server buffer — /join a channel or /msg someone");
        // Explicit commands still work from there.
        assert_eq!(run(&mut app, "/msg status hi"), vec![r##"{"type":"send","conn_id":"n1","raw":"PRIVMSG status :hi"}"##]);
        let s = app.find_buf("n1", "").unwrap();
        app.switch_to(s);
        assert_eq!(run(&mut app, "/notice status hey"), vec![r##"{"type":"send","conn_id":"n1","raw":"NOTICE status :hey"}"##]);
        assert_eq!(run(&mut app, "/raw PRIVMSG status :raw"), vec![r##"{"type":"send","conn_id":"n1","raw":"PRIVMSG status :raw"}"##]);
        // A query buffer WITH the user "status" is a real DM: text goes to that user, as for any nick.
        let q = app.find_buf("n1", "status").unwrap();
        app.switch_to(q);
        assert_eq!(run(&mut app, "dm text"), vec![r##"{"type":"send","conn_id":"n1","raw":"PRIVMSG status :dm text"}"##]);
    }

    /// r4 (w3-irc N2/N3): irc-core's own status notices (a prefix-less NOTICE: from "*",
    /// target "status") are shown in the network buffer — e.g. the EXTERNAL→PLAIN switch.
    #[test]
    fn daemon_status_notices_land_in_the_network_buffer() {
        let mut app = app_with_net();
        handle_event(&mut app, ev(r##"{"type":"irc_message","conn_id":"n1","from":"*","target":"status","text":"CryptIRC: SASL EXTERNAL (client certificate) failed 3 times — trying SASL PLAIN next","ts":5,"kind":"Notice","msg_id":7}"##));
        assert!(texts(&app, "n1", "").iter().any(|t| t.contains("trying SASL PLAIN next")), "{:?}", texts(&app, "n1", ""));
    }

    #[test]
    fn multiline_bot_result_becomes_rows_without_raw_newlines() {
        let mut app = App::new("u".into());
        let i = app.buf_index("n1", "#t", Some("#t"));
        app.switch_to(i);
        handle_event(&mut app, ServerEvent::BotResult { bot: "ai".into(), text: "line one\r\nline two\n\nline three".into() });
        let texts: Vec<&str> = app.buffers[i].lines.iter().map(|l| l.text.as_str()).collect();
        assert_eq!(texts, vec!["🤖 ai line one", "   line two", "   line three"]);
    }
}
