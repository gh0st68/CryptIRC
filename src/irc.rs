//! irc.rs — IRC connection handler
//!
//! Fixes this pass:
//!   B1/B2 — removed unused imports (AtomicBool, Ordering, SaslConfig)
//!   S3    — names_buf bounded (max 512 channels × 4096 entries each)
//!   S4    — nick collision aborts after MAX_NICK_RETRIES attempts
//!   L1    — auto_reconnect flag respected in outer connect() loop
//!   L3    — stale IrcConnection removed from map on run_loop exit

use anyhow::Result;
use std::{collections::{HashMap, HashSet}, sync::Arc};
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
    time::{sleep, timeout, Duration, Instant},
};
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::{certs::CertStore, network_config_lock, strip_crlf, AppState, MessageKind, NetworkConfig, ServerEvent};

// ─── Constants ────────────────────────────────────────────────────────────────

const PING_INTERVAL:     Duration = Duration::from_secs(30);
const PONG_TIMEOUT:      Duration = Duration::from_secs(90);
const RECONNECT_BASE:    Duration = Duration::from_secs(5);
const RECONNECT_MAX:     Duration = Duration::from_secs(300);
const READ_TIMEOUT:      Duration = Duration::from_secs(120);
// How often to poll WHO per joined channel to refresh away (G/H) state. ircd-ratbox
// 3.0.10 (and other old IRCds) don't advertise the IRCv3 `away-notify` cap, so the
// only server-independent way to gray out away nicks is to poll WHO and read the G flag.
const WHO_INTERVAL:      Duration = Duration::from_secs(45);
/// #27: cap the number of WHO commands the away-poll fan-out emits per WHO_INTERVAL
/// tick. Iterating every joined channel (up to MAX_CHANNELS_PER_CONN=256) and sending
/// WHO for each back-to-back is a burst most IRCds flood-kill (excess-flood/SendQ); a
/// hostile server can inflate the channel count with forged self-JOINs to maximise it,
/// and the resulting kill→reconnect→rejoin→WHO-storm becomes a self-sustaining loop.
/// Emit at most this many WHO per tick and round-robin a cursor across ticks so every
/// channel is still polled, just spread over time.
const WHO_MAX_PER_TICK: usize = 8;
/// S4: maximum number of times we'll retry a nick before aborting registration
const MAX_NICK_RETRIES:  u32 = 5;
/// S3: maximum total channels in names_buf
const NAMES_BUF_MAX_CHANNELS: usize = 512;
/// S3: maximum entries per channel in names_buf
const NAMES_BUF_MAX_PER_CHAN: usize = 4096;
/// S7: maximum IRC line length (prevent memory exhaustion from rogue server)
const MAX_IRC_LINE_LEN: usize = 8192;
/// #43: cap the number of channels a single connection will track. A malicious
/// server can forge unlimited `:<ournick> JOIN #chanN` lines to grow c.channels,
/// create per-channel log dirs, and amplify outbound NAMES requests without bound.
const MAX_CHANNELS_PER_CONN: usize = 256;
/// F5: hard cap on persisted per-channel auto-rejoin keys. A malicious server can't be
/// allowed to grow the on-disk channel_keys map without bound (each add re-encrypts +
/// rewrites the whole config). Sized well above MAX_CHANNELS_PER_CONN so real users who
/// cycle through many keyed channels over a session keep working; only pathological
/// growth is refused.
const MAX_CHANNEL_KEYS: usize = 1024;
/// #45: minimum interval between automatic CTCP replies (per connection). Prevents
/// an attacker from reflecting a NOTICE flood off the victim via rapid CTCP VERSION
/// requests, which most IRCds penalize with SendQ/excess-flood kills.
const CTCP_REPLY_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// #31: inbound line rate limit (token bucket, per connection). Per-line LENGTH is
/// already bounded, but the RATE of accepted lines was not — READ_TIMEOUT only fires
/// on 120s of silence, so a server streaming maximal-length PRIVMSG/NOTICE/JOIN/… with
/// no idle gap drives an unbounded AES-GCM encrypt + fsync'd `.seq` write + append + WS
/// broadcast per line on the read loop's critical path (disk/IOPS/CPU exhaustion). Pace
/// accepted lines to a sustained ceiling (refill) with a generous burst so ordinary
/// traffic — including ZNC/bouncer playback bursts — is never throttled, while a flood
/// is capped and back-pressured onto the TCP socket. Set well above any legitimate
/// sustained inbound rate; tune here if a very busy aggregate ever nears the ceiling.
const INBOUND_RATE_BURST:  f64 = 1024.0;
/// tokens (accepted lines) refilled per second
const INBOUND_RATE_REFILL: f64 = 64.0;

// ─── Safe-truncation / slice helpers ───────────────────────────────────────────

/// #19: char-boundary-safe truncation. Byte-slicing a String (`&s[..n]`) panics
/// when byte `n` lands in the middle of a multibyte UTF-8 sequence; an ordinary
/// IRC peer can trivially trigger this with a unicode NOTICE/nick. Take whole
/// chars instead so truncation can never split a code point.
fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// #93: replace `token` (an ASCII `$me`/`$nick`) with `val` only when it occurs as a
/// whole token — i.e. bounded by a non-word character (or string edge) on both sides —
/// so a literal `$me`/`$nick` embedded in a larger word (e.g. a NickServ password) is
/// left untouched instead of being silently rewritten to the nick.
fn expand_perform_token(s: &str, token: &str, val: &str) -> String {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i..].starts_with(token) {
            let before_ok = i == 0 || !is_word(bytes[i - 1]);
            let after = i + token.len();
            let after_ok = after >= s.len() || !is_word(bytes[after]);
            if before_ok && after_ok {
                out.push_str(val);
                i = after;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// #19: join the tail of params starting at index `n` without panicking when
/// there are fewer than `n` params. `parse_irc` can legitimately return 0 params,
/// so any `p.params[N..]` is a panic waiting to happen on malformed server input.
fn params_from(params: &[String], n: usize) -> String {
    params.get(n..).map(|s| s.join(" ")).unwrap_or_default()
}

/// RFC1459 case-fold for channel/nick comparison. EFnet (ircd-ratbox) and most
/// legacy IRCds advertise CASEMAPPING=rfc1459, in which `{}|^` are the lowercase
/// forms of `[]\~`. Channel names are case-INSENSITIVE on the wire, but a server
/// — or, very commonly, a ZNC bouncer sitting between us and the network — can
/// echo a channel in a different case than the JOIN we stored: ZNC replays the
/// self-JOIN using its own configured channel case while WHO 352/315 replies pass
/// through verbatim from the real server in the server's canonical case. When
/// those two cases disagree (only possible for names with letters, e.g. `#IRC30`),
/// a case-SENSITIVE who_pending lookup misses, so the automatic away-poll's WHO
/// reply gets dumped into the user's view instead of being consumed silently —
/// the "one channel spamming /who non-stop" symptom. Fold both sides to this
/// canonical key before any HashSet/HashMap match so case never breaks matching.
fn irc_lower(s: &str) -> String {
    s.chars().map(|c| match c {
        'A'..='Z' => (c as u8 + 32) as char,
        '['  => '{',
        ']'  => '}',
        '\\' => '|',
        '~'  => '^',
        other => other,
    }).collect()
}

/// #S7: outcome of a single capped line read. See `read_capped_line`.
enum CappedLine {
    /// A complete (or final unterminated) line whose content fit within the cap.
    /// The terminating `\n` is removed; a trailing `\r`, if any, is left for the
    /// caller's existing `trim_end_matches` to strip (identical to the old path).
    Line(String),
    /// The line exceeded `MAX_IRC_LINE_LEN` and was drained to the next newline
    /// without ever buffering past the cap. Caller skips it (warn + continue),
    /// matching the previous post-buffer length check.
    Oversized,
    /// Clean end of stream with no pending bytes (server closed the connection).
    Eof,
}

/// #S7: read one IRC line with a hard memory bound.
///
/// The previous implementation used `BufReader::lines()` / `next_line()`, which
/// allocate the ENTIRE line before any size check runs. A hostile server that
/// streams bytes with no `\n` would grow that buffer without limit and OOM the
/// shared process; the `MAX_IRC_LINE_LEN` guard only fired *after* the unbounded
/// allocation had already happened.
///
/// This helper instead pulls from the `BufReader`'s internal buffer via
/// `fill_buf()`/`consume()` and copies at most `MAX_IRC_LINE_LEN + 2` content
/// bytes into an owned buffer. Once that ceiling is hit it keeps consuming (so the
/// connection stays in sync) but stops growing the buffer, then reports
/// `Oversized`. The `+2` headroom reproduces the old "trim `\r\n`, then compare
/// length" semantics exactly, so a maximal legitimate line is still accepted.
///
/// Behaviour parity with the old `next_line()` path:
///   (a) EOF with no pending bytes → `Eof` (caller returns `Ok(())`).
///   (e) LENIENT UTF-8: invalid bytes are decoded lossily (→ U+FFFD) so a single
///       non-UTF-8 byte in a server line (common in MOTD/topic/realname) can never
///       drop the connection. (The old strict `from_utf8` broke HybridIRC entirely.)
async fn read_capped_line<R>(reader: &mut R) -> std::io::Result<CappedLine>
where
    R: AsyncBufRead + Unpin,
{
    // Ceiling on buffered content bytes (everything before the terminating `\n`).
    // `+2` so a line of exactly MAX_IRC_LINE_LEN content followed by `\r\n` — or a
    // trailing `\r` that trimming would remove — is still accepted, matching the
    // old trim-then-compare check.
    const CONTENT_CEIL: usize = MAX_IRC_LINE_LEN + 2;

    let mut buf: Vec<u8> = Vec::new();
    let mut oversized = false;

    loop {
        // How many bytes to consume from the BufReader after inspecting them, and
        // whether this chunk contained the line-terminating newline. Computed inside
        // a scope so the `&[u8]` borrow from `fill_buf()` ends before `consume()`.
        let (consume_amt, found_nl) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                // EOF. If we have pending content it's a final unterminated line
                // (parity with `Lines`, which yields a last line without `\n`);
                // otherwise it's a clean close.
                if buf.is_empty() && !oversized {
                    return Ok(CappedLine::Eof);
                }
                break;
            }
            match available.iter().position(|&b| b == b'\n') {
                Some(idx) => {
                    // `idx` bytes are line content; +1 to also consume the `\n`.
                    if !oversized {
                        let take = idx.min(CONTENT_CEIL - buf.len());
                        buf.extend_from_slice(&available[..take]);
                        if take < idx {
                            // The newline is within reach but content already exceeds
                            // the cap — discard this line.
                            oversized = true;
                        }
                    }
                    (idx + 1, true)
                }
                None => {
                    // No newline yet: copy what fits, then keep draining without
                    // growing the buffer once the ceiling is reached.
                    if !oversized {
                        let room = CONTENT_CEIL - buf.len();
                        let take = available.len().min(room);
                        buf.extend_from_slice(&available[..take]);
                        if take < available.len() {
                            oversized = true;
                        }
                    }
                    (available.len(), false)
                }
            }
        };
        reader.consume(consume_amt);
        if found_nl {
            break;
        }
    }

    if oversized {
        return Ok(CappedLine::Oversized);
    }

    // `buf` holds the line content only — the terminating `\n` is consumed but
    // never copied in, so there is nothing more to strip here. Any trailing `\r`
    // is left for the caller's existing `trim_end_matches` (parity with the old
    // path, which re-trimmed too).
    //
    // Decode LENIENTLY (lossy): real IRC servers legitimately send non-UTF-8 bytes
    // (Latin-1/CP1252 in MOTD art, topics, realnames). Strict `from_utf8` here
    // returned InvalidData on a single bad byte, which propagated as a fatal
    // "Connection error" and dropped the WHOLE connection — so a server whose
    // post-SASL burst contains one such byte (HybridIRC's MOTD has one at offset
    // 248) could NEVER finish registration: it looped SASL-success → utf-8 error →
    // 300s reconnect forever (448+ times observed). `from_utf8_lossy` maps invalid
    // bytes to U+FFFD so the line still parses and the connection survives; the
    // downstream CR/LF/NUL stripping and IRC tokenizer are unaffected.
    let line = String::from_utf8_lossy(&buf).into_owned();
    Ok(CappedLine::Line(line))
}

/// #46: RAII guard that removes a connection's shared-state entries on ANY exit
/// from `run_loop`, including a panic unwind. Previously the only cleanup lived in
/// `connect()` *after* the `do_connect(...).await`, so a panic in the parse/dispatch
/// loop (see #19) unwound straight past it, leaving a stale `connections` /
/// `conn_owners` pair, a live "connected" UI state, and no auto-reconnect. Holding
/// cheap Arc clones of the maps lets us reclaim the entries no matter how the loop
/// terminates.
///
/// NOTE: this guard intentionally does NOT touch `connect_tasks`. That handle tracks
/// the `connect()` task, which outlives a single `run_loop` call (it spans every
/// reconnect), and `abort_connect_task` relies on it being present to deterministically
/// kill a reconnecting task. Removing it here would open a race window during the
/// reconnect backoff. `connect_tasks` is reclaimed on `connect()`'s terminal returns.
struct ConnCleanup {
    conn_id:     String,
    conn:        Arc<Mutex<IrcConnection>>,
    connections: Arc<dashmap::DashMap<String, Arc<Mutex<IrcConnection>>>>,
    conn_owners: Arc<dashmap::DashMap<String, String>>,
}

impl Drop for ConnCleanup {
    fn drop(&mut self) {
        // Identity-checked removal: only reclaim the map entries if they still
        // point at THIS connection. A fast Disconnect/RemoveNetwork+Connect (or a
        // reconnect) can replace the entry with a brand-new task's connection before
        // this old task's Drop runs; an unconditional rem() would then delete the
        // live successor's freshly-inserted entry. `conn_owners` is keyed by the same
        // conn_id and inserted/removed in lockstep with `connections`, so gate it on
        // the identical Arc-identity test to avoid orphaning the successor's owner.
        let removed = self
            .connections
            .remove_if(&self.conn_id, |_, v| Arc::ptr_eq(v, &self.conn))
            .is_some();
        if removed {
            self.conn_owners.remove(&self.conn_id);
        }
    }
}

// ─── Public types ─────────────────────────────────────────────────────────────

pub struct ChannelState {
    /// #92: display name as the server first announced it. `IrcConnection.channels` is
    /// keyed by `irc_lower(name)` so a PART/KICK/MODE echoed in a different case than the
    /// JOIN still resolves (previously a case mismatch left a stale channel that the WHO
    /// ticker kept polling — the "one channel spamming /who" symptom). This preserves the
    /// original casing for everything user-facing.
    pub name:  String,
    pub topic: String,
    pub names: Vec<String>,
    /// Last +k key we've learned for this channel (from MODE/324), used purely as an
    /// in-memory dedup so a server that streams identical 324/MODE echoes can't force a
    /// disk read+decrypt (get_network_config) + re-encrypt+rewrite (save_network) per line.
    /// `None` = key unknown/keyless; we only touch persist_channel_key when this changes.
    pub key:   Option<String>,
}

pub struct IrcConnection {
    pub conn_id:   String,
    pub nick:      String,
    pub connected: bool,
    pub lag_ms:    Option<u64>,
    pub channels:  HashMap<String, ChannelState>,
    pub writer:    Box<dyn AsyncWrite + Send + Unpin>,
    pub message_tags: bool,
    pub self_userhost: String,
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

/// Extract the +k key from a 324-style "<+modes> <param…>" string (the currently-set
/// modes, all additive). Only param-taking modes consume a param, in letter order;
/// returns the key if present and not masked ('*'). Best-effort: lets us learn a keyed
/// channel's key on join so auto-rejoin can re-enter it even when we didn't /join with it.
fn channel_key_from_modes(modes: &str) -> Option<String> {
    let mut it = modes.split_whitespace();
    let letters = it.next()?.trim_start_matches('+');
    for c in letters.chars() {
        match c {
            'k' => {
                let k = it.next()?;
                return if !k.is_empty() && k != "*" { Some(k.to_string()) } else { None };
            }
            // Other additive param-taking channel modes consume their param first so the
            // key lines up with the right token (ratbox: l limit, f forward, j throttle).
            'l' | 'j' | 'f' | 'L' | 'J' => { let _ = it.next(); }
            _ => {}
        }
    }
    None
}

/// Persist a learned channel key into the network config's channel_keys (under the
/// per-config lock, mirroring the JoinChannel/PartChannel writers) so auto-rejoin — and
/// a fresh connect after a full server restart — can re-enter a keyed channel whose +k
/// was set/changed AFTER we joined. key=Some(k) saves; key=None removes (-k). Only writes
/// when the value actually changes, so repeated 324s/MODE echoes don't churn the disk.
async fn persist_channel_key(state: &AppState, username: &str, conn_id: &str, channel: &str, key: Option<&str>) {
    let lc = channel.to_lowercase();
    let lock = network_config_lock(username, conn_id);
    let _guard = lock.lock().await;
    if let Some(mut cfg) = state.get_network_config(conn_id, username).await {
        let mut changed = false;
        match key {
            Some(k) if !k.is_empty() && k != "*" => {
                let is_new = !cfg.channel_keys.contains_key(&lc);
                // F5: refuse to grow the persisted map past the cap when this would add a
                // NEW entry; updating an existing channel's key stays allowed.
                if is_new && cfg.channel_keys.len() >= MAX_CHANNEL_KEYS {
                    // bounded — drop silently, mirrors the c.channels cap behavior
                } else if cfg.channel_keys.get(&lc).map(|s| s.as_str()) != Some(k) {
                    cfg.channel_keys.insert(lc, strip_crlf(k));
                    changed = true;
                }
            }
            _ => {
                if cfg.channel_keys.remove(&lc).is_some() { changed = true; }
            }
        }
        if changed { let _ = state.save_network(&cfg, username).await; }
    }
}

pub async fn connect(
    conn_id:  String,
    mut cfg:  NetworkConfig,
    username: String,
    state:    AppState,
) -> Result<()> {
    let mut delay   = RECONNECT_BASE;
    let mut attempt = 0u32;
    // SASL retry tracking — local to this connect() task. Not persisted to the
    // user's stored config; resets on successful registration or task restart.
    let mut sasl_failures = 0u32;
    let original_sasl_external = cfg.sasl_external;
    const MAX_SASL_RETRIES: u32 = 3;

    loop {
        attempt += 1;
        info!("[{}] Connect attempt {} → {}:{} (sasl_external={})", conn_id, attempt, cfg.server, cfg.port, cfg.sasl_external);
        state.send_to_user(&username, ServerEvent::Connecting {
            conn_id: conn_id.clone(),
            server:  cfg.server.clone(),
        });

        let result = do_connect(&conn_id, &cfg, &username, &state).await;

        // Map cleanup is owned by ConnCleanup::drop, which runs on EVERY run_loop exit
        // (return/error/cancel) and removes the entry with an identity check
        // (remove_if Arc::ptr_eq). Do NOT remove by conn_id here: this block is
        // synchronous and a fast Disconnect/Connect can reinsert a SUCCESSOR task's
        // entry before it runs, so an unconditional remove would delete the successor —
        // orphaning a live, uncontrollable "ghost" connection. (Supersedes the old L3
        // immediate-remove, which is redundant for this task's own entry and unsafe.)

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
                // Reset SASL retry state on a successful prior connection
                sasl_failures = 0;
                cfg.sasl_external = original_sasl_external;
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.starts_with("SASL_RETRY:") {
                    sasl_failures += 1;
                    if sasl_failures == 1 {
                        // First failure: explain the failure with actionable advice, and
                        // reset delay so the next attempt cycles DNS quickly (this helps
                        // on networks like TwistedNet where one leaf may have a stale
                        // cert mapping while another works).
                        let advice = if cfg.sasl_external {
                            "⚠ SASL EXTERNAL rejected by server. Your client certificate is not registered with this network. To fix: edit the network and set SASL to None, connect, identify with NickServ, then run /msg NickServ CERT ADD <fingerprint>. The cert fingerprint is in the 🔑 Cert panel. Retrying…"
                        } else {
                            "⚠ SASL authentication rejected. Check your SASL account/password. Retrying without SASL after a few more attempts…"
                        };
                        state.send_to_user(&username, ServerEvent::IrcMessage {
                            conn_id: conn_id.clone(), from: "*".into(), target: "status".into(),
                            text: advice.to_string(),
                            ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
                        });
                        info!("[{}] SASL failure 1/{}, fast retry for DNS cycling", conn_id, MAX_SASL_RETRIES);
                        delay = RECONNECT_BASE;
                    } else if sasl_failures >= MAX_SASL_RETRIES {
                        warn!("[{}] SASL failed {} times — disabling SASL for this session, will reconnect without it", conn_id, sasl_failures);
                        state.send_to_user(&username, ServerEvent::IrcMessage {
                            conn_id: conn_id.clone(), from: "*".into(), target: "status".into(),
                            text: format!("⚠ SASL failed {} times. Reconnecting without SASL — identify with NickServ manually if needed.", sasl_failures),
                            ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
                        });
                        cfg.sasl_external = false;
                        // Floor to 30s on final SASL failure so IP-level throttles
                        // (e.g. UnrealIRCd's "Too many unknown connections") clear
                        // before the no-SASL retry.
                        delay = delay.max(Duration::from_secs(30));
                    } else {
                        info!("[{}] SASL failure {}/{}, backing off", conn_id, sasl_failures, MAX_SASL_RETRIES);
                        // Subsequent failures: floor at 30s to avoid tripping server
                        // IP throttles when the failure is permanent (wrong cert,
                        // wrong password) rather than a flaky leaf server.
                        delay = delay.max(Duration::from_secs(30));
                    }
                }
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
                    Err(e) => {
                        warn!("[{}] Client cert load FAILED: {} — vault may be locked", conn_id, e);
                        if cfg.sasl_external {
                            state.send_to_user(username, ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                                text: format!("⚠ SASL EXTERNAL cert could not load ({}). Unlock your vault and reconnect.", e),
                                ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
                            });
                            return Err(anyhow::anyhow!("Client cert unavailable for SASL EXTERNAL — vault locked?"));
                        }
                        None
                    }
                }
            } else {
                warn!("[{}] Cert files NOT found for {}", conn_id, cert_id);
                if cfg.sasl_external {
                    state.send_to_user(username, ServerEvent::IrcMessage {
                        conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                        text: "⚠ SASL EXTERNAL cert not found. Generate a certificate in network settings.".into(),
                        ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
                    });
                    return Err(anyhow::anyhow!("Client cert not found for SASL EXTERNAL"));
                }
                None
            }
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
            // Load client cert + key from PEM. #48: route the cert_id through the
            // CertStore's shared sanitizer (no raw join), and don't .unwrap() — a
            // missing id is a graceful error, not a panic.
            let cert_id = cfg.client_cert_id.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Client cert id missing"))?;
            let dir = CertStore::new(&state.data_dir, state.crypto.clone()).cert_path_for(cert_id);
            let cert_pem = tokio::fs::read(dir.join("cert.pem")).await?;
            let key_enc = tokio::fs::read_to_string(dir.join("key.enc")).await?;
            let mut key_pem = state.crypto.decrypt(username, key_enc.trim()).await?;
            let x509 = openssl::x509::X509::from_pem(&cert_pem)?;
            let pkey = openssl::pkey::PKey::private_key_from_pem(&key_pem)?;
            // F26: scrub the decrypted plaintext ECDSA key PEM once PKey holds a copy
            // (mirrors certs.rs::load_identity). PKey owns its own key material now.
            key_pem.zeroize();
            ssl_builder.set_certificate(&x509)?;
            ssl_builder.set_private_key(&pkey)?;
            // Enable post-handshake auth for TLS 1.3 client certs
            unsafe { openssl_sys::SSL_CTX_set_post_handshake_auth(ssl_builder.as_ptr() as *mut _, 1); }
            let connector = ssl_builder.build();
            let tcp2 = TcpStream::connect(&addr).await?;
            tcp2.set_nodelay(true)?;
            let ssl = connector.configure()?.into_ssl(&cfg.server)?;
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
        self_userhost: String::new(),
    }));

    state.connections.insert(conn_id.to_string(), conn.clone());
    state.conn_owners.insert(conn_id.to_string(), username.to_string());

    // #46: ensure the connections/conn_owners entries are reclaimed on every exit
    // path — including a panic unwind through the dispatch loop — not just on the
    // clean `Err`/`Ok` returns handled by connect().
    let _cleanup = ConnCleanup {
        conn_id:     conn_id.to_string(),
        conn:        conn.clone(),
        connections: state.connections.clone(),
        conn_owners: state.conn_owners.clone(),
    };

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
                ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
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
    // #45: throttle automatic CTCP replies so an attacker can't reflect a NOTICE
    // flood off us (rapid CTCP VERSION → matching NOTICE stream → SendQ/excess-flood
    // kill). Per-connection token gate; first reply allowed immediately.
    let mut last_ctcp_reply: Option<Instant> = None;

    // Registration. EFnet (hybrid/ratbox lineage) doesn't speak modern IRCv3/SASL the
    // way newer networks do — when connecting there, skip CAP negotiation entirely so
    // NO capabilities (and no SASL) are requested. Detected by network label or server host.
    let efnet = cfg.label.to_lowercase().contains("efnet") || cfg.server.to_lowercase().contains("efnet");
    if efnet {
        info!("[{}] EFnet detected (label='{}' server='{}') — IRCv3 caps disabled, skipping CAP negotiation", conn_id, cfg.label, cfg.server);
    }
    {
        let mut c = conn.lock().await;
        if let Some(ref pass) = cfg.password {
            c.send_raw(&format!("PASS {}\r\n", strip_crlf(pass))).await?;
        }
        if !efnet {
            c.send_raw("CAP LS 302\r\n").await?;
            if use_sasl {
                sasl_state = SaslState::CapLsSent;
            }
        }
        c.send_raw(&format!("NICK {}\r\n", strip_crlf(&cfg.nick))).await?;
        c.send_raw(&format!("USER {} 0 * :{}\r\n", strip_crlf(&cfg.username), strip_crlf(&cfg.realname))).await?;
    }

    let mut reader     = BufReader::new(read_half);
    let mut registered = false;
    // S3: bounded names accumulation buffer
    let mut names_buf: HashMap<String, Vec<String>> = HashMap::with_capacity(32);
    let mut ping_ticker = tokio::time::interval(PING_INTERVAL);
    // Away-state polling (see WHO_INTERVAL). `who_pending` holds channels for which WE
    // issued an automatic WHO — their 352/315 replies are consumed silently for away
    // tracking instead of being dumped to the status buffer (a user-typed /who is not in
    // the set, so its output is still forwarded). `who_away` accumulates the away nicks
    // of the in-flight WHO, keyed by channel, flushed into a snapshot on 315 (end of WHO).
    let mut who_ticker = tokio::time::interval(WHO_INTERVAL);
    // Don't let a busy event loop (e.g. a long burst of inbound traffic through a
    // ZNC bouncer monopolising the read side) bank up missed WHO ticks and then
    // fire them all back-to-back — `interval`'s default Burst behaviour would turn
    // the 45s away-poll into a rapid WHO storm on catch-up. Skip missed ticks.
    who_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut who_pending: HashSet<String> = HashSet::new();
    let mut who_away: HashMap<String, Vec<String>> = HashMap::new();
    // #27: round-robin cursor into the joined-channel list for the paced WHO fan-out
    // (see WHO_MAX_PER_TICK). Persists across ticks so successive ticks poll different
    // channels; the tick handler clamps/wraps it when the channel set changes size.
    let mut who_rr_cursor: usize = 0;
    // #31: per-connection inbound token bucket (see INBOUND_RATE_*). Starts full so a
    // fresh connection's registration/backlog burst is never delayed.
    let mut inbound_tokens: f64 = INBOUND_RATE_BURST;
    let mut inbound_refill_at = Instant::now();

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

            // ── Away-state poll ───────────────────────────────────────────
            // Periodically WHO every joined channel to refresh the nick panel's
            // away (grayed-out) state on servers without away-notify.
            _ = who_ticker.tick() => {
                if registered {
                    // #92: iterate the display names (channels is keyed by irc_lower now).
                    let chans: Vec<String> = { conn.lock().await.channels.values().map(|ch| ch.name.clone()).collect() };
                    // #27: pace the WHO fan-out. Sending WHO for every joined channel (up to
                    // MAX_CHANNELS_PER_CONN=256) back-to-back on each 45s tick is a burst most
                    // IRCds penalise with an excess-flood/SendQ kill, and a hostile server can
                    // inflate the channel count via forged self-JOINs to maximise it — yielding
                    // a self-sustaining kill/reconnect loop. Emit at most WHO_MAX_PER_TICK per
                    // tick, advancing a round-robin cursor so every channel is still polled,
                    // just spread across successive ticks.
                    let n = chans.len();
                    if n > 0 {
                        if who_rr_cursor >= n { who_rr_cursor = 0; }
                        let take = n.min(WHO_MAX_PER_TICK);
                        for i in 0..take {
                            let ch = &chans[(who_rr_cursor + i) % n];
                            // Key who_pending by the case-folded name so the 352/315
                            // replies match even when the server/ZNC echoes the channel
                            // in a different case than the JOIN-echo we stored.
                            // #91: cap the pending set (it's already bounded by the per-conn
                            // channel cap, but keep the guard symmetric with the JOIN path).
                            let ck = irc_lower(ch);
                            if who_pending.len() < NAMES_BUF_MAX_CHANNELS || who_pending.contains(&ck) {
                                who_pending.insert(ck);
                            }
                            // A send failure here just means the connection is going down;
                            // the read side will surface the real error and reconnect.
                            // strip_crlf: channel keys originate from server-supplied JOIN names;
                            // a stored interior \r would otherwise be reflected into the WHO.
                            if conn.lock().await.send_raw(&format!("WHO {}\r\n", strip_crlf(ch))).await.is_err() { break; }
                        }
                        who_rr_cursor = (who_rr_cursor + take) % n;
                    }
                }
            }

            // ── Incoming line ──────────────────────────────────────────────
            res = timeout(READ_TIMEOUT, async {
                // #31: token-bucket rate limit BEFORE reading the next line. Placed ahead
                // of the read so a cancellation of this select! branch by the ping/who arms
                // loses no buffered data — nothing has been read or consumed yet. We only
                // ever wait for a single token, so the sleep is at most 1/INBOUND_RATE_REFILL
                // (~16ms) and can never approach READ_TIMEOUT; the ping heartbeat still fires
                // because this sleep is a select! branch polled alongside ping_ticker.
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
                    Err(_)                       => return Err(anyhow::anyhow!("Read timeout")),
                    Ok(Ok(CappedLine::Line(l)))  => l,
                    Ok(Ok(CappedLine::Eof))      => return Ok(()), // clean server close
                    // S7: an oversized line is drained to the next newline without
                    // growing the buffer past the cap, then skipped — identical
                    // observable result to the previous post-buffer length check.
                    Ok(Ok(CappedLine::Oversized)) => {
                        warn!("[{}] Dropping oversized IRC line (> {} bytes)", conn_id, MAX_IRC_LINE_LEN);
                        continue;
                    }
                    Ok(Err(e))                   => return Err(e.into()),
                };
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.is_empty() { continue; }
                // S7: enforce the exact post-trim length cutoff. `read_capped_line`
                // already bounds the allocation (it never buffers far past the cap),
                // but a line whose trimmed content lands just over MAX_IRC_LINE_LEN
                // must still be dropped here to match the original boundary exactly.
                if line.len() > MAX_IRC_LINE_LEN {
                    warn!("[{}] Dropping oversized IRC line ({} bytes)", conn_id, line.len());
                    continue;
                }

                let p  = parse_irc(&line);
                // Log raw lines only during the active SASL handshake (positive match
                // so SaslState::Failed/Done/Idle don't accidentally trigger log spam).
                let _in_sasl_handshake = matches!(sasl_state, SaslState::CapLsSent | SaslState::CapReqSent | SaslState::AuthenticateSent);
                let _is_sasl_resp = matches!(p.command.as_str(), "900" | "902" | "903" | "904" | "905" | "906" | "907" | "AUTHENTICATE");
                if _in_sasl_handshake || _is_sasl_resp {
                    // #142: gate raw SASL-handshake lines behind debug (off by default) — an
                    // AUTHENTICATE payload can carry credential material; don't log at info.
                    tracing::debug!("[{}] RAW(sasl): {}", conn_id, line);
                }
                // Prefer IRCv3 server-time tag when available
                let ts = p.tags.get("time")
                    .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
                    .map(|dt| dt.timestamp())
                    .unwrap_or_else(|| chrono::Utc::now().timestamp());

                match p.command.as_str() {

                    "PING" => {
                        let tok = p.params.last().cloned().unwrap_or_default();
                        // strip_crlf: `tok` is a server-supplied PING param echoed verbatim into
                        // the outbound PONG; an interior \r would inject a second command.
                        conn.lock().await.send_raw(&format!("PONG :{}\r\n", strip_crlf(&tok))).await?;
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
                                // Bound the accumulator: a malicious server can stream
                                // unbounded `CAP * LS *` lines and never send the terminal
                                // line, growing this without limit. Real servers advertise
                                // well under 100 caps, so a 256 cap changes nothing for them.
                                if available_caps.len() > 256 { available_caps.truncate(256); }
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
                                } else if !caps.contains("sasl") {
                                    // Non-SASL caps ACKed — send CAP END only if SASL is
                                    // not pending (already done/failed/not used)
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
                        info!("[{}] SASL 903: authentication successful", conn_id);
                        sasl_state = SaslState::Done;
                        conn.lock().await.send_raw("CAP END\r\n").await?;
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: true, message: "SASL authentication successful".into() });
                    }
                    "902" | "904" | "905" | "906" | "907" => {
                        let reason = p.params.last().cloned().unwrap_or_else(|| "SASL failed".into());
                        warn!("[{}] SASL {} FAILED: {}", conn_id, p.command, reason);
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: reason.clone() });
                        // Force-disconnect to let the connect loop retry. The "SASL_RETRY:"
                        // prefix tells the loop this is a SASL-specific failure (not a
                        // generic network error) so it can track failures separately.
                        return Err(anyhow::anyhow!("SASL_RETRY: {}", reason));
                    }

                    // ── Welcome ──────────────────────────────────────────
                    "001" => {
                        // #29: RPL_WELCOME must be idempotent. A hostile or broken server can
                        // replay 001 to make us re-send the NickServ IDENTIFY and OPER
                        // credentials and re-flood the perform-command + auto-join batch
                        // (outbound SendQ flood → excess-flood self-kill). Once we've
                        // registered on this connection, ignore any further 001.
                        if registered { continue; }
                        registered = true;
                        last_pong  = Instant::now();
                        let actual_nick = {
                            let mut c = conn.lock().await;
                            c.connected = true;
                            // Adopt the nick the network actually assigned us — the
                            // first parameter of 001 (RPL_WELCOME). This is the
                            // authoritative nick. Critical for ZNC, where the real
                            // nick can differ from the NICK we sent: if c.nick stays
                            // stale, self-echo suppression (`from == c.nick`, see the
                            // PRIVMSG/NOTICE arms) misses and the user's own messages
                            // appear twice — once under the config nick, once under
                            // the real nick.
                            if let Some(real) = p.params.get(0) {
                                if !real.is_empty() && real.as_str() != "*" {
                                    // strip_crlf: a server-supplied nick with an interior \r
                                    // (next_line only trims trailing CRLF) would otherwise be
                                    // smuggled into a later raw `NICK <nick>` send (CRLF injection).
                                    c.nick = strip_crlf(real);
                                }
                            }
                            c.nick.clone()
                        };
                        send(ServerEvent::Connected { conn_id: conn_id.to_string(), server: cfg.server.clone(), nick: actual_nick.clone() });
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
                        // Perform commands — raw IRC lines (or /slash) run after NickServ, before auto-join.
                        // Slash shortcuts mirror the interactive frontend: /msg, /notice, /ns, /nickserv,
                        // /cs, /chanserv, /identify, /id, /ghost, /quote, /raw. Anything else with a
                        // leading slash is stripped and sent raw (so `/MODE me +ix` works). `$me` and
                        // `$nick` expand to the current nickname.
                        // #93: split each perform entry on embedded newlines FIRST so a
                        // multi-line entry runs as multiple commands instead of being
                        // collapsed by strip_crlf into one corrupt line. Each sub-line then
                        // has any stray CR/LF stripped (CRLF-injection defense).
                        for entry in &cfg.perform_commands {
                        for line in entry.split(['\n', '\r']) {
                            let raw = strip_crlf(line.trim());
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
                                    "NS" | "NICKSERV"     => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :{}", args)) },
                                    "CS" | "CHANSERV"     => if args.is_empty() { None } else { Some(format!("PRIVMSG ChanServ :{}", args)) },
                                    "IDENTIFY" | "ID"     => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :IDENTIFY {}", args)) },
                                    "GHOST"               => if args.is_empty() { None } else { Some(format!("PRIVMSG NickServ :GHOST {}", args)) },
                                    "QUOTE" | "RAW"       => if args.is_empty() { None } else { Some(args.to_string()) },
                                    _                     => Some(rest.to_string()),
                                }
                            } else {
                                Some(raw.to_string())
                            };
                            let Some(mut to_send) = to_send_opt else { continue; };
                            // #93: expand $me / $nick only as WHOLE tokens (word-boundary), so a
                            // literal "$me"/"$nick" inside a larger word — e.g. a NickServ password —
                            // is left intact rather than silently rewritten to the nick.
                            to_send = expand_perform_token(&to_send, "$nick", &actual_nick);
                            to_send = expand_perform_token(&to_send, "$me",   &actual_nick);
                            conn.lock().await.send_raw(&format!("{}\r\n", to_send)).await?;
                        }
                        }
                        for ch in &cfg.auto_join {
                            let safe = strip_crlf(ch);
                            if !safe.is_empty() {
                                let lc = safe.to_lowercase();
                                // #24: the channel name is stripped above, but the channel KEY comes
                                // verbatim from config (channel_keys, persisted unsanitized). A key
                                // containing \r\n<extra line> would smuggle additional raw IRC lines,
                                // auto-replayed on every reconnect. Strip CRLF/NUL from the key too.
                                let cmd = if let Some(key) = cfg.channel_keys.get(&lc) {
                                    format!("JOIN {} {}\r\n", safe, strip_crlf(key))
                                } else {
                                    format!("JOIN {}\r\n", safe)
                                };
                                conn.lock().await.send_raw(&cmd).await?;
                            }
                        }
                    }

                    // S4: bounded nick collision retry — ONLY while still registering (pre-001).
                    // During registration we need *a* nick to finish connecting, so auto-append
                    // "_N". But once registered, a manual /nick that collides must surface the
                    // server's message (e.g. "Nickname is already in use") and keep the user's
                    // current nick — NOT silently switch it.
                    "432" | "433" | "436" => {
                        if registered {
                            // Show whatever the server said, in the status window (same as the
                            // default numeric handler) instead of auto-changing the nick.
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
                                    msg_id: 0,
                                    prefix: None,
                                });
                            }
                        } else {
                            nick_retries += 1;
                            if nick_retries > MAX_NICK_RETRIES {
                                return Err(anyhow::anyhow!("Nick collision: exhausted {} retries", MAX_NICK_RETRIES));
                            }
                            let mut c = conn.lock().await;
                            // Truncate to 28 chars before appending to stay within limits.
                            // #19: take whole chars — c.nick is adopted from remote 001/NICK and
                            // byte-slicing a multibyte nick would panic the connection task.
                            let base = truncate_chars(&c.nick, 28);
                            let new_nick = format!("{}_{}", base, nick_retries);
                            c.nick = new_nick.clone();
                            c.send_raw(&format!("NICK {}\r\n", new_nick)).await?;
                        }
                    }

                    "PRIVMSG" => {
                        let from   = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let text   = p.params.get(1).cloned().unwrap_or_default();
                        let user_nick = { conn.lock().await.nick.clone() };
                        // echo-message: if server echoes our own PRIVMSG, skip it here —
                        // the Send handler already broadcasts IrcEcho for multi-device sync.
                        // Suppress regardless of prefix form: a real IRCd echoes the full
                        // nick!user@host, but ZNC (and some bouncers) echo self-messages with
                        // a bare `:nick` prefix. Gating on `prefix.contains('!')` let those
                        // through and the user saw their own line twice. `from == user_nick`
                        // (with the authoritative nick adopted from 001) is the real test.
                        // Don't suppress echo for batch messages (chathistory/+H playback).
                        let in_batch = p.tags.contains_key("batch");
                        if echo_message_enabled && from == user_nick && !in_batch {
                            continue;
                        }
                        // Reply to CTCP VERSION
                        if text == "\x01VERSION\x01" {
                            // #45: rate-limit automatic CTCP replies. Without this, a stream of
                            // CTCP VERSION requests (optionally spoofed from many nicks) forces us
                            // to emit a matching NOTICE stream that the server penalizes with a
                            // SendQ/excess-flood kill — a no-privilege way to get us disconnected.
                            let now = Instant::now();
                            let allow = last_ctcp_reply.map_or(true, |t| now.duration_since(t) >= CTCP_REPLY_MIN_INTERVAL);
                            if allow {
                                last_ctcp_reply = Some(now);
                                // strip_crlf on `from` for defense-in-depth against IRC-line injection
                                // into the outbound NOTICE (the reader already splits on \r\n).
                                conn.lock().await.send_raw(&format!(
                                    "NOTICE {} :\x01VERSION CryptIRC v{} · {} - Made by gh0st - Visit irc.twistednet.org #dev #twisted\x01\r\n",
                                    strip_crlf(&from),
                                    env!("CARGO_PKG_VERSION"),
                                    option_env!("CRYPTIRC_BUILD").unwrap_or("dev"),
                                )).await?;
                            }
                            continue;
                        }
                        let (kind, clean) = if text.starts_with("\x01ACTION ") && text.ends_with('\x01') {
                            (MessageKind::Action, text[8..text.len()-1].to_string())
                        } else { (MessageKind::Privmsg, text) };
                        // Route PMs to sender's nick, not our own nick
                        let display_target = if target.starts_with(['#','&','+','!']) { target.clone() } else { from.clone() };
                        let msg_id = state.logger.append(username, conn_id, &display_target, ts, &from, &clean, kind_str(&kind)).await;
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: from.clone(), target: display_target.clone(), text: clean.clone(), ts, kind, msg_id, prefix: p.prefix.clone() });
                        // Push notification for DMs and mentions — only if no active (non-idle) sessions
                        // Fires when: no WS connected at all, OR all connected sessions are idle (20m timeout)
                        if from != user_nick && (state.user_events.get(username).map_or(true, |tx| tx.receiver_count() == 0) || state.user_is_idle(username)) {
                            // #11: spawn the push fan-out DETACHED so it can never block the IRC
                            // read loop (which must keep answering PINGs). maybe_notify is now
                            // internally concurrent + deadline-bounded + rate-limited.
                            let notifier = state.notifier.clone();
                            let (u, un, cid, lbl, tgt, frm, txt) = (
                                username.to_string(), user_nick.clone(), conn_id.to_string(),
                                cfg.label.clone(), display_target.clone(), from.clone(), clean.clone(),
                            );
                            tokio::spawn(async move {
                                notifier.maybe_notify(&u, &un, &cid, &lbl, &tgt, &frm, &txt, ts).await;
                            });
                        }
                    }
                    "NOTICE" => {
                        let from   = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let text   = p.params.get(1).cloned().unwrap_or_default();
                        let user_nick = { conn.lock().await.nick.clone() };
                        // #19: char-safe truncation — byte-slicing remote text panics on multibyte chars.
                        info!("[{}] NOTICE: from={} target={} text={}", conn_id, from, target, truncate_chars(&text, 120));
                        // Suppress echo-message echoes of our own NOTICEs (same as PRIVMSG).
                        // Match on `from == user_nick` only — ZNC echoes self-messages with a
                        // bare `:nick` prefix, so gating on `prefix.contains('!')` let them
                        // through and duplicated. Don't suppress batch (playback) NOTICEs.
                        let in_batch = p.tags.contains_key("batch");
                        if echo_message_enabled && from == user_nick && !in_batch {
                            continue;
                        }
                        // Route notices: channel → channel, server → status,
                        // our own outgoing → keep target (recipient), incoming → sender's nick
                        let display_target = if target.starts_with(['#','&','+','!']) {
                            target.clone()
                        } else if from == "*" || from.contains('.') || p.prefix.is_none() {
                            "status".to_string()
                        } else if from == user_nick {
                            target.clone() // Our own NOTICE — route to recipient's PM window
                        } else {
                            from.clone() // Incoming NOTICE — route to sender's nick
                        };
                        let msg_id = state.logger.append(username, conn_id, &display_target, ts, &from, &text, "notice").await;
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from, target: display_target, text, ts, kind: MessageKind::Notice, msg_id, prefix: None });
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
                        // #43: a malicious server can forge unlimited `:<ournick> JOIN #chanN`
                        // lines. Each forged self-JOIN would otherwise grow c.channels without
                        // bound, emit an outbound NAMES (request amplification), and create a
                        // per-channel log dir on disk. Track whether we accepted this channel so
                        // we can skip the NAMES + log bookkeeping when over the cap.
                        // `accepted` = this JOIN should be persisted/echoed;
                        // `is_self_join` = it was our own JOIN and we should issue NAMES.
                        let (accepted, is_self_join) = {
                            let mut c = conn.lock().await;
                            let chan_key = irc_lower(&channel); // #92
                            if nick == c.nick {
                                // #30: learn our own user@host from a self-JOIN so a later forged
                                // `:<ournick> NICK <x>` whose prefix does not match us cannot rewrite c.nick.
                                let uh = userhost_from_prefix(&p.prefix);
                                if !uh.is_empty() { c.self_userhost = uh; }
                                if c.channels.contains_key(&chan_key) {
                                    // #43: a server can repeat ":<ournick> JOIN #chan" to force
                                    // unbounded outbound NAMES/WHO. Only issue NAMES/WHO when the
                                    // channel is newly inserted; a re-JOIN of an already-tracked
                                    // channel is still echoed/logged but skips the amplification.
                                    (true, false)
                                } else if c.channels.len() < MAX_CHANNELS_PER_CONN {
                                    // F5: seed the in-memory key from the connect-time config so a
                                    // later -k on a favorites-keyed channel still persists its
                                    // removal (the +k/324/-k dedup compares against ch.key).
                                    let seed_key = cfg.channel_keys.get(&chan_key).cloned();
                                    c.channels.insert(chan_key.clone(), ChannelState { name: channel.clone(), topic: String::new(), names: vec![], key: seed_key });
                                    (true, true)
                                } else {
                                    warn!("[{}] Ignoring self-JOIN {} — channel cap ({}) reached", conn_id, channel, MAX_CHANNELS_PER_CONN);
                                    (false, false)
                                }
                            } else {
                                if let Some(ch) = c.channels.get_mut(&chan_key) {
                                    if ch.names.len() < NAMES_BUF_MAX_PER_CHAN { ch.names.push(nick.clone()); }
                                }
                                (true, false)
                            }
                        };
                        // Only issue the outbound NAMES amplification for an accepted self-JOIN.
                        if is_self_join {
                            // strip_crlf: `channel` is a server-supplied JOIN param; an interior
                            // \r would otherwise be reflected into the outbound NAMES/WHO (CRLF
                            // injection). The reader splits on \n, so a bare \r survives parsing.
                            conn.lock().await.send_raw(&format!("NAMES {}\r\n", strip_crlf(&channel))).await?;
                            // Seed the nick panel's away state immediately (don't wait for the
                            // periodic WHO_INTERVAL tick). Marked pending so the reply is consumed
                            // silently rather than dumped to the status buffer.
                            // Cap who_pending independently of the c.channels 256-cap: a self-PART
                            // removes the channel from c.channels (freeing the #43 slot) but NOT from
                            // who_pending, and the removing 315 reply is server-controlled. Without
                            // this guard a malicious peer's JOIN/PART churn (never sending 315) grows
                            // who_pending without bound → heap exhaustion. Mirrors the who_away guard.
                            let chan_key = irc_lower(&channel);
                            if who_pending.len() < NAMES_BUF_MAX_CHANNELS || who_pending.contains(&chan_key) {
                                who_pending.insert(chan_key);
                            }
                            conn.lock().await.send_raw(&format!("WHO {}\r\n", strip_crlf(&channel))).await?;
                        }
                        // Persist for log replay (Lounge-style condense after refresh) —
                        // skipped for channels rejected by the cap to bound disk/inode growth.
                        if accepted {
                            let mut join_text = format!("→ {} joined", nick);
                            if !account.is_empty() && account != "*" { join_text.push_str(&format!(" ({})", account)); }
                            if !realname.is_empty()                  { join_text.push_str(&format!(" — {}", realname)); }
                            let _ = state.logger.append(&username, &conn_id, &channel, ts, &nick, &join_text, "join").await;
                        }
                        // #43: don't surface a JOIN for a channel we refused to track
                        // (a cap-rejected forged self-JOIN) — keep client and server state in sync.
                        if accepted {
                            send(ServerEvent::IrcJoinEx {
                                conn_id: conn_id.to_string(), nick, channel,
                                account, realname, ts,
                            });
                        }
                    }
                    "PART" => {
                        let nick    = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let reason  = p.params.get(1).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; let k = irc_lower(&channel); if nick == c.nick { c.channels.remove(&k); } else if let Some(ch) = c.channels.get_mut(&k) { ch.names.retain(|n| strip_pfx(n) != nick); } }
                        let part_text = if reason.is_empty() { format!("← {} left", nick) } else { format!("← {} left ({})", nick, reason) };
                        let _ = state.logger.append(&username, &conn_id, &channel, ts, &nick, &part_text, "part").await;
                        send(ServerEvent::IrcPart { conn_id: conn_id.to_string(), nick, channel, reason, ts });
                    }
                    "QUIT" => {
                        let nick   = nick_from_prefix(&p.prefix);
                        let reason = p.params.get(0).cloned().unwrap_or_default();
                        let affected: Vec<String> = {
                            let mut c = conn.lock().await;
                            let chans: Vec<String> = c.channels.iter().filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n) == nick)).map(|(_, ch)| ch.name.clone()).collect();
                            for ch in c.channels.values_mut() { ch.names.retain(|n| strip_pfx(n) != nick); }
                            chans
                        };
                        let quit_text = if reason.is_empty() { format!("⊗ {} quit", nick) } else { format!("⊗ {} quit ({})", nick, reason) };
                        if affected.is_empty() {
                            let _ = state.logger.append(&username, &conn_id, "status", ts, &nick, &quit_text, "quit").await;
                        } else {
                            for ch in &affected {
                                let _ = state.logger.append(&username, &conn_id, ch, ts, &nick, &quit_text, "quit").await;
                            }
                        }
                        send(ServerEvent::IrcQuit { conn_id: conn_id.to_string(), nick, reason, ts });
                    }
                    "NICK" => {
                        let old = nick_from_prefix(&p.prefix);
                        let new = p.params.get(0).cloned().unwrap_or_default();
                        // #30: source user@host, used to verify a self-NICK really identifies us.
                        let src_userhost = userhost_from_prefix(&p.prefix);
                        let affected: Vec<String> = {
                            let mut c = conn.lock().await;
                            let chans: Vec<String> = c.channels.iter().filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n) == old)).map(|(_, ch)| ch.name.clone()).collect();
                            // #30: only adopt a self-NICK into our authoritative nick when the
                            // source fully identifies us — its user@host matches the one we recorded
                            // (from self-JOIN/CHGHOST). Before we have learned our own user@host
                            // (pre-JOIN) fall back to the legacy accept so a genuine early self-NICK
                            // still lands. This blocks a forged `:<ournick> NICK <x>` (bare or mismatched
                            // prefix) from corrupting self-echo suppression and the nick-retry base.
                            if old == c.nick
                                && (c.self_userhost.is_empty()
                                    || src_userhost.eq_ignore_ascii_case(&c.self_userhost))
                            {
                                c.nick = strip_crlf(&new);
                                if !src_userhost.is_empty() { c.self_userhost = src_userhost.clone(); }
                            }
                            for ch in c.channels.values_mut() {
                                for n in ch.names.iter_mut() {
                                    if strip_pfx(n) == old {
                                        let pfx: String = n.chars().take_while(|c| "@+~&%".contains(*c)).collect();
                                        *n = format!("{}{}", pfx, new);
                                    }
                                }
                            }
                            chans
                        };
                        let nick_text = format!("• {} is now known as {}", old, new);
                        if affected.is_empty() {
                            let _ = state.logger.append(&username, &conn_id, "status", ts, &new, &nick_text, "nick").await;
                        } else {
                            for ch in &affected {
                                let _ = state.logger.append(&username, &conn_id, ch, ts, &new, &nick_text, "nick").await;
                            }
                        }
                        send(ServerEvent::IrcNick { conn_id: conn_id.to_string(), old, new, ts });
                    }
                    "CHGHOST" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let new_host = p.params.get(1).cloned().unwrap_or_else(|| p.params.get(0).cloned().unwrap_or_default());
                        let mut c = conn.lock().await;
                        // #30: keep our recorded identity current across host cloaks so a later
                        // genuine self-NICK (which carries the NEW user@host) still matches.
                        if nick == c.nick {
                            let nu = p.params.get(0).cloned().unwrap_or_default();
                            let nh = p.params.get(1).cloned().unwrap_or_default();
                            if !nu.is_empty() && !nh.is_empty() { c.self_userhost = format!("{}@{}", nu, nh); }
                        }
                        let chans: Vec<String> = c.channels.iter()
                            .filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n) == nick))
                            .map(|(_, ch)| ch.name.clone())
                            .collect();
                        drop(c);
                        for ch in &chans {
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(), from: "*".into(), target: ch.clone(),
                                text: format!("*** {} has changed hostname to {}", nick, new_host),
                                ts, kind: MessageKind::Notice, msg_id: 0,
                                prefix: None,
                            });
                        }
                        if chans.is_empty() {
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                                text: format!("*** {} has changed hostname to {}", nick, new_host),
                                ts, kind: MessageKind::Notice, msg_id: 0,
                                prefix: None,
                            });
                        }
                    }
                    // ── IRCv3: away-notify ───────────────────────────
                    "AWAY" => {
                        let nick = nick_from_prefix(&p.prefix);
                        let message = p.params.get(0).cloned().unwrap_or_default();
                        let is_away = !message.is_empty();
                        let (kind_str, log_text) = if is_away {
                            ("away", format!("{} is away: {}", nick, message))
                        } else {
                            ("back", format!("{} is back", nick))
                        };
                        let _ = state.logger.append(&username, &conn_id, "status", ts, &nick, &log_text, kind_str).await;
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
                                let display_target = if target.starts_with(['#','&','+','!']) { target } else { from.clone() };
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
                            kind: MessageKind::Notice, msg_id: 0,
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
                        let text = params_from(&p.params, 1); // #19: guard against <1 param
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: "status".into(), text, ts,
                            kind: MessageKind::Notice, msg_id: 0,
                            prefix: None,
                        });
                    }
                    // 734 ERR_MONLISTFULL
                    "734" => {
                        let text = p.params.last().cloned().unwrap_or("Monitor list full".into());
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: "status".into(), text, ts,
                            kind: MessageKind::Notice, msg_id: 0,
                            prefix: None,
                        });
                    }

                    "KICK" => {
                        let by      = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let kicked  = p.params.get(1).cloned().unwrap_or_default();
                        let reason  = p.params.get(2).cloned().unwrap_or_default();
                        { let mut c = conn.lock().await; let k = irc_lower(&channel); if kicked == c.nick { c.channels.remove(&k); } else if let Some(ch) = c.channels.get_mut(&k) { ch.names.retain(|n| strip_pfx(n) != kicked); } }
                        let kick_text = if reason.is_empty() { format!("✗ {} kicked by {}", kicked, by) } else { format!("✗ {} kicked by {} ({})", kicked, by, reason) };
                        let _ = state.logger.append(&username, &conn_id, &channel, ts, &kicked, &kick_text, "kick").await;
                        send(ServerEvent::IrcKick { conn_id: conn_id.to_string(), channel, kicked, by, reason, ts });
                    }
                    "TOPIC" => {
                        let set_by  = nick_from_prefix(&p.prefix);
                        let channel = p.params.get(0).cloned().unwrap_or_default();
                        let topic   = p.params.get(1).cloned().unwrap_or_default();
                        // #28: only surface a topic for a channel we actually track. A malicious
                        // server can forge TOPIC for unlimited untracked channels to grow client
                        // state unbounded, bypassing the #43 256-channel JOIN cap.
                        let tracked = { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&irc_lower(&channel)) { ch.topic = topic.clone(); true } else { false } };
                        if tracked {
                            send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by, ts });
                        }
                    }
                    "332" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let topic   = p.params.get(2).cloned().unwrap_or_default();
                        // #28: gate forged 332 for untracked channels (see TOPIC arm).
                        let tracked = { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&irc_lower(&channel)) { ch.topic = topic.clone(); true } else { false } };
                        if tracked {
                            send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by: String::new(), ts });
                        }
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
                        // #28: gate forged 366 for untracked channels (see TOPIC arm). The names_buf
                        // remove above still runs so buffered names for a dropped channel are freed.
                        let tracked = { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&irc_lower(&channel)) { ch.names = names.clone(); true } else { false } };
                        if tracked {
                            send(ServerEvent::IrcNames { conn_id: conn_id.to_string(), channel, names });
                        }
                    }
                    "MODE" => {
                        let setter = nick_from_prefix(&p.prefix);
                        let target = p.params.get(0).cloned().unwrap_or_default();
                        let modes  = params_from(&p.params, 1); // #19: guard against parameterless MODE
                        // Capture a +k/-k channel-key change so the auto-rejoin store stays
                        // current. Outer Some = a k mode was seen; inner Some(key) = +k <key>,
                        // inner None = -k. Persisted AFTER the conn lock is dropped (below).
                        let mut k_change: Option<Option<String>> = None;
                        // Update nick prefixes in server-side names list so reconnecting
                        // clients get accurate op/voice/etc. status from the State event.
                        if target.starts_with(['#','&','+','!']) {
                            let mode_map: &[(char,char)] = &[('o','@'),('v','+'),('h','%'),('a','&'),('q','~')];
                            let parts: Vec<&str> = modes.split_whitespace().collect();
                            let mode_str = parts.first().copied().unwrap_or("");
                            let mut arg_idx = 1usize;
                            let mut adding = true;
                            let mut c = conn.lock().await;
                            if let Some(ch) = c.channels.get_mut(&irc_lower(&target)) {
                                for mc in mode_str.chars() {
                                    if mc == '+' { adding = true; continue; }
                                    if mc == '-' { adding = false; continue; }
                                    if let Some(&(_, pfx)) = mode_map.iter().find(|(m,_)| *m == mc) {
                                        if let Some(&t_nick) = parts.get(arg_idx) {
                                            arg_idx += 1;
                                            if let Some(entry) = ch.names.iter_mut().find(|n| strip_pfx(n).eq_ignore_ascii_case(t_nick)) {
                                                let old_pfx: String = entry.chars().take_while(|c| "~&@%+".contains(*c)).collect();
                                                let bare = strip_pfx(entry).to_string();
                                                if adding {
                                                    if !old_pfx.contains(pfx) {
                                                        let all_pfx: String = old_pfx.chars().chain(std::iter::once(pfx)).collect();
                                                        let mut new_pfx = String::new();
                                                        for ch_c in "~&@%+".chars() {
                                                            if all_pfx.contains(ch_c) { new_pfx.push(ch_c); }
                                                        }
                                                        *entry = format!("{}{}", new_pfx, bare);
                                                    }
                                                } else {
                                                    let new_pfx: String = old_pfx.chars().filter(|c| *c != pfx).collect();
                                                    *entry = format!("{}{}", new_pfx, bare);
                                                }
                                            }
                                        }
                                    } else if mc == 'k' {
                                        // Type-B mode: always carries a param (+k <key>, -k [*]).
                                        // Capture it for the auto-rejoin store, but only when the
                                        // key actually changed vs. our in-memory copy (F5) so a
                                        // stream of identical MODE echoes can't force a per-line
                                        // get/save on disk. ch.key mirrors the persisted value.
                                        if adding {
                                            if let Some(&kp) = parts.get(arg_idx) {
                                                if !kp.is_empty() && kp != "*" && ch.key.as_deref() != Some(kp) {
                                                    ch.key = Some(kp.to_string());
                                                    k_change = Some(Some(kp.to_string()));
                                                }
                                            }
                                        } else if ch.key.is_some() {
                                            ch.key = None;
                                            k_change = Some(None); // -k removes the saved key
                                        }
                                        arg_idx += 1;
                                    } else if "beI".contains(mc) {
                                        arg_idx += 1;                          // type-A list modes: param on + and -
                                    } else if adding && "lfjLJ".contains(mc) {
                                        arg_idx += 1;                          // type-C modes: param on set only
                                    }
                                }
                            }
                            drop(c);
                        }
                        // Persist a captured +k/-k change to the network config so a fresh
                        // connect() after a full server restart re-enters this keyed channel,
                        // even though its key was set/changed AFTER we joined. (do_connect only
                        // borrows cfg, so we can't update the in-task snapshot — disk is the
                        // source of truth the next connect() reads.)
                        if let Some(kc) = k_change {
                            persist_channel_key(&state, &username, &conn_id, &target, kc.as_deref()).await;
                        }
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
                        // Persist for log replay; text matches what the frontend renders.
                        let log_text = if !setter.is_empty() && !setter.contains('.') {
                            format!("{} sets mode {}", setter, modes)
                        } else {
                            format!("MODE {}", modes)
                        };
                        let log_from: String = if setter.is_empty() || setter.contains('.') { "*".into() } else { setter.clone() };
                        let _ = state.logger.append(&username, &conn_id, &display_target, ts, &log_from, &log_text, "mode").await;
                        send(ServerEvent::IrcMode { conn_id: conn_id.to_string(), target: display_target, modes: display, ts });
                    }
                    // 311-318 = WHOIS replies — route to nick's query buffer
                    "311" => { // RPL_WHOISUSER: nick user host * :realname
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let user = p.params.get(2).cloned().unwrap_or_default();
                        let host = p.params.get(3).cloned().unwrap_or_default();
                        let real = p.params.get(5).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("{}!{}@{} ({})", p.params.get(1).cloned().unwrap_or_default(), user, host, real), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "312" => { // RPL_WHOISSERVER
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = params_from(&p.params, 2); // #19: guard against <2 params
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Server: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "313" => { // RPL_WHOISOPERATOR
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "317" => { // RPL_WHOISIDLE
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let idle: u64 = p.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let signon: i64 = p.params.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
                        let idle_str = if idle >= 3600 { format!("{}h {}m {}s", idle/3600, (idle%3600)/60, idle%60) } else if idle >= 60 { format!("{}m {}s", idle/60, idle%60) } else { format!("{}s", idle) };
                        let signon_str = chrono::DateTime::from_timestamp(signon, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Idle: {} | Signon: {}", idle_str, signon_str), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "318" => { // RPL_ENDOFWHOIS
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "End of WHOIS".into(), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "319" => { // RPL_WHOISCHANNELS
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let chans = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Channels: {}", chans), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "330" => { // RPL_WHOISACCOUNT (logged in as)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let account = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Logged in as: {}", account), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "338" => { // RPL_WHOISACTUALLY (actual host/IP)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = params_from(&p.params, 2); // #19: guard against <2 params
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Actually: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "671" => { // RPL_WHOISSECURE
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "Using secure connection (TLS)".into(), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    // Additional WHOIS numerics — route to nick's query buffer
                    "301" => { // RPL_AWAY
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let msg = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Away: {}", msg), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "307" => { // RPL_WHOISREGNICK
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or("is a registered nick".into());
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "378" => { // RPL_WHOISHOST (connecting from)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "379" => { // RPL_WHOISMODES
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "320" => { // RPL_WHOISSPECIAL (identified, bot, etc)
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    "275" | "276" => { // RPL_WHOISCERTFP — TLS certificate fingerprint
                        let nick = p.params.get(1).cloned().unwrap_or_default();
                        let text = p.params.get(2).cloned().unwrap_or_default();
                        send(ServerEvent::IrcMessage { conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Certificate: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
                    }
                    // 367 = RPL_BANLIST — one entry in the ban list
                    // 367 = RPL_BANLIST, 348 = RPL_EXCEPTLIST, 346 = RPL_INVITELIST (invex).
                    // All three are single list entries; `list` tags which list.
                    "367" | "348" | "346" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let mask    = p.params.get(2).cloned().unwrap_or_default();
                        let set_by  = p.params.get(3).cloned().unwrap_or_default();
                        let list = match p.command.as_str() { "348" => "e", "346" => "I", _ => "b" }.to_string();
                        send(ServerEvent::IrcBanEntry {
                            conn_id: conn_id.to_string(), channel, mask, set_by, ts, list,
                        });
                    }
                    // 368 = end ban list, 349 = end exempt list, 347 = end invex list
                    "368" | "349" | "347" => {
                        let channel = p.params.get(1).cloned().unwrap_or_default();
                        let list = match p.command.as_str() { "349" => "e", "347" => "I", _ => "b" }.to_string();
                        send(ServerEvent::IrcBanEnd { conn_id: conn_id.to_string(), channel, list });
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
                            ts, kind: MessageKind::Notice, msg_id: 0,
                            prefix: None,
                        });
                    }
                    // 365 = RPL_ENDOFLINKS
                    "365" => {
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "links".into(),
                            target: "status".into(),
                            text: "End of /LINKS".into(),
                            ts, kind: MessageKind::Notice, msg_id: 0,
                            prefix: None,
                        });
                    }
                    // 324 RPL_CHANNELMODEIS — route to channel, not status
                    "324" => {
                        let chan = p.params.get(1).cloned().unwrap_or_default();
                        let modes = params_from(&p.params, 2); // #19: guard against <2 params
                        // Learn this channel's key (when it's keyed and the server reveals it
                        // to us) so auto-rejoin can re-enter even if we didn't /join with the
                        // key — e.g. joined an already-keyed channel from favorites/the list.
                        // ADD-only: a masked '*' / absent key means "not told", NOT keyless, so
                        // we never remove here (that would clobber a key we legitimately hold).
                        if chan.starts_with(['#','&','+','!']) {
                            if let Some(key) = channel_key_from_modes(&modes) {
                                // F5: only persist for a channel we're actually tracking (gate
                                // like TOPIC/332/366) and only when the key changed in memory —
                                // this short-circuits BEFORE the expensive get/save so a server
                                // streaming distinct/repeated 324s can't force unbounded growth
                                // or O(n) disk I/O on the read loop's critical path.
                                let need_persist = {
                                    let mut c = conn.lock().await;
                                    match c.channels.get_mut(&irc_lower(&chan)) {
                                        Some(ch) if ch.key.as_deref() != Some(key.as_str()) => {
                                            ch.key = Some(key.clone());
                                            true
                                        }
                                        _ => false,
                                    }
                                };
                                if need_persist {
                                    persist_channel_key(&state, &username, &conn_id, &chan, Some(key.as_str())).await;
                                }
                            }
                        }
                        // Structured event so the Channel Modes GUI can parse current
                        // modes; the frontend also shows a sysMsg for manual /mode users.
                        send(ServerEvent::IrcChannelModes {
                            conn_id: conn_id.to_string(), channel: chan, modes,
                        });
                    }
                    // 329 RPL_CREATIONTIME — route to channel
                    "329" => {
                        let chan = p.params.get(1).cloned().unwrap_or_default();
                        let raw_ts = p.params.get(2).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
                        let text = if raw_ts > 0 {
                            let dt = chrono::DateTime::from_timestamp(raw_ts, 0)
                                .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                                .unwrap_or_else(|| raw_ts.to_string());
                            format!("Channel created: {}", dt)
                        } else { raw_ts.to_string() };
                        let display_target = if chan.starts_with(['#','&','+','!']) { chan } else { "status".to_string() };
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: display_target, text, ts,
                            kind: MessageKind::Notice, msg_id: 0, prefix: None,
                        });
                    }
                    // 403 ERR_NOSUCHCHANNEL — route to channel if it looks like one
                    "403" => {
                        let chan = p.params.get(1).cloned().unwrap_or_default();
                        let reason = p.params.get(2).cloned().unwrap_or("No such channel".into());
                        let display_target = if chan.starts_with(['#','&','+','!']) { chan } else { "status".to_string() };
                        send(ServerEvent::IrcMessage {
                            conn_id: conn_id.to_string(), from: "*".into(),
                            target: display_target, text: reason, ts,
                            kind: MessageKind::Notice, msg_id: 0, prefix: None,
                        });
                    }
                    // ── WHO away-state polling (no away-notify on ratbox) ─────
                    "352" => { // RPL_WHOREPLY: <me> <chan> <user> <host> <server> <nick> <H|G..> :<hops> <real>
                        let channel  = p.params.get(1).cloned().unwrap_or_default();
                        let who_nick = p.params.get(5).cloned().unwrap_or_default();
                        let status   = p.params.get(6).cloned().unwrap_or_default();
                        // Case-fold the server-echoed channel for all internal lookups
                        // (who_away keying + the who_pending auto/manual discrimination).
                        let chan_key = irc_lower(&channel);
                        // 'G' = gone/away, 'H' = here. Accumulate away nicks for the snapshot;
                        // here-nicks are implied by absence (the frontend has the member list).
                        if status.starts_with('G') && !who_nick.is_empty()
                            && (who_away.len() < NAMES_BUF_MAX_CHANNELS || who_away.contains_key(&chan_key)) {
                            let v = who_away.entry(chan_key.clone()).or_default();
                            if v.len() < NAMES_BUF_MAX_PER_CHAN { v.push(who_nick); }
                        }
                        // A user-typed /who isn't in who_pending — keep forwarding its raw
                        // reply to status so manual WHO still works as before.
                        if !who_pending.contains(&chan_key) {
                            let text = if p.params.len() > 1 { p.params[1..].join(" ") } else { String::new() };
                            if !text.is_empty() {
                                let msg_id = state.logger.append(username, conn_id, "status", ts, "*", &text, "notice").await;
                                send(ServerEvent::IrcMessage {
                                    conn_id: conn_id.to_string(), from: "*".into(),
                                    target: "status".into(), text, ts,
                                    kind: MessageKind::Notice, msg_id, prefix: None,
                                });
                            }
                        }
                    }
                    "315" => { // RPL_ENDOFWHO: <me> <chan/mask> :End of /WHO list.
                        let channel  = p.params.get(1).cloned().unwrap_or_default();
                        let chan_key = irc_lower(&channel);
                        let was_auto = who_pending.remove(&chan_key);
                        // Emit a snapshot only for real channels (skip `WHO nick`-style masks).
                        if channel.starts_with(['#','&','+','!']) {
                            let away_nicks = who_away.remove(&chan_key).unwrap_or_default();
                            // Resolve back to the canonical channel name we actually track
                            // (the JOIN-echo case) so the frontend — which keys its channel
                            // buffers by that exact string — can apply the snapshot. The
                            // server/ZNC may have echoed this 315 in a different case;
                            // emitting it verbatim would silently miss the away graying.
                            let display_chan = {
                                let c = conn.lock().await;
                                // #92: channels is keyed by irc_lower; return the stored display name.
                                c.channels.get(&chan_key).map(|ch| ch.name.clone()).unwrap_or(channel)
                            };
                            send(ServerEvent::IrcAwaySnapshot {
                                conn_id: conn_id.to_string(), channel: display_chan, away_nicks,
                            });
                        } else {
                            who_away.remove(&chan_key);
                        }
                        // Preserve the status line for a user-initiated /who.
                        if !was_auto {
                            let text = if p.params.len() > 1 { p.params[1..].join(" ") } else { String::new() };
                            if !text.is_empty() {
                                let msg_id = state.logger.append(username, conn_id, "status", ts, "*", &text, "notice").await;
                                send(ServerEvent::IrcMessage {
                                    conn_id: conn_id.to_string(), from: "*".into(),
                                    target: "status".into(), text, ts,
                                    kind: MessageKind::Notice, msg_id, prefix: None,
                                });
                            }
                        }
                    }
                    // Forward unhandled numerics (whois, lusers, motd, etc.) as status messages
                    cmd if cmd.chars().all(|c| c.is_ascii_digit()) => {
                        let text = if p.params.len() > 1 {
                            p.params[1..].join(" ")
                        } else {
                            p.params.join(" ")
                        };
                        if !text.is_empty() {
                            let msg_id = state.logger.append(username, conn_id, "status", ts, "*", &text, "notice").await;
                            send(ServerEvent::IrcMessage {
                                conn_id: conn_id.to_string(),
                                from: "*".to_string(),
                                target: "status".to_string(),
                                text,
                                ts,
                                kind: MessageKind::Notice,
                                msg_id,
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
                                msg_id: 0,
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
        // #91: cap the number of parsed tags. The IRCv3 spec limits a tag section to
        // 8191 bytes; a malicious server could still pack thousands of tiny tags per
        // line to churn allocations. Real servers send a handful.
        for pair in tag_str.split(';').take(64) {
            if let Some((k, v)) = pair.split_once('=') {
                // #85: unescape IRCv3 tag values in a single left-to-right pass as the
                // message-tags spec requires. The previous chained `.replace()` applied
                // escapes out of order (e.g. `\s` matched before `\\` collapsed), so an
                // adversarially-escaped value like `\\s` decoded to `\ ` instead of `\s`.
                tags.insert(k.to_string(), unescape_tag_value(v));
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

/// #85: spec-correct single-pass IRCv3 message-tag value unescaper. Walks the
/// value once; on '\' it consumes the next char and maps `:`→`;`, `s`→space,
/// `r`→CR, `n`→LF, any other char to itself, and a trailing lone backslash to a
/// literal backslash. This avoids the ordering bugs and extra allocations of the
/// old chained `.replace()` approach.
fn unescape_tag_value(v: &str) -> String {
    // Defense-in-depth: CR, LF and NUL are illegal inside IRC tag values (they are
    // line/field delimiters), so DROP any decoded-or-literal CR/LF/NUL rather than
    // materializing them. This stops a malicious server from smuggling a newline
    // into a parsed tag value (e.g. the `account` / `time` tags) that some future
    // code path might concatenate into an outbound raw line — a latent CRLF
    // injection vector. No legitimate tag value contains these bytes, so honest
    // traffic is unaffected.
    fn forbidden(c: char) -> bool { c == '\r' || c == '\n' || c == '\0' }
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some(':')  => out.push(';'),
                Some('s')  => out.push(' '),
                Some('r')  => {}            // \r → CR: dropped (delimiter)
                Some('n')  => {}            // \n → LF: dropped (delimiter)
                Some('\\') => out.push('\\'),
                Some(other) if !forbidden(other) => out.push(other),
                Some(_)    => {}            // literal CR/LF/NUL after a backslash: dropped
                None       => out.push('\\'), // trailing lone backslash → literal
            }
        } else if !forbidden(c) {
            out.push(c);
        }
    }
    out
}

fn nick_from_prefix(p: &Option<String>) -> String {
    p.as_deref().and_then(|s| s.split('!').next()).unwrap_or("*").to_string()
}

fn userhost_from_prefix(p: &Option<String>) -> String {
    p.as_deref().and_then(|s| s.split_once('!')).map(|(_, uh)| uh.to_string()).unwrap_or_default()
}

fn strip_pfx(n: &str) -> &str { let s = n.trim_start_matches(|c: char| "@+~&%".contains(c)); if s.is_empty() { n } else { s } }
fn kind_str(k: &MessageKind) -> &'static str {
    match k { MessageKind::Privmsg => "privmsg", MessageKind::Notice => "notice", MessageKind::Action => "action" }
}
