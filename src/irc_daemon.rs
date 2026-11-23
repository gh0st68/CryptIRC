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
    channel_key_change, channel_key_from_modes, channel_key_lookup_cm, nick_from_prefix, CaseMapping, ChanModes,
    params_from, parse_irc, strip_crlf, truncate_chars, CappedLine, CappedLineReader, MAX_IRC_LINE_LEN,
};
use anyhow::Result;
use rand::Rng;
use std::collections::{HashMap, HashSet};
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
/// No complete line from the server for this long = dead connection. A real deadline
/// in run_loop's select! (reset on every line read), not a per-iteration timeout: the
/// old per-iteration form was recreated every <=30 s by the heartbeat tick, so it could
/// never fire.
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
/// r7 (codex P2 irc_daemon.rs:1614): what the tracked channel names may add up to in a
/// SessionSync, JSON-serialized (quotes + comma each; a `"` or `\` escapes to 2 bytes; control
/// bytes are never tracked). It replaces the old per-name filter (≤ 100 bytes, no `"`/`\`),
/// which left channels the web accepts out of every SessionSync — after a web restart they
/// vanished from the web and the TUI. Reserve room for registration and the
/// worst-case JSON escaping of a colored userhost within MAX_FRAME_LEN (64 KiB).
const TRACKED_NAMES_JSON_BUDGET: usize = 50 * 1024;

/// JSON size of one channel name in the SessionSync list (see TRACKED_NAMES_JSON_BUDGET).
fn tracked_json_len(name: &str) -> usize { name.len() + name.bytes().filter(|b| *b == b'"' || *b == b'\\').count() + 3 }

/// r8 (codex P2 irc_daemon.rs:97): may this SessionSync channel list have been cut by
/// admit_tracked (count cap reached, or too little budget left for one more name of the
/// largest JSON size)? Then a channel missing from it is no proof it was left — the web
/// does not drop such a channel on the strength of this snapshot.
pub fn snapshot_may_be_truncated(channels: &[String]) -> bool {
    let largest = 2 * (MAX_INTENT_CHANNEL_LEN - 1) + 1 + 3;
    channels.len() >= MAX_TRACKED_CHANNELS
        || channels.iter().map(|c| tracked_json_len(c)).sum::<usize>() + largest > TRACKED_NAMES_JSON_BUDGET
}

/// May `name` (fold `lc`) join the tracked set? Count and JSON-size bounded; a channel already
/// tracked may always change its spelling.
fn admit_tracked(channels: &HashMap<String, String>, lc: &str, name: &str) -> bool {
    if let Some(old) = channels.get(lc) {
        let total: usize = channels.values().map(|v| tracked_json_len(v)).sum();
        return total - tracked_json_len(old) + tracked_json_len(name) <= TRACKED_NAMES_JSON_BUDGET;
    }
    channels.len() < MAX_TRACKED_CHANNELS
        && channels.values().map(|v| tracked_json_len(v)).sum::<usize>() + tracked_json_len(name) <= TRACKED_NAMES_JSON_BUDGET
}
/// Covers TwistedNET's 300-byte colored host plus the ident and separator.
/// SessionSync also has room for the JSON escapes of its formatting bytes.
pub const MAX_USERHOST_LEN: usize = 320;
/// Cap on a server-assigned nick we adopt (001 / self-NICK). Also serialized in every
/// SessionSync, so it needs the same bound as channel names and the userhost: real
/// NICKLEN is 9-50.
const MAX_NICK_LEN: usize = 64;
/// SASL (IRCv3): an AUTHENTICATE payload is sent in chunks of at most this many bytes.
const SASL_CHUNK: usize = 400;

/// A channel name we'll TRACK (for SessionSync + reconnect re-join) must be sane:
/// channel-prefixed, length-bounded, and free of bytes that aren't valid in a channel
/// (space/comma/control). r7 (codex P2 irc_daemon.rs:1614): exactly the names the web accepts
/// (is_intent_channel) — the frame-size bound is now kept by TRACKED_NAMES_JSON_BUDGET over
/// the whole set (admit_tracked), not by refusing `"` / `\` / long names one by one.
/// Public so the web side can tell which of its channels a SessionSync speaks for.
pub fn is_trackable_channel(name: &str) -> bool { is_intent_channel(name) }

/// r6 (codex P2 irc_daemon.rs:183): a channel name the USER can join through the web
/// (main.rs is_valid_channel: channel prefix, at most 200 bytes, no space/comma/NUL), here
/// also without control bytes. The daemon's own bookkeeping of the user's intent — channels
/// parted (user_parted), channels to re-join after a reconnect (persistent_channels) and
/// their learned keys — is never serialized into a SessionSync, so it accepts `"` and `\`
/// too: a PART or backoff JOIN of `#team\ops` used to be dropped silently. What is TRACKED
/// for the SessionSync (is_trackable_channel) is unchanged.
pub fn is_intent_channel(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_INTENT_CHANNEL_LEN { return false; }
    if !matches!(name.as_bytes()[0], b'#' | b'&' | b'+' | b'!') { return false; }
    name.bytes().all(|b| b > 0x20 && b != b',' && b != 0x7f)
}
/// The web's channel-name length bound (main.rs is_valid_channel).
const MAX_INTENT_CHANNEL_LEN: usize = 200;

/// Preserve the exact user@host for identity checks. Only the host may carry
/// the formatting bytes supported by TwistedNET.
pub fn clean_userhost(uh: &str) -> Option<String> {
    let (ident, host) = uh.split_once('@')?;
    let plain = |b| b > 0x20 && !matches!(b, b'"' | b'\\' | b'\x7f');
    if uh.len() > MAX_USERHOST_LEN || ident.is_empty() || host.is_empty()
        || !ident.bytes().all(plain)
        || !host.bytes().all(|b| b != b'@' && (plain(b) || matches!(b, 2 | 3 | 15 | 22 | 29 | 31)))
    {
        return None;
    }
    Some(uh.to_string())
}

/// Bound + sanitize a server-assigned nick (001 param / self-NICK) before adopting it.
/// Returns None if it's implausible (empty, too long, control bytes or space) so the
/// caller keeps the previous nick. Without this a hostile server could set an 8 KB nick
/// of control bytes (6 JSON bytes each) and push every SessionSync past MAX_FRAME_LEN,
/// where write_frame silently drops it (live AND on replay). Backslash and other
/// RFC1459 specials are legal nick bytes and stay allowed; with the length cap they can
/// at most double a 64-byte nick in JSON.
fn clean_nick(n: &str) -> Option<String> {
    let n = strip_crlf(n);
    if n.is_empty() || n.len() > MAX_NICK_LEN { return None; }
    if !n.bytes().all(|b| b > 0x20 && b != 0x7f) { return None; }
    Some(n)
}

/// Cap on a learned channel key's length (real servers cap keys at ~23-50).
const MAX_KEY_LEN: usize = 128;

/// Remember a channel key learned DURING the session (see `learned_keys` in
/// run_connection), bounded and sanitized like every other tracked value.
/// remember_key, keyed by the connection's CASEMAPPING fold (codex P2 :144).
fn remember_key_cm(keys: &mut HashMap<String, String>, chan: &str, key: &str, cm: CaseMapping) {
    let key = strip_crlf(key.trim_start_matches(':'));
    if key.is_empty() || key == "*" || key.len() > MAX_KEY_LEN || key.contains(' ') { return; }
    if !is_intent_channel(chan) { return; }
    let lc = cm.fold(chan);
    if keys.len() < MAX_TRACKED_CHANNELS || keys.contains_key(&lc) {
        keys.insert(lc, key);
    }
}

/// Learn the keys the user supplies in an outbound `JOIN #a,#b keyA,keyB` (every web-side
/// JOIN — the Join dialog, `/join #chan key` — goes out through RawSend).
#[cfg(test)]
fn learn_join_keys(line: &str, keys: &mut HashMap<String, String>) {
    learn_join_keys_cm(line, keys, CaseMapping::default())
}
fn learn_join_keys_cm(line: &str, keys: &mut HashMap<String, String>, cm: CaseMapping) {
    let mut line = line.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
    // r8 (codex P2 irc_daemon.rs:183): after IRCv3 `@tags` (and a `:source`), like the other
    // outbound parsers — `@label=x JOIN #keyed secret` teaches the key too.
    if line.starts_with('@') { line = line.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    if line.starts_with(':') { line = line.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    let mut parts = line.split(' ').filter(|t| !t.is_empty());
    if !parts.next().map_or(false, |c| c.eq_ignore_ascii_case("JOIN")) { return; }
    let (Some(chans), Some(klist)) = (parts.next(), parts.next()) else { return };
    for (chan, key) in chans.split(',').zip(klist.trim_start_matches(':').split(',')) {
        remember_key_cm(keys, chan, key, cm);
    }
}

/// r4 (codex P2 irc_daemon.rs:1361): track the channels the user parts / joins through an
/// outbound line (`PART #a,#b [:reason]` / `JOIN #a[,#b] [keys]`, optionally after `@tags`
/// / `:source`) in `parted` (folded → spelling; see `user_parted` in run_connection). A
/// server-forced PART or a KICK is not the user's choice and is not recorded: the saved
/// auto-join list keeps such a channel, and so does this side. `JOIN 0` names no channel.
fn note_user_part_join(line: &str, parted: &mut HashMap<String, String>, cm: CaseMapping) {
    let mut rest = line.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
    if rest.starts_with('@') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    if rest.starts_with(':') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    let mut parts = rest.split(' ').filter(|t| !t.is_empty());
    let verb = parts.next().unwrap_or("");
    let is_part = verb.eq_ignore_ascii_case("PART");
    if !is_part && !verb.eq_ignore_ascii_case("JOIN") { return; }
    let Some(chans) = parts.next() else { return };
    for chan in chans.trim_start_matches(':').split(',') {
        if !is_intent_channel(chan) { continue; }
        let lc = cm.fold(chan);
        if !is_part {
            parted.remove(&lc);
        } else if parted.len() < MAX_TRACKED_CHANNELS || parted.contains_key(&lc) {
            parted.insert(lc, chan.to_string());
        }
    }
}

/// r5 (codex P2 irc_daemon.rs:717): an outbound JOIN/PART that arrives while the connection is
/// down (reconnect backoff) cannot be sent, but the user's intent must survive to the next
/// registration: PART → recorded as user-parted and dropped from the channels re-joined
/// after registration; JOIN → un-parted and added to them (bounded), with its key as a
/// learned key. Returns true if the line was such a JOIN/PART.
fn apply_backoff_part_join(line: &str, persistent: &mut HashMap<String, String>, parted: &mut HashMap<String, String>,
                           keys: &mut HashMap<String, String>, cm: CaseMapping) -> bool {
    let mut rest = line.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
    if rest.starts_with('@') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    if rest.starts_with(':') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
    let mut parts = rest.split(' ').filter(|t| !t.is_empty());
    let verb = parts.next().unwrap_or("");
    let is_join = verb.eq_ignore_ascii_case("JOIN");
    if !is_join && !verb.eq_ignore_ascii_case("PART") { return false; }
    let Some(chans) = parts.next() else { return false };
    note_user_part_join(line, parted, cm);
    let klist: Vec<&str> = parts.next().map(|k| k.trim_start_matches(':').split(',').collect()).unwrap_or_default();
    for (i, chan) in chans.trim_start_matches(':').split(',').enumerate() {
        if !is_intent_channel(chan) { continue; }
        let lc = cm.fold(chan);
        if is_join {
            if persistent.len() < MAX_TRACKED_CHANNELS || persistent.contains_key(&lc) {
                persistent.insert(lc, chan.to_string());
            }
            if let Some(k) = klist.get(i) { remember_key_cm(keys, chan, k, cm); }
        } else {
            persistent.remove(&lc);
        }
    }
    true
}

/// Split a base64 SASL response into AUTHENTICATE arguments (IRCv3 sasl-3.1): chunks of
/// at most 400 bytes, and a final `+` when the last chunk is exactly 400 bytes (or the
/// payload is empty) so the server knows the response is complete. A payload under 400
/// bytes — every normal PLAIN login — is one chunk, exactly as before.
fn sasl_chunks(b64: &str) -> Vec<String> {
    if b64.is_empty() { return vec!["+".to_string()]; }
    // base64 is ASCII, so byte chunks are char boundaries.
    let mut out: Vec<String> = b64.as_bytes().chunks(SASL_CHUNK)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    if b64.len() % SASL_CHUNK == 0 { out.push("+".to_string()); }
    out
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

/// codex P2 ipc_server.rs:745: IRC line limits for a web-originated outbound line. The
/// message part (everything after an optional `@tags ` section) is at most 512 bytes
/// including CRLF; an IRCv3 tag section is at most 8191 bytes including its `@` and the
/// separating space. A server cuts (or rejects) anything longer, so capping here changes
/// nothing on the wire — it only stops a queued line from pinning up to a whole 64 KiB
/// IPC frame of daemon memory.
pub const OUT_MSG_MAX: usize = 510;
pub const OUT_TAGS_MAX: usize = 8191;
/// Bytes of web RawSend lines that may wait in ONE connection's command queue (the queue
/// only fills while that connection's socket write is stalled), and in all of them
/// together. Over either budget a line is dropped and logged, like a full queue.
pub const RAWSEND_CONN_BYTE_CAP: usize = 256 * 1024;
pub const RAWSEND_GLOBAL_BYTE_CAP: usize = 32 * 1024 * 1024;
static RAWSEND_BYTES_TOTAL: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Fit a web-originated line into the IRC limits: the message part is cut to
/// OUT_MSG_MAX bytes (on a char boundary — what the server would do anyway); a line
/// whose tag section alone exceeds OUT_TAGS_MAX is refused (`None`), as a server would.
pub fn cap_outbound_line(line: &str) -> Option<String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let (tags, msg) = match line.strip_prefix('@') {
        Some(_) => match line.split_once(' ') {
            Some((t, rest)) => (Some(t), rest),
            None => (None, line), // a bare "@…" with no message part: just cut it
        },
        None => (None, line),
    };
    if let Some(t) = tags {
        if t.len() + 1 > OUT_TAGS_MAX { return None; }
    }
    let msg = if msg.len() > OUT_MSG_MAX {
        let mut end = OUT_MSG_MAX;
        while end > 0 && !msg.is_char_boundary(end) { end -= 1; }
        &msg[..end]
    } else { msg };
    Some(match tags { Some(t) => format!("{} {}", t, msg), None => msg.to_string() })
}

/// One web RawSend line waiting in a connection's command queue, charged against that
/// connection's and the daemon-wide byte budgets until it is dropped (sent, discarded
/// during a reconnect backoff, or lost with the queue).
pub struct QueuedLine {
    line: String,
    conn_bytes: Arc<std::sync::atomic::AtomicUsize>,
}

impl QueuedLine {
    /// Charge `line` (already capped) to the budgets; `None` = over a budget (dropped).
    pub fn charge(line: String, conn_bytes: Arc<std::sync::atomic::AtomicUsize>) -> Option<Self> {
        use std::sync::atomic::Ordering::AcqRel;
        let w = line.len() + 32;
        if conn_bytes.fetch_add(w, AcqRel) + w > RAWSEND_CONN_BYTE_CAP {
            conn_bytes.fetch_sub(w, AcqRel);
            return None;
        }
        if RAWSEND_BYTES_TOTAL.fetch_add(w, AcqRel) + w > RAWSEND_GLOBAL_BYTE_CAP {
            RAWSEND_BYTES_TOTAL.fetch_sub(w, AcqRel);
            conn_bytes.fetch_sub(w, AcqRel);
            return None;
        }
        Some(Self { line, conn_bytes })
    }
    pub fn line(&self) -> &str { &self.line }
}

impl Drop for QueuedLine {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering::AcqRel;
        let w = self.line.len() + 32;
        self.conn_bytes.fetch_sub(w, AcqRel);
        RAWSEND_BYTES_TOTAL.fetch_sub(w, AcqRel);
    }
}

/// A command routed in from the IPC server for a specific conn_id — the
/// inbound half that lets a running connection be driven from outside (the
/// web process, via the daemon's IPC dispatch).
pub enum DaemonCmd {
    /// Forward one raw outbound line (mirrors `ClientMessage::Send` and every
    /// other existing `send_raw()` call site that now originates web-side).
    RawSend(QueuedLine),
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

#[derive(PartialEq, Debug)]
enum SaslState {
    Idle,
    CapLsSent,
    CapReqSent,
    AuthenticateSent,
    Done,
}

/// r4 V3I-N2/N3: a notice for the network's status window, as a prefix-less IRC line
/// forwarded like any other: every web version files a prefix-less NOTICE under "status"
/// (sender "*"), which the browser and the TUI both render — unlike
/// ConnStatus::Reconnecting.reason, which neither displays.
fn status_notice_line(text: &str) -> String {
    let t: String = strip_crlf(text).chars().filter(|c| !c.is_control()).collect();
    format!("NOTICE * :{}", t)
}

/// The terminal Disconnected reason after MAX_SASL_RETRIES SASL failures (shown by every
/// web version as the disconnect reason).
fn sasl_giveup_reason(params: &DialParams) -> String {
    let net: String = strip_crlf(&params.label).chars().filter(|c| !c.is_control()).take(64).collect();
    let net = if net.trim().is_empty() { params.server.clone() } else { net };
    let what = if params.sasl_external {
        "check the client certificate (is its fingerprint registered with the network's services?)"
    } else {
        "check the SASL account name and password"
    };
    format!("SASL authentication failed {} times on {}: {}, then press Connect. Not connecting without SASL.", MAX_SASL_RETRIES, net, what)
}

/// Is `who` our own nick? ASCII case folding only — the same rule as the web side's
/// `same_nick` (agy P2: an rfc1459 fold here, e.g. before/without a CASEMAPPING token,
/// treated a different user `alice{` on an ascii server as us `alice[`). A server always
/// names us with our registered spelling, so nothing real is lost.
fn is_self_nick(who: &str, our: &str) -> bool {
    !who.is_empty() && who.eq_ignore_ascii_case(our)
}

/// `user@host` of a `nick!user@host` prefix ("" for a bare / server prefix).
fn prefix_userhost(prefix: &Option<String>) -> &str {
    prefix.as_deref().and_then(|p| p.split_once('!')).map_or("", |(_, uh)| uh)
}

/// A NICK/CHGHOST line is OURS when its source nick is us and its source carries the
/// user (ident) part of the user@host we learned, or we have not learned one yet (pre-JOIN
/// legacy accept, as on the web side). A bare `:nick` source (no user@host) never matches
/// a learned identity. The HOST is deliberately not compared: a server can change it
/// without a CHGHOST (a services vhost/cloak announced only by numeric 396, or no chghost
/// cap), and rejecting our own next NICK then would desync our nick from the server's.
fn self_source_matches(who: &str, src_uh: &str, our_nick: &str, our_uh: &str) -> bool {
    is_self_nick(who, our_nick) && (our_uh.is_empty() || same_ident(src_uh, our_uh))
}

/// Same ident (the `user` of `user@host`, case-insensitive); an empty source never matches.
pub fn same_ident(src_uh: &str, our_uh: &str) -> bool {
    let ident = |uh: &str| uh.split_once('@').map(|(u, _)| u.to_string());
    match (ident(src_uh), ident(our_uh)) {
        (Some(a), Some(b)) => !a.is_empty() && a.eq_ignore_ascii_case(&b),
        _ => false,
    }
}

/// The dialed host as carried in SessionSync: only a plausible hostname (bounded, no
/// JSON-escaping or control bytes), else "" (= not reported).
pub(crate) fn clean_dial_server(s: &str) -> String {
    if s.is_empty() || s.len() > 255 { return String::new(); }
    if !s.bytes().all(|b| b > 0x20 && b != b'"' && b != b'\\' && b != 0x7f) { return String::new(); }
    s.to_string()
}

/// CAP negotiation is complete (CAP END may be sent): every CAP REQ answered and no SASL
/// exchange in flight.
fn cap_negotiation_done(outstanding: u32, sasl: &SaslState) -> bool {
    outstanding == 0 && !matches!(sasl, SaslState::CapLsSent | SaslState::CapReqSent | SaslState::AuthenticateSent)
}

/// Whether a CAP ACK/NAK list names `cap` (exact token, ignoring a `-` disable prefix and
/// any `=value`), so e.g. `sasl` is not matched by a hypothetical `draft/sasl-ir`.
fn cap_list_has(list: &str, cap: &str) -> bool {
    list.split_whitespace().any(|t| t.trim_start_matches('-').split('=').next() == Some(cap))
}

// Leave room for the existing 52 KiB channel list in a 64 KiB IPC frame.
const REG_CAPS_JSON_BUDGET: usize = 6 * 1024;
// Enabled names need no values; keep the added snapshot within the IPC frame budget.
const REG_ENABLED_CAPS_JSON_BUDGET: usize = 1024;
const REG_ISUPPORT_JSON_BUDGET: usize = 2 * 1024;
const REG_CAPS_MAX: usize = 256;

fn registration_key(token: &str) -> &str {
    token.trim_start_matches('-').split('=').next().unwrap_or(token)
}

/// Keep original spelling/values, but only one current value per token. Never truncate a
/// value into a different meaning. Overflow makes the entire classification restrictive.
fn store_registration_token(tokens: &mut Vec<String>, token: &str, budget: usize, count: usize) -> bool {
    let mut next = tokens.clone();
    next.retain(|t| !registration_key(t).eq_ignore_ascii_case(registration_key(token)));
    next.push(token.to_string());
    if next.len() > count || serde_json::to_vec(&next).map_or(true, |v| v.len() > budget) { return false; }
    *tokens = next;
    true
}

/// Allocate before CAP so pre-001 facts and the registered session share an epoch.
/// A random process seed avoids reusing a counter sequence after daemon restart;
/// the atomic counter guarantees distinct epochs for every socket in this process.
fn next_session_epoch() -> u64 {
    use std::sync::{OnceLock, atomic::{AtomicU64, Ordering}};
    static NEXT: OnceLock<AtomicU64> = OnceLock::new();
    let next = NEXT.get_or_init(|| AtomicU64::new(rand::thread_rng().gen()));
    loop {
        let epoch = next.fetch_add(1, Ordering::Relaxed);
        if epoch != 0 { return epoch; }
    }
}

/// Called ONLY at the server socket read boundary, before forwarding a line. RawSend and
/// Attach replay never enter here. A fresh run_loop creates fresh facts on every dial.
fn note_registration_input(facts: &mut crate::ipc::RegistrationFacts, p: &crate::ircproto::IrcLine, registered: bool) {
    match p.command.as_str() {
        "CAP" => {
            let sub = p.params.get(1).map(String::as_str).unwrap_or("");
            let multiline = p.params.get(2).map(String::as_str) == Some("*");
            let caps = if multiline { p.params.get(3) } else { p.params.last() }.map(String::as_str).unwrap_or("");
            if matches!(sub, "LS" | "NEW") {
                facts.behind_bouncer |= crate::ircproto::classify_avatar_registration(p.prefix.as_deref(), caps, &[], false).behind_bouncer;
            }
            if (sub == "LS" && !registered && !facts.cap_ls_done) || sub == "NEW" {
                facts.cap_ls_done |= sub == "LS" && !multiline;
                for cap in caps.split_whitespace() {
                    if !store_registration_token(&mut facts.caps, cap, REG_CAPS_JSON_BUDGET, REG_CAPS_MAX) { facts.truncated = true; }
                }
            } else if sub == "DEL" {
                facts.caps.retain(|c| !caps.split_whitespace().any(|t| registration_key(t).eq_ignore_ascii_case(registration_key(c))));
                facts.enabled_caps.retain(|c| !caps.split_whitespace().any(|t| registration_key(t).eq_ignore_ascii_case(c)));
                // The sticky bouncer evidence survives DEL, just as it does in the web.
            } else if sub == "ACK" {
                // This boundary also sees ACKs for the web's mid-session CAP REQs.
                for cap in caps.split_whitespace() {
                    let name = registration_key(cap);
                    if cap.starts_with('-') {
                        facts.enabled_caps.retain(|c| !c.eq_ignore_ascii_case(name));
                    } else if !store_registration_token(&mut facts.enabled_caps, name, REG_ENABLED_CAPS_JSON_BUDGET, REG_CAPS_MAX) {
                        facts.truncated = true;
                    }
                }
            }
        }
        "001" | "004" => {
            facts.behind_bouncer |= crate::ircproto::classify_avatar_registration(p.prefix.as_deref(), "", &[], false).behind_bouncer;
            if let Some(name) = &p.prefix {
                if serde_json::to_vec(name).map_or(false, |v| v.len() <= 512) {
                    facts.server_name = Some(name.clone());
                } else { facts.truncated = true; }
            }
        }
        "005" => {
            facts.behind_bouncer |= crate::ircproto::classify_avatar_registration(None, "", &p.params, false).behind_bouncer;
            let mut saw_casemapping = false;
            for token in &p.params {
                let key = token.split('=').next().unwrap_or(token);
                // CaseMapping::from_isupport takes the first mapping on each 005.
                if key.eq_ignore_ascii_case("CASEMAPPING") && token.contains('=') {
                    if saw_casemapping { continue; }
                    saw_casemapping = true;
                }
                // Match what the web actually consumes: bare CLIENTTAGDENY/CASEMAPPING
                // and -CASEMAPPING are ignored there and must not erase an earlier value.
                let used = key.eq_ignore_ascii_case("BOUNCER_NETID") || token.eq_ignore_ascii_case("-BOUNCER_NETID")
                    || token.eq_ignore_ascii_case("-CLIENTTAGDENY")
                    || (token.contains('=') && (key.eq_ignore_ascii_case("CLIENTTAGDENY") || key.eq_ignore_ascii_case("CASEMAPPING")));
                if used {
                    if !store_registration_token(&mut facts.isupport, token, REG_ISUPPORT_JSON_BUDGET, 3) { facts.truncated = true; }
                }
            }
        }
        _ => {}
    }
}

/// The daemon's own narrow per-connection state — nick + which channels we
/// believe we're in (case-folded names only) + the real socket writer. No
/// topics/names/keys/message log; that display-layer state stays web-side.
struct DaemonConn {
    nick: String,
    /// Channels we're in: CASEMAPPING fold → the server's own spelling (from the JOIN
    /// echo). SessionSync carries the spellings, so a re-Attached web resyncs (NAMES/
    /// WHO/MODE/TOPIC) the real channel — on an ascii server the rfc1459-folded name it
    /// used to get (`#foo{bar}` for `#Foo[Bar]`) is a different, usually empty, channel.
    channels: HashMap<String, String>,
    /// Mirror of run_connection's persisted CASEMAPPING, for SessionSync.
    casemapping: CaseMapping,
    /// r7/r8: the server's CHANMODES / PREFIX (005), for walking mode parameters to the right
    /// key — and, r8, in every SessionSync so a re-Attached web knows them too.
    chanmodes: ChanModes,
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
    registration: crate::ipc::RegistrationFacts,
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
    // codex P2 irc_daemon.rs:460 / agy P2 + integrator decision (FAIL CLOSED): SASL that
    // keeps failing must neither loop forever (the old "disable" only cleared EXTERNAL, so
    // PLAIN retried endlessly against a wrong password / dead SASL service — account
    // lockouts) nor fall back to an UNAUTHENTICATED registration (that exposes the real host
    // before any cloak and joins as an unidentified nick, and is exactly what a hostile
    // network or a MITM could provoke). After MAX_SASL_RETRIES failures the connection
    // STOPS with a clear Disconnected reason; a manual Connect (a fresh Dial) starts over.
    // EXTERNAL → PLAIN (both configured) is the one allowed step, logged and announced.
    let original_sasl_plain = params.sasl_plain.clone();
    // Channels the daemon has joined, persisted ACROSS its own reconnects so a
    // ping-timeout/netsplit re-join restores EVERY channel — not just auto_join
    // (findings #3/#8: a manually-joined channel was silently dropped on a
    // daemon-internal reconnect). run_loop seeds from + updates this set.
    // Keyed by the irc_lower fold (membership matching), value = the server's own
    // spelling from the JOIN echo, which is what gets re-JOINed: on an ascii-casemapping
    // server (Unreal, InspIRCd 4, Ergo) the folded `#foo{bar}^` is a DIFFERENT channel
    // from `#Foo[Bar]~`.
    let mut persistent_channels: HashMap<String, String> = HashMap::new();
    // Channel keys learned during the session (a keyed outbound JOIN once the server confirms
    // the self-JOIN, 324 / MODE +k for a tracked channel), keyed by irc_lower and kept across
    // this daemon's own reconnects.
    // DialParams.channel_keys is a snapshot from Dial time, so a channel joined or keyed
    // AFTER the Dial used to rejoin keyless after a ping timeout / netsplit / KILL.
    let mut learned_keys: HashMap<String, String> = HashMap::new();
    // r4 (codex P2 irc_daemon.rs:1361): channels the USER parted during this Dial (an
    // outbound PART through RawSend; joined again = forgotten), folded → spelling, kept
    // across this daemon's own reconnects. The Dial-time DialParams.auto_join is never
    // refreshed while the connection lives, so a parted auto-join channel used to be
    // re-joined on every ping timeout / netsplit until the next fresh Dial — although the
    // web had already removed it from the saved auto-join list (PartChannel / raw /part).
    let mut user_parted: HashMap<String, String> = HashMap::new();
    // The server's CASEMAPPING (005), kept across reconnects like the two maps above,
    // whose keys are folded with it.
    let mut casemapping = CaseMapping::default();

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
        let result = do_connect(&conn_id, &params, &emit, &mut cmd_rx, &mut stopped, &mut registered_ok, &mut persistent_channels, &mut learned_keys, &mut user_parted, &mut casemapping, &web_version).await;
        let uptime = attempt_start.elapsed();
        // If this attempt reached registration, the connection genuinely worked —
        // reset the SASL-failure counter and re-arm SASL for next time (W5: an
        // auto-disable must not persist forever across later error-path reconnects).
        if registered_ok {
            sasl_failures = 0;
            params.sasl_external = original_sasl_external;
            params.sasl_plain = original_sasl_plain.clone();
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
                    params.sasl_plain = original_sasl_plain.clone();
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
                let mut reason = e.to_string();
                if msg.starts_with("SASL_RETRY:") {
                    sasl_failures += 1;
                    if sasl_failures >= MAX_SASL_RETRIES {
                        if params.sasl_external && params.sasl_plain.is_some() && params.tls {
                            // Both configured: PLAIN gets its own MAX_SASL_RETRIES attempts.
                            warn!("[{}] SASL EXTERNAL failed {} times — trying SASL PLAIN (also configured) next", conn_id, sasl_failures);
                            params.sasl_external = false;
                            sasl_failures = 0;
                            delay = RECONNECT_BASE;
                            reason = format!("SASL EXTERNAL (client certificate) failed {} times — trying SASL PLAIN next", MAX_SASL_RETRIES);
                            // r4 V3I-N3: also in the status window (no client shows the reason).
                            emit(IpcMessage::RawLine {
                                conn_id: conn_id.clone(), line: status_notice_line(&format!("CryptIRC: {}", reason)),
                                replayed: false, backlog: false, recv_ts: chrono::Utc::now().timestamp(), seq: 0,
                            });
                        } else {
                            let why = sasl_giveup_reason(&params);
                            warn!("[{}] SASL failed {} times — not reconnecting until the user presses Connect", conn_id, MAX_SASL_RETRIES);
                            emit(IpcMessage::ConnStatus {
                                conn_id: conn_id.clone(),
                                state: ConnLifecycle::Disconnected { reason: why },
                            });
                            return;
                        }
                    } else if sasl_failures == 1 {
                        let advice = if params.sasl_external {
                            "SASL EXTERNAL rejected by server — client certificate not registered with this network."
                        } else {
                            "SASL authentication rejected — check SASL account/password."
                        };
                        info!("[{}] SASL failure 1/{}: {}. Fast retry for DNS cycling", conn_id, MAX_SASL_RETRIES, advice);
                        delay = RECONNECT_BASE;
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
                        reason,
                    },
                });
            }
        }

        // Let a Drop arriving DURING the backoff wait interrupt it immediately
        // instead of waiting out the full delay before honoring it. The sleep is
        // JITTERED (±50%) so many connections dropped by one network blip don't
        // re-dial in lockstep (thundering-herd reconnect storm).
        // r5: a RawSend (the user typed /join or /part during the outage) is noted and the
        // wait goes on — it used to end the wait, so every line typed meanwhile re-dialed at
        // once and the exponential backoff never grew.
        let wake_at = Instant::now() + jitter(delay);
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(wake_at) => break,
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
                        Some(DaemonCmd::Reconnect) => { info!("[{}] Reconnect during backoff", conn_id); break; }
                        // Re-arm SASL for the next attempt (and dial it now, as before).
                        Some(DaemonCmd::RearmSasl) => {
                            params.sasl_external = original_sasl_external;
                            params.sasl_plain = original_sasl_plain.clone();
                            sasl_failures = 0;
                            break;
                        }
                        // No live connection to send to while backing off — the line can't go
                        // out. F2: log it (not silent). The web-side connected-check already
                        // told the user "not connected"; this makes the drop observable here.
                        // r5 (codex P2 irc_daemon.rs:717): a /part or /join the user made meanwhile
                        // still takes effect at the next registration (the web has already updated the
                        // saved auto-join list): PART → not re-joined, JOIN → joined (with its key).
                        Some(DaemonCmd::RawSend(q)) => {
                            if apply_backoff_part_join(q.line(), &mut persistent_channels, &mut user_parted, &mut learned_keys, casemapping) {
                                info!("[{}] /join or /part during reconnect noted — applied at the next registration", conn_id);
                            } else {
                                warn!("[{}] dropping web RawSend — connection is down (reconnecting)", conn_id);
                            }
                        }
                        // Sender side gone (server task exited) — nothing more will
                        // ever arrive for this conn_id; stop rather than spin forever.
                        None => return,
                    }
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
    persistent_channels: &mut HashMap<String, String>,
    learned_keys: &mut HashMap<String, String>,
    user_parted: &mut HashMap<String, String>,
    casemapping: &mut CaseMapping,
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
            run_loop(conn_id, params, emit, stream, cmd_rx, stopped, registered_out, persistent_channels, learned_keys, user_parted, casemapping, web_version).await
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
            run_loop(conn_id, params, emit, tls, cmd_rx, stopped, registered_out, persistent_channels, learned_keys, user_parted, casemapping, web_version).await
        }
    } else {
        let tcp = dial_tcp().await?;
        run_loop(conn_id, params, emit, tcp, cmd_rx, stopped, registered_out, persistent_channels, learned_keys, user_parted, casemapping, web_version).await
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
    persistent_channels: &mut HashMap<String, String>,
    learned_keys: &mut HashMap<String, String>,
    user_parted: &mut HashMap<String, String>,
    casemapping: &mut CaseMapping,
    web_version: &Arc<WebVersionCell>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    F: Fn(IpcMessage) + Send + Sync + Clone + 'static,
{
    let (read_half, write_half) = tokio::io::split(stream);
    let conn = Arc::new(Mutex::new(DaemonConn {
        // The same CR/LF/NUL-stripped form the registration NICK below sends, so the
        // pre-001 433 retry (which builds on c.nick) can never carry a raw newline.
        nick: strip_crlf(&params.nick),
        channels: HashMap::new(),
        casemapping: *casemapping,
        chanmodes: ChanModes::default(),
        writer: Box::new(write_half),
        message_tags: false,
        echo_message_enabled: false,
        self_userhost: String::new(),
        registration: crate::ipc::RegistrationFacts { session_epoch: next_session_epoch(), ..Default::default() },
    }));

    // codex P2 main.rs:6834 / agy P2: the endpoint this connection really dials, so a
    // re-Attached web takes the connection's network identity from it instead of from the
    // (editable) saved config. Bounded + filtered like every other SessionSync string.
    let dial_server = clean_dial_server(&params.server);
    let dial_port = if dial_server.is_empty() { 0 } else { params.port };
    let sync = |c: &DaemonConn, registered: bool, connected: bool, lag_ms: Option<u64>| {
        emit(IpcMessage::SessionSync {
            conn_id: conn_id.to_string(),
            nick: c.nick.clone(),
            channels: c.channels.values().cloned().collect(),
            registered,
            connected,
            lag_ms,
            message_tags: c.message_tags,
            echo_message_enabled: c.echo_message_enabled,
            self_userhost: c.self_userhost.clone(),
            casemapping: c.casemapping.token().to_string(),
            registration: Some(c.registration.clone()),
            dial_server: dial_server.clone(),
            chanmodes: c.chanmodes.isupport(),
            dial_port,
        });
    };
    let fwd = |line: &str| emit(IpcMessage::RawLine {
        conn_id: conn_id.to_string(), line: line.to_string(), replayed: false,
        backlog: false, recv_ts: chrono::Utc::now().timestamp(), seq: 0,
    });

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
    // r4 V3I-N2: unchanged behaviour (an open product question), but visible in the status
    // window, not only in the irc_core journal.
    if params.sasl_plain.is_some() && !params.sasl_external && !params.tls {
        fwd(&status_notice_line("CryptIRC: SASL PLAIN is configured but TLS is off — the SASL password is not sent over an unencrypted connection; connecting WITHOUT SASL."));
    }
    let mut sasl_state = SaslState::Idle;
    // agy P2 irc_daemon.rs:900-945: general caps and `sasl` are requested in two CAP REQs
    // (so one NAKed cap can't take SASL down with it). CAP END is sent exactly once, when
    // every CAP REQ has been answered (ACK/NAK) AND no SASL exchange is in flight — an
    // unconditional CAP END on any NAK used to abort an in-flight SASL login, and a 903
    // used to end negotiation before the other REQ was answered.
    let mut cap_reqs_outstanding: u32 = 0;
    let mut cap_end_sent = false;
    let mut available_caps: Vec<String> = Vec::new();
    let mut last_pong = Instant::now();
    // Set when a heartbeat PING is outstanding; cleared by any PONG in our private
    // `hb-<ts>` namespace (see the PONG handler). A foreign PONG can't clear it, so it
    // can't mask a real timeout.
    let mut ping_out = false;
    let mut nick_retries = 0u32;
    let mut last_ctcp_reply: Option<Instant> = None;
    // Keys from outbound JOINs awaiting the server's self-JOIN confirmation (see RawSend).
    let mut pending_keys: HashMap<String, String> = HashMap::new();

    let efnet_named = params.label.to_lowercase().contains("efnet") || params.server.to_lowercase().contains("efnet");
    // r5 (codex P2 irc_daemon.rs:906, integrator decision): with SASL configured (PLAIN or
    // EXTERNAL) CAP is NEVER skipped — a display label / host substring must not turn the
    // configured authentication off. The EFnet-style CAP skip applies only without SASL; a
    // real EFnet server then answers CAP with 421 and the SASL-failure rule (3 attempts, then
    // "not connecting without SASL") applies, as for any server without SASL.
    let sasl_configured = params.sasl_external || params.sasl_plain.is_some();
    let efnet = efnet_named && !sasl_configured;
    if efnet {
        info!("[{}] EFnet detected (label='{}' server='{}') — IRCv3 caps disabled", conn_id, params.label, params.server);
    } else if efnet_named {
        info!("[{}] EFnet-style name (label='{}' server='{}') but SASL is configured — negotiating CAP/SASL anyway", conn_id, params.label, params.server);
        fwd(&status_notice_line("CryptIRC: this network looks like EFnet (no IRCv3 CAP/SASL), but SASL is configured, so CryptIRC negotiates SASL anyway and will not connect without it. Remove the SASL settings if this really is EFnet."));
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

    // CANCEL-SAFE line reader: the partial line lives in `reader`, not in the select!
    // branch future, so a heartbeat tick or a web command winning the race while a line
    // is half-received no longer throws its head away (whose tail would then be parsed
    // as a forged standalone line — see ircproto::CappedLineReader).
    let mut reader = CappedLineReader::new(BufReader::new(read_half));
    let mut registered = false;
    let mut ping_ticker = tokio::time::interval(PING_INTERVAL);
    let mut inbound_tokens: f64 = INBOUND_RATE_BURST;
    let mut inbound_refill_at = Instant::now();
    // Absolute deadline to reach 001. The per-line READ_TIMEOUT resets on every
    // line, and the heartbeat is gated off pre-registration — so a server that
    // slow-drips CAP/SASL forever would otherwise pin this task un-registered
    // with no reconnect ever firing. Disarmed the instant we register.
    let reg_timer = sleep(REG_TIMEOUT);
    tokio::pin!(reg_timer);
    // Liveness deadline: no complete line for READ_TIMEOUT → reconnect. Lives OUTSIDE
    // the select! (reset after every line) so other branches winning can't keep
    // re-arming it the way the old per-iteration `timeout()` wrapper did.
    let read_deadline = sleep(READ_TIMEOUT);
    tokio::pin!(read_deadline);

    loop {
        // Inbound token bucket (#31): how long to hold off before reading the next
        // line. Computed from state WITHOUT mutating it; the token is only charged once
        // a line has actually been read (below), so a read cancelled by another branch
        // costs nothing and the wait simply shrinks on the next iteration.
        let throttle = {
            let avail = (inbound_tokens
                + Instant::now().duration_since(inbound_refill_at).as_secs_f64() * INBOUND_RATE_REFILL)
                .min(INBOUND_RATE_BURST);
            if avail < 1.0 { Some(Duration::from_secs_f64((1.0 - avail) / INBOUND_RATE_REFILL)) } else { None }
        };
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
                    Some(DaemonCmd::RawSend(queued)) => {
                        // r5: a /join or /part that arrives while this attempt is still
                        // registering would be refused by the server (451) and lost — or go
                        // out before SASL completed. Like one made during the backoff, it is
                        // applied to the channels joined right after registration instead.
                        if !registered && apply_backoff_part_join(queued.line(), persistent_channels, user_parted, learned_keys, *casemapping) {
                            info!("[{}] /join or /part before registration noted — applied when registered", conn_id);
                            continue;
                        }
                        // Candidate keys only: promoted to learned_keys when the server
                        // confirms the self-JOIN (a mistyped key must never override the
                        // configured one on the next rejoin).
                        learn_join_keys_cm(queued.line(), &mut pending_keys, *casemapping);
                        note_user_part_join(queued.line(), user_parted, *casemapping);
                        // Defense-in-depth: the web is trusted to have stripped
                        // interior CR/LF, but the daemon is the last barrier before
                        // the socket and can never be patched — re-enforce it here so
                        // command injection is structurally impossible at the boundary.
                        conn.lock().await.send_raw(&sanitize_outbound(queued.line())).await?;
                        // (`queued` drops here, releasing its RawSend byte budget.)
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

            _ = &mut read_deadline => {
                warn!("[{}] No data from server for {}s, triggering reconnect", conn_id, READ_TIMEOUT.as_secs());
                return Err(anyhow::anyhow!("Read timeout"));
            }

            // Both awaits in here are cancel-safe: `sleep` holds no state, and
            // `reader.next_line()` keeps any partial line inside `reader`.
            res = async {
                if let Some(wait) = throttle { sleep(wait).await; }
                reader.next_line().await
            } => {
                // Charge the token for the line just read, and re-arm the liveness deadline.
                let now = Instant::now();
                inbound_tokens = (inbound_tokens
                    + now.duration_since(inbound_refill_at).as_secs_f64() * INBOUND_RATE_REFILL)
                    .min(INBOUND_RATE_BURST) - 1.0;
                inbound_refill_at = now;
                read_deadline.as_mut().reset(now + READ_TIMEOUT);
                let line = match res {
                    Ok(CappedLine::Line(l)) => l,
                    Ok(CappedLine::Eof) => return Ok(()),
                    Ok(CappedLine::Oversized) => {
                        warn!("[{}] Dropping oversized IRC line (> {} bytes)", conn_id, MAX_IRC_LINE_LEN);
                        continue;
                    }
                    Err(e) => return Err(e.into()),
                };
                let line = line.trim_end_matches(['\r', '\n']).to_string();
                if line.is_empty() { continue; }
                if line.len() > MAX_IRC_LINE_LEN {
                    warn!("[{}] Dropping oversized IRC line ({} bytes)", conn_id, line.len());
                    continue;
                }

                let p = parse_irc(&line);
                if matches!(p.command.as_str(), "CAP" | "001" | "004" | "005") {
                    let mut c = conn.lock().await;
                    let before = c.registration.clone();
                    note_registration_input(&mut c.registration, &p, registered);
                    if c.registration != before { sync(&c, registered, true, None); }
                }

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
                                    cap_reqs_outstanding += 1;
                                }
                                if use_sasl && available_caps.iter().any(|c| c == "sasl") {
                                    conn.lock().await.send_raw("CAP REQ :sasl\r\n").await?;
                                    cap_reqs_outstanding += 1;
                                    sasl_state = SaslState::CapReqSent;
                                } else if use_sasl {
                                    // Fail closed (integrator decision): SASL is configured, so
                                    // never register without it — a server (or a MITM) that hides
                                    // the cap counts as a SASL failure (3 strikes, then stop).
                                    warn!("[{}] SASL configured but the server offers no sasl cap — not registering without SASL", conn_id);
                                    fwd(&line);
                                    return Err(anyhow::anyhow!("SASL_RETRY: the server does not offer SASL"));
                                }
                                available_caps.clear();
                                // Nothing requested (and no SASL): end negotiation now.
                                if !cap_end_sent && !registered && cap_negotiation_done(cap_reqs_outstanding, &sasl_state) {
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                    cap_end_sent = true;
                                }
                            }
                            "ACK" => {
                                info!("[{}] CAP ACK: {}", conn_id, caps);
                                // One reply per CAP REQ; only its final line counts.
                                if !is_multiline { cap_reqs_outstanding = cap_reqs_outstanding.saturating_sub(1); }
                                {
                                    let mut c = conn.lock().await;
                                    if caps.contains("message-tags") { c.message_tags = true; }
                                    if caps.contains("echo-message") { c.echo_message_enabled = true; }
                                }
                                if cap_list_has(&caps, "sasl") && sasl_state == SaslState::CapReqSent {
                                    let method = match &sasl_method {
                                        Some(SaslMethod::External) => "EXTERNAL",
                                        Some(SaslMethod::Plain { .. }) => "PLAIN",
                                        None => "PLAIN",
                                    };
                                    conn.lock().await.send_raw(&format!("AUTHENTICATE {}\r\n", method)).await?;
                                    sasl_state = SaslState::AuthenticateSent;
                                }
                                if !cap_end_sent && !registered && cap_negotiation_done(cap_reqs_outstanding, &sasl_state) {
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                    cap_end_sent = true;
                                }
                            }
                            "NAK" => {
                                warn!("[{}] CAP NAK: {}", conn_id, caps);
                                if !is_multiline { cap_reqs_outstanding = cap_reqs_outstanding.saturating_sub(1); }
                                // A NAKed `sasl` REQ is a SASL failure (fail closed: never register
                                // without it; the web shows "SASL capability rejected" from this
                                // forwarded line). A NAK of the OTHER REQ leaves an in-flight SASL
                                // exchange alone.
                                if use_sasl && cap_list_has(&caps, "sasl") && sasl_state == SaslState::CapReqSent {
                                    fwd(&line);
                                    return Err(anyhow::anyhow!("SASL_RETRY: the server rejected the SASL capability"));
                                }
                                if !cap_end_sent && !registered && cap_negotiation_done(cap_reqs_outstanding, &sasl_state) {
                                    conn.lock().await.send_raw("CAP END\r\n").await?;
                                    cap_end_sent = true;
                                }
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
                                    cap_reqs_outstanding += 1;
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
                            // "+" (EXTERNAL / empty) goes as-is; a base64 payload is split
                            // into <=400-byte AUTHENTICATE lines per the SASL spec (a long
                            // account/password used to go out as one line and fail with 905).
                            let chunks = if response == "+" { vec![response] } else { sasl_chunks(&response) };
                            let mut c = conn.lock().await;
                            for chunk in chunks {
                                c.send_raw(&format!("AUTHENTICATE {}\r\n", chunk)).await?;
                            }
                        }
                        fwd(&line);
                    }

                    "903" => {
                        info!("[{}] SASL 903: authentication successful", conn_id);
                        sasl_state = SaslState::Done;
                        // Only once the other CAP REQ is answered too (see cap_reqs_outstanding).
                        if !cap_end_sent && !registered && cap_negotiation_done(cap_reqs_outstanding, &sasl_state) {
                            conn.lock().await.send_raw("CAP END\r\n").await?;
                            cap_end_sent = true;
                        }
                        fwd(&line);
                    }
                    "902" | "904" | "905" | "906" | "907" => {
                        let reason = p.params.last().cloned().unwrap_or_else(|| "SASL failed".into());
                        // Only a failure of OUR OWN in-flight, pre-registration SASL exchange
                        // cycles the socket. The same numerics after 001 — a user's
                        // `/quote AUTHENTICATE …` answered with 907/906, a perform line, a
                        // bouncer relaying upstream numerics, a hostile server — used to tear
                        // a healthy connection down and (because the attempt had registered,
                        // resetting sasl_failures) reconnect every 5 s forever. Now they are
                        // just forwarded for the web to display.
                        let in_our_exchange = !registered && use_sasl
                            && matches!(sasl_state, SaslState::CapReqSent | SaslState::AuthenticateSent);
                        if in_our_exchange {
                            warn!("[{}] SASL {} FAILED: {}", conn_id, p.command, reason);
                            fwd(&line);
                            return Err(anyhow::anyhow!("SASL_RETRY: {}", reason));
                        }
                        info!("[{}] SASL {} outside our own SASL exchange — forwarded, connection kept", conn_id, p.command);
                        fwd(&line);
                    }
                    "900" => {
                        fwd(&line);
                    }

                    // ISUPPORT: adopt the server's CASEMAPPING (codex P2 :144). Every map
                    // keyed by a channel fold is re-keyed when it changes (first time on
                    // a non-rfc1459 server; or a different server of the network after a
                    // reconnect). On a collision the first entry wins — the two names were
                    // already one entry under the old fold.
                    "005" => {
                        if conn.lock().await.chanmodes.learn(&p.params) {
                            let c = conn.lock().await;
                            sync(&c, registered, true, None);   // r8: the web learns them too
                        }
                        if let Some(new_cm) = CaseMapping::from_isupport(&p.params) {
                            if new_cm != *casemapping {
                                info!("[{}] server CASEMAPPING is {:?} (was {:?})", conn_id, new_cm, *casemapping);
                                *casemapping = new_cm;
                                // Spellings by OLD fold, so key maps (whose values are keys,
                                // not names) can be re-folded from the real channel name.
                                let mut spelling: HashMap<String, String> = persistent_channels.clone();
                                for (k, v) in conn.lock().await.channels.iter() {
                                    spelling.entry(k.clone()).or_insert_with(|| v.clone());
                                }
                                let refold_names = |m: &mut HashMap<String, String>| {
                                    for (_, v) in std::mem::take(m) { m.entry(new_cm.fold(&v)).or_insert(v); }
                                };
                                let refold_keys = |m: &mut HashMap<String, String>| {
                                    for (k, v) in std::mem::take(m) {
                                        let nk = new_cm.fold(spelling.get(&k).map_or(k.as_str(), |s| s.as_str()));
                                        m.entry(nk).or_insert(v);
                                    }
                                };
                                refold_keys(learned_keys);
                                refold_keys(&mut pending_keys);
                                refold_names(persistent_channels);
                                refold_names(user_parted);
                                let mut c = conn.lock().await;
                                refold_names(&mut c.channels);
                                c.casemapping = new_cm;
                                sync(&c, registered, true, None);
                            }
                        }
                        fwd(&line);
                    }

                    "001" => {
                        // #29 (carried over): idempotent — ignore a replayed 001.
                        if registered { fwd(&line); continue; }
                        // r4 V3I-N2 (w3-irc MED, integrator decision: fail closed like "no sasl
                        // cap" / NAK): SASL is configured and CAP LS was sent, but the server
                        // registered us on NICK/USER without SASL completing — it ignored CAP
                        // (421 / no reply), or a MITM dropped our CAP LS. Registering would
                        // expose the real host and an unidentified nick: count it as a SASL
                        // failure (3 strikes → the terminal Disconnected). The 001 is not
                        // forwarded (the web must not show the network as connected).
                        if use_sasl && !efnet && !matches!(sasl_state, SaslState::Done) {
                            warn!("[{}] server registered the connection before SASL completed (state {:?}) — refusing", conn_id, sasl_state);
                            let _ = conn.lock().await.send_raw("QUIT :SASL authentication did not complete\r\n").await;
                            return Err(anyhow::anyhow!("SASL_RETRY: the server registered the connection without completing SASL"));
                        }
                        registered = true;
                        // Tell run_connection this attempt genuinely reached the
                        // network — it uses this to reset SASL-failure state / re-arm.
                        *registered_out = true;
                        last_pong = Instant::now();
                        let actual_nick = {
                            let mut c = conn.lock().await;
                            if let Some(real) = p.params.first() {
                                if !real.is_empty() && real.as_str() != "*" {
                                    // Bounded + filtered (serialized in every SessionSync).
                                    match clean_nick(real) {
                                        Some(n) => c.nick = n,
                                        None => warn!("[{}] 001 carried an implausible nick ({} bytes) — keeping {:?}", conn_id, real.len(), c.nick),
                                    }
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
                        let cm = *casemapping;
                        let auto_lc: HashSet<String> =
                            params.auto_join.iter().map(|c| cm.fold(c)).collect();
                        for ch in &params.auto_join {
                            let safe = strip_crlf(ch);
                            // r4: not a channel the user parted since the Dial.
                            if user_parted.contains_key(&cm.fold(&safe)) { continue; }
                            if !safe.is_empty() {
                                // Fold-tolerant: the web stores keys under to_lowercase(),
                                // this side matches channels by irc_lower — see
                                // channel_key_lookup. (A `#Key[X]` used to rejoin keyless.)
                                let key = learned_keys.get(&cm.fold(&safe))
                                    .or_else(|| channel_key_lookup_cm(&params.channel_keys, &safe, cm));
                                let cmd = if let Some(key) = key {
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
                        // Re-JOIN under the server's own spelling (the map's value), never
                        // the irc_lower key: on an ascii-casemapping server the folded
                        // name is a different channel.
                        for (lc, name) in persistent_channels.iter() {
                            if auto_lc.contains(lc) || user_parted.contains_key(lc) { continue; }
                            let safe = strip_crlf(name);
                            if safe.is_empty() { continue; }
                            // Session-learned key first (newest), then the Dial-time config.
                            let key = learned_keys.get(lc)
                                .or_else(|| channel_key_lookup_cm(&params.channel_keys, &safe, cm));
                            let cmd = if let Some(key) = key {
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
                            c.send_raw(&format!("NICK {}\r\n", strip_crlf(&new_nick))).await?;
                        }
                        // Post-registration: no daemon action (a manual /nick
                        // collision is surfaced by the web side re-parsing this
                        // forwarded line — no silent nick switch).
                        fwd(&line);
                    }

                    "JOIN" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut joined: Option<(String, String)> = None;
                        // Whether this JOIN changed our own state, i.e. whether a SessionSync
                        // is owed (codex P2 ipc_server.rs:862: a repeated self-JOIN of an
                        // already-tracked channel changes nothing and no longer produces a
                        // full snapshot). Deferred until AFTER the line is forwarded — see the
                        // comment at the emit below.
                        let mut changed = false;
                        let cm = *casemapping;
                        {
                            let mut c = conn.lock().await;
                            if is_self_nick(&who, &c.nick) {
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
                                        if let Some(u) = clean_userhost(uh) {
                                            if c.self_userhost != u { c.self_userhost = u; changed = true; }
                                        }
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
                                        let lc = cm.fold(chan);
                                        // Count- and size-bounded (admit_tracked); a channel past the
                                        // budget is still re-joined after a reconnect (`joined`).
                                        if c.channels.get(&lc).map(String::as_str) != Some(chan.as_str())
                                            && admit_tracked(&c.channels, &lc, chan)
                                        {
                                            c.channels.insert(lc.clone(), chan.to_string());
                                            changed = true;
                                        }
                                        joined = Some((lc, chan.to_string()));
                                    }
                                }
                            }
                        }
                        if let Some((lc, name)) = joined {
                            if let Some(k) = pending_keys.remove(&lc) {
                                remember_key_cm(learned_keys, &name, &k, cm);
                            }
                            // Bounded: a hostile server can't force unbounded growth by
                            // spoofing self-JOIN prefixes to arbitrary channel names.
                            // (Updating an already-tracked channel's spelling is fine.)
                            if persistent_channels.len() < MAX_TRACKED_CHANNELS || persistent_channels.contains_key(&lc) {
                                persistent_channels.insert(lc, name);
                            }
                        }
                        // Forward the JOIN BEFORE the state snapshot. Emitting SessionSync
                        // first meant the web process learned about the channel from the
                        // snapshot, not from the JOIN: it inserted an empty placeholder and
                        // queued a full NAMES/WHO/MODE/TOPIC resync burst, and by the time the
                        // JOIN line arrived the channel was "already tracked" — so the web
                        // side's own self-JOIN handling was skipped on every single join. Two
                        // consequences, both fixed by this one line move: the burst's bare
                        // `MODE #chan` produced a duplicate RPL_CREATIONTIME line per join, and
                        // the placeholder kept the case-FOLDED channel name (this set is keyed
                        // by irc_lower) as its display/log name, so a mixed-case channel had its
                        // history split across a second, all-lowercase log directory. JOIN-first
                        // hands the channel
                        // to the self-JOIN path with the server's canonical spelling.
                        fwd(&line);
                        if changed {
                            let c = conn.lock().await;
                            sync(&c, registered, true, None);
                        }
                    }
                    // PART / KICK / NICK / CHGHOST: like JOIN, the line goes out FIRST and the
                    // snapshot (only when something changed) after it, so the web handles the
                    // line against the state it describes (agy P2 irc_daemon.rs:1330: a snapshot
                    // that overtook its NICK line pre-applied the nick and bypassed the web's
                    // #30 spoof guard).
                    "PART" => {
                        let who = nick_from_prefix(&p.prefix);
                        let mut parted: Option<String> = None;
                        let mut changed = false;
                        let cm = *casemapping;
                        {
                            let mut c = conn.lock().await;
                            if is_self_nick(&who, &c.nick) {
                                if let Some(chan) = p.params.first() {
                                    let lc = cm.fold(chan);
                                    changed = c.channels.remove(&lc).is_some();
                                    parted = Some(lc);
                                }
                            }
                        }
                        if let Some(lc) = parted { persistent_channels.remove(&lc); }
                        fwd(&line);
                        if changed { let c = conn.lock().await; sync(&c, registered, true, None); }
                    }
                    "KICK" => {
                        let mut kicked_from: Option<String> = None;
                        let mut changed = false;
                        let cm = *casemapping;
                        {
                            let mut c = conn.lock().await;
                            if let Some(kicked) = p.params.get(1) {
                                if is_self_nick(kicked, &c.nick) {
                                    if let Some(chan) = p.params.first() {
                                        let lc = cm.fold(chan);
                                        changed = c.channels.remove(&lc).is_some();
                                        kicked_from = Some(lc);
                                    }
                                }
                            }
                        }
                        if let Some(lc) = kicked_from { persistent_channels.remove(&lc); }
                        fwd(&line);
                        if changed { let c = conn.lock().await; sync(&c, registered, true, None); }
                    }
                    "NICK" => {
                        let who = nick_from_prefix(&p.prefix);
                        let src_uh = prefix_userhost(&p.prefix);
                        let mut changed = false;
                        {
                            let mut c = conn.lock().await;
                            // agy P2 #30 bypass: the same guard as the web side — a self-NICK
                            // is adopted only when its source fully identifies us (the user@host
                            // learned from our self-JOIN/CHGHOST), or before that is known.
                            if self_source_matches(&who, src_uh, &c.nick, &c.self_userhost) {
                                if let Some(new_nick) = p.params.first() {
                                    // Bounded + filtered (serialized in every SessionSync): an
                                    // implausible nick is not adopted, so it can't push the state
                                    // frame past MAX_FRAME_LEN.
                                    match clean_nick(new_nick) {
                                        Some(n) => {
                                            if c.nick != n { c.nick = n; changed = true; }
                                            if src_uh.contains('@') {
                                                if let Some(u) = clean_userhost(src_uh) {
                                                    if c.self_userhost != u { c.self_userhost = u; changed = true; }
                                                }
                                            }
                                        }
                                        None => warn!("[{}] ignoring implausible self-NICK ({} bytes)", conn_id, new_nick.len()),
                                    }
                                }
                            } else if is_self_nick(&who, &c.nick) {
                                warn!("[{}] ignoring a self-NICK whose source does not match our user@host", conn_id);
                            }
                        }
                        fwd(&line);
                        if changed { let c = conn.lock().await; sync(&c, registered, true, None); }
                    }
                    "CHGHOST" => {
                        // Server changed our user@host mid-session — keep the learned
                        // value fresh so the web spoof guard stays accurate after reattach.
                        // Guarded like NICK: the line's source must be us as we know us.
                        let who = nick_from_prefix(&p.prefix);
                        let src_uh = prefix_userhost(&p.prefix);
                        let mut changed = false;
                        {
                            let mut c = conn.lock().await;
                            if self_source_matches(&who, src_uh, &c.nick, &c.self_userhost) {
                                if let (Some(u), Some(h)) = (p.params.first(), p.params.get(1)) {
                                    // Bound + sanitize (serialized in every SessionSync).
                                    if let Some(uh) = clean_userhost(&format!("{}@{}", u, h)) {
                                        if c.self_userhost != uh { c.self_userhost = uh; changed = true; }
                                    }
                                }
                            }
                        }
                        fwd(&line);
                        if changed { let c = conn.lock().await; sync(&c, registered, true, None); }
                    }

                    // Keep session-learned channel keys current for a TRACKED channel (a
                    // hostile server can't grow the map: tracked channels are capped).
                    "324" => {
                        if let Some(chan) = p.params.get(1) {
                            let cm = *casemapping;
                            let tracked = conn.lock().await.channels.contains_key(&cm.fold(chan));
                            if tracked {
                                let chm = conn.lock().await.chanmodes.clone();
                                if let Some(k) = channel_key_from_modes(&params_from(&p.params, 2), &chm) {
                                    remember_key_cm(learned_keys, chan, &k, cm);
                                }
                            }
                        }
                        fwd(&line);
                    }
                    "MODE" => {
                        if let Some(chan) = p.params.first() {
                            let cm = *casemapping;
                            let tracked = conn.lock().await.channels.contains_key(&cm.fold(chan));
                            if tracked {
                                let chm = conn.lock().await.chanmodes.clone();
                                match channel_key_change(&params_from(&p.params, 1), &chm) {
                                    Some(Some(k)) => remember_key_cm(learned_keys, chan, &k, cm),
                                    Some(None) => { learned_keys.remove(&cm.fold(chan)); }
                                    None => {}
                                }
                            }
                        }
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
                            // Never answer our OWN request (echo-message hands it back to us)
                            // or a historical one (chathistory/bouncer playback in a batch).
                            let from_self = is_self_nick(&from, &conn.lock().await.nick);
                            let playback = p.tags.contains_key("batch");
                            let now = Instant::now();
                            let allow = !from_self && !playback
                                && last_ctcp_reply.map_or(true, |t| now.duration_since(t) >= CTCP_REPLY_MIN_INTERVAL);
                            if allow {
                                last_ctcp_reply = Some(now);
                                let (ver, build) = resolve_ctcp_version(web_version);
                                // version/build come from the web's Attach — sanitize like every
                                // other interpolated field (defense in depth).
                                conn.lock().await.send_raw(&format!(
                                    "NOTICE {} :\x01VERSION CryptIRC v{} · {} - Made by gh0st - Visit irc.twistednet.org #dev #twisted\x01\r\n",
                                    strip_crlf(&from),
                                    strip_crlf(&ver).replace('\x01', ""),
                                    strip_crlf(&build).replace('\x01', ""),
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

    fn worst_registration_facts() -> crate::ipc::RegistrationFacts {
        let mut facts = crate::ipc::RegistrationFacts::default();
        facts.session_epoch = u64::MAX;
        // Fill all byte budgets with JSON-escaping tokens, then prove overflow closes.
        for (key, budget, list) in [("cap", REG_CAPS_JSON_BUDGET, &mut facts.caps),
                                    ("enabled", REG_ENABLED_CAPS_JSON_BUDGET, &mut facts.enabled_caps),
                                    ("CLIENTTAGDENY", REG_ISUPPORT_JSON_BUDGET, &mut facts.isupport)] {
            let token = format!("{}={}", key, "\\".repeat((budget - key.len() - 5) / 2));
            assert!(store_registration_token(list, &token, budget, REG_CAPS_MAX));
        }
        facts.server_name = Some("\\".repeat(255));
        facts.cap_ls_done = true;
        facts
    }

    #[test]
    fn registration_fragments_changes_and_bounds() {
        let mut f = crate::ipc::RegistrationFacts::default();
        note_registration_input(&mut f, &parse_irc(":irc CAP me LS * :sasl=PLAIN,EXTERNAL multi-prefix"), false);
        assert!(!f.cap_ls_done);
        note_registration_input(&mut f, &parse_irc(":irc CAP me LS :server-time"), false);
        assert!(f.cap_ls_done);
        assert_eq!(f.caps, ["sasl=PLAIN,EXTERNAL", "multi-prefix", "server-time"]);
        note_registration_input(&mut f, &parse_irc(":irc 005 me CASEMAPPING=ascii CLIENTTAGDENY=* :supported"), true);
        note_registration_input(&mut f, &parse_irc(":irc 005 me NETWORK=test BOUNCER_NETID=42 :supported"), true);
        assert!(f.behind_bouncer);
        assert_eq!(f.isupport, ["CASEMAPPING=ascii", "CLIENTTAGDENY=*", "BOUNCER_NETID=42"]);
        note_registration_input(&mut f, &parse_irc(":irc CAP me NEW :soju.im/bouncer-networks=value"), true);
        note_registration_input(&mut f, &parse_irc(":irc CAP me DEL :soju.im/bouncer-networks sasl"), true);
        note_registration_input(&mut f, &parse_irc(":irc 005 me -BOUNCER_NETID -CLIENTTAGDENY :supported"), true);
        assert_eq!(f.caps, ["multi-prefix", "server-time"]);
        assert!(f.behind_bouncer, "withdrawals never erase evidence");
        assert!(f.isupport.contains(&"-CLIENTTAGDENY".into()));
        note_registration_input(&mut f, &parse_irc(":irc 005 me CLIENTTAGDENY=* CASEMAPPING=ascii CASEMAPPING=rfc1459 :supported"), true);
        note_registration_input(&mut f, &parse_irc(":irc 005 me CLIENTTAGDENY CASEMAPPING -CASEMAPPING -CLIENTTAGDENY=ignored :supported"), true);
        assert!(f.isupport.contains(&"CLIENTTAGDENY=*".into()));
        assert!(f.isupport.contains(&"CASEMAPPING=ascii".into()));
        let mut cap_only = crate::ipc::RegistrationFacts::default();
        note_registration_input(&mut cap_only, &parse_irc(":irc CAP me LS :soju.im/bouncer-networks"), false);
        note_registration_input(&mut cap_only, &parse_irc(":irc CAP me DEL :soju.im/bouncer-networks"), true);
        assert!(cap_only.caps.is_empty() && cap_only.behind_bouncer);
        let mut prefix_only = crate::ipc::RegistrationFacts::default();
        note_registration_input(&mut prefix_only, &parse_irc(":irc.znc.in 004 me irc version modes modes"), true);
        assert!(prefix_only.behind_bouncer && !prefix_only.cap_ls_done);

        let mut bounded = worst_registration_facts();
        note_registration_input(&mut bounded, &parse_irc(":irc CAP me NEW :soju.im/overflow"), true);
        assert!(bounded.truncated && bounded.behind_bouncer);
        assert!(serde_json::to_vec(&bounded).unwrap().len() < 10 * 1024);
        let mut count = crate::ipc::RegistrationFacts::default();
        for i in 0..=REG_CAPS_MAX { note_registration_input(&mut count, &parse_irc(&format!(":irc CAP me NEW :c{i}")), true); }
        assert_eq!(count.caps.len(), REG_CAPS_MAX);
        assert!(count.truncated);
    }

    #[test]
    fn enabled_caps_follow_initial_and_mid_session_ack_and_withdrawals() {
        let mut f = crate::ipc::RegistrationFacts::default();
        note_registration_input(&mut f, &parse_irc(":irc CAP me LS :message-tags draft/metadata-2"), false);
        assert!(f.enabled_caps.is_empty(), "LS does not enable anything");
        note_registration_input(&mut f, &parse_irc(":irc CAP me ACK :message-tags"), false);
        note_registration_input(&mut f, &parse_irc(":irc CAP me ACK :draft/metadata-2=value"), true);
        assert_eq!(f.enabled_caps, ["message-tags", "draft/metadata-2"]);
        note_registration_input(&mut f, &parse_irc(":irc CAP me ACK :draft/metadata-2"), true);
        assert_eq!(f.enabled_caps.len(), 2, "duplicate ACKs do not grow facts");
        note_registration_input(&mut f, &parse_irc(":irc CAP me ACK :-draft/metadata-2"), true);
        assert_eq!(f.enabled_caps, ["message-tags"]);
        assert!(f.caps.contains(&"draft/metadata-2".into()), "negative ACK only disables");
        note_registration_input(&mut f, &parse_irc(":irc CAP me NAK :draft/metadata-2"), true);
        assert_eq!(f.enabled_caps, ["message-tags"]);
        note_registration_input(&mut f, &parse_irc(":irc CAP me ACK :draft/metadata-2"), true);
        note_registration_input(&mut f, &parse_irc(":irc CAP me DEL :draft/metadata-2"), true);
        assert_eq!(f.enabled_caps, ["message-tags"]);
        assert!(!f.caps.contains(&"draft/metadata-2".into()));
        note_registration_input(&mut f, &parse_irc(":irc CAP me NEW :draft/metadata-2"), true);
        assert_eq!(f.enabled_caps, ["message-tags"], "NEW does not re-enable");

        let mut bounded = worst_registration_facts();
        note_registration_input(&mut bounded, &parse_irc(":irc CAP me ACK :draft/metadata-2"), true);
        assert!(bounded.truncated);
        assert!(!bounded.enabled_caps.contains(&"draft/metadata-2".into()));
        assert!(serde_json::to_vec(&bounded.enabled_caps).unwrap().len() <= REG_ENABLED_CAPS_JSON_BUDGET);
    }

    /// Exercise the actual server-reader/RawSend boundary with an in-memory socket.
    /// Each invocation is a new run_loop, exactly the reset boundary used by reconnect.
    async fn registration_session(lines: &str) -> Vec<IpcMessage> {
        use tokio::io::AsyncBufReadExt;
        let params: DialParams = serde_json::from_value(serde_json::json!({
            "server":"irc.test", "port":6667, "tls":false, "tls_accept_invalid_certs":false,
            "nick":"me", "username":"me", "realname":"me", "password":null, "sasl_plain":null,
            "sasl_external":false, "client_identity":null, "oper_login":null, "oper_pass":null,
            "nickserv_pass":null, "auto_identify":false, "auto_join":[], "channel_keys":{},
            "perform_commands":[], "disabled_caps":[], "label":"test", "auto_reconnect":true
        })).unwrap();
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (tx, mut rx) = mpsc::channel(8);
        let messages = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = messages.clone();
        let emit = move |m| sink.lock().unwrap().push(m);
        let mut stopped = false;
        let mut registered = false;
        let mut channels = HashMap::new();
        let mut keys = HashMap::new();
        let mut parted = HashMap::new();
        let mut cm = CaseMapping::default();
        let version = Arc::new(WebVersionCell::default());
        let run = run_loop("c", &params, &emit, client, &mut rx, &mut stopped, &mut registered,
            &mut channels, &mut keys, &mut parted, &mut cm, &version);
        let driver = async {
            let (read, mut write) = tokio::io::split(server);
            let mut read = BufReader::new(read);
            let mut line = String::new();
            // An outbound line that looks exactly like registration is NOT evidence.
            let fake = ":irc.znc.in CAP me LS :soju.im/bouncer-networks";
            let q = QueuedLine::charge(fake.into(), Arc::new(std::sync::atomic::AtomicUsize::new(0))).unwrap();
            tx.send(DaemonCmd::RawSend(q)).await.ok().unwrap();
            loop {
                line.clear();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                if line.trim_end() == fake { break; }
            }
            write.write_all(lines.as_bytes()).await.unwrap();
            // Keep reading until the daemon has handled all input, then cycle the socket.
            write.write_all(b"PING :finished\r\n").await.unwrap();
            loop {
                line.clear();
                assert!(read.read_line(&mut line).await.unwrap() > 0);
                if line.trim_end() == "PONG :finished" { break; }
            }
            tx.send(DaemonCmd::Reconnect).await.ok().unwrap();
            // Drain QUIT so the reconnect write cannot fail because the peer disappeared.
            loop {
                line.clear();
                if read.read_line(&mut line).await.unwrap() == 0 { break; }
            }
        };
        timeout(Duration::from_secs(5), async { let (result, ()) = tokio::join!(run, driver); result.unwrap(); }).await.unwrap();
        assert!(!stopped && registered);
        let result = messages.lock().unwrap().clone();
        result
    }

    #[tokio::test]
    async fn oversized_clienttagdeny_marks_sessionsync_incomplete() {
        let oversized = format!("CLIENTTAGDENY=cryptirc.com/avatar,{}", "other/tag,".repeat(300));
        assert!(oversized.len() > REG_ISUPPORT_JSON_BUDGET);
        for earlier in ["", ":irc 005 me CLIENTTAGDENY=other/tag :supported\r\n"] {
            let lines = format!(":irc 001 me :hi\r\n{earlier}:irc 005 me {oversized} :supported\r\n");
            let messages = registration_session(&lines).await;
            let facts = messages.iter().rev().find_map(|m| match m {
                IpcMessage::SessionSync { registration: Some(f), .. } => Some(f), _ => None,
            }).unwrap();
            assert!(facts.truncated);
            let expected: Vec<String> = if earlier.is_empty() { vec![] } else { vec!["CLIENTTAGDENY=other/tag".into()] };
            assert_eq!(facts.isupport, expected, "overflow leaves missing or stale facts");
            assert!(messages.iter().any(|m| matches!(m, IpcMessage::RawLine { line, .. } if line.contains(&oversized))),
                "the web still receives the full live denial");
        }
    }

    #[tokio::test]
    async fn live_registration_and_reconnect_ignore_outbound_evidence() {
        let lines = ":irc CAP me LS * :sasl=PLAIN multi-prefix\r\n:irc CAP me LS :server-time draft/metadata-2\r\n:irc CAP me ACK :server-time\r\n:irc 001 me :hi\r\n:irc CAP me ACK :draft/metadata-2\r\n:irc 004 me irc version modes modes\r\n:irc 005 me CLIENTTAGDENY=* CASEMAPPING=ascii :supported\r\n:irc 005 me BOUNCER_NETID=42 :supported\r\n:irc CAP me NEW :soju.im/bouncer-networks=value\r\n:irc CAP me DEL :soju.im/bouncer-networks\r\n";
        let messages = registration_session(lines).await;
        let snapshots: Vec<_> = messages.iter().filter_map(|m| match m {
            IpcMessage::SessionSync { registration: Some(f), .. } => Some(f), _ => None,
        }).collect();
        assert!(!snapshots[0].cap_ls_done && !snapshots[0].behind_bouncer);
        assert!(snapshots[0].enabled_caps.is_empty());
        let last = snapshots.last().unwrap();
        let epoch = last.session_epoch;
        assert_ne!(epoch, 0);
        assert!(snapshots.iter().all(|f| f.session_epoch == epoch), "CAP, 001 and later facts share an epoch");
        assert!(last.cap_ls_done && last.behind_bouncer);
        assert_eq!(last.server_name.as_deref(), Some("irc"));
        assert!(last.caps.contains(&"sasl=PLAIN".into()));
        assert_eq!(last.enabled_caps, ["server-time", "draft/metadata-2"]);
        assert!(!last.caps.iter().any(|c| c.starts_with("soju.im/")));
        // Nothing was hidden: all original server lines were forwarded verbatim.
        let forwarded: Vec<_> = messages.iter().filter_map(|m| match m { IpcMessage::RawLine { line, .. } => Some(line.as_str()), _ => None }).collect();
        assert_eq!(forwarded, lines.lines().collect::<Vec<_>>());
        let mut epochs = HashSet::from([epoch]);
        for reply in [":irc 001 me :hi\r\n", ":irc 421 me CAP :unknown\r\n:irc 001 me :hi\r\n"] {
            let messages = registration_session(reply).await;
            let f = messages.iter().rev().find_map(|m| match m { IpcMessage::SessionSync { registration: Some(f), .. } => Some(f), _ => None }).unwrap();
            assert_ne!(f.session_epoch, 0);
            assert!(epochs.insert(f.session_epoch), "re-registering the same conn_id gets a new epoch");
            assert!(!f.cap_ls_done && !f.behind_bouncer);
            assert!(f.caps.is_empty() && f.enabled_caps.is_empty() && f.isupport.is_empty(), "new dial resets all facts");
        }
    }

    #[tokio::test]
    async fn live_metadata_del_updates_sessionsync() {
        let messages = registration_session(":irc CAP me LS :draft/metadata-2\r\n:irc 001 me :hi\r\n:irc CAP me ACK :draft/metadata-2\r\n:irc CAP me DEL :draft/metadata-2\r\n").await;
        let snapshots: Vec<_> = messages.iter().filter_map(|m| match m {
            IpcMessage::SessionSync { registration: Some(f), .. } => Some(f), _ => None,
        }).collect();
        assert!(snapshots.iter().any(|f| f.enabled_caps == ["draft/metadata-2"]));
        let last = snapshots.last().unwrap();
        assert!(last.enabled_caps.is_empty() && last.caps.is_empty());
    }

    #[test]
    fn trackable_channel_filter() {
        assert!(is_trackable_channel("#chan"));
        assert!(is_trackable_channel("&local"));
        assert!(is_trackable_channel("#Über")); // multibyte UTF-8 ok (serializes 1:1)
        assert!(!is_trackable_channel(""));
        assert!(!is_trackable_channel("nochanprefix"));
        // r7: every name the web accepts (is_intent_channel), `"` and `\` included.
        assert!(is_trackable_channel("#with\"quote"));
        assert!(is_trackable_channel("#with\\backslash"));
        assert!(!is_trackable_channel("#with space"));
        assert!(!is_trackable_channel("#with,comma"));
        assert!(!is_trackable_channel("#with\u{01}ctrl"));
        assert!(is_trackable_channel(&format!("#{}", "x".repeat(199))));
        assert!(!is_trackable_channel(&format!("#{}", "x".repeat(200))));
    }

    #[test]
    fn clean_userhost_filter() {
        assert_eq!(clean_userhost("user@host.example"), Some("user@host.example".to_string()));
        assert!(clean_userhost("").is_none());
        assert!(clean_userhost(&format!("u@{}", "h".repeat(MAX_USERHOST_LEN))).is_none());
        assert!(clean_userhost("u@ho\"st").is_none());
        assert!(clean_userhost("u@ho\u{01}st").is_none());
        assert!(clean_userhost("u@host\r\n").is_none());
        assert!(clean_userhost("u@host\x7f").is_none());
        assert!(clean_userhost("\x0304u@host").is_none());
        let colored = format!("user@{}host.example", "\x0304\x1f".repeat(66));
        assert_eq!(clean_userhost(&colored), Some(colored.clone()));
        assert!(colored.len() > 256);
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
    /// names admit_tracked lets in, plus a max-length userhost/nick — must still
    /// serialize UNDER MAX_FRAME_LEN, so no hostile server can spoof self-JOINs to silence
    /// the state channel. Use names and userhosts that expand under JSON escaping.
    #[test]
    fn worst_case_sessionsync_fits_frame() {
        // r7: as many worst-case names as admit_tracked lets in — 200 bytes, all but the
        // prefix and a counter JSON-escaping (`\`), so each is ~400 JSON bytes.
        let mut tracked: HashMap<String, String> = HashMap::new();
        for i in 0..MAX_TRACKED_CHANNELS {
            let mut s = format!("#{:07}", i);
            while s.len() < 200 - 1 { s.push('\\'); }
            assert!(is_trackable_channel(&s));
            if admit_tracked(&tracked, &s.to_lowercase(), &s) { tracked.insert(s.to_lowercase(), s); }
        }
        assert!(tracked.len() > 100, "{} worst-case names admitted", tracked.len());
        let short: HashMap<String, String> = (0..MAX_TRACKED_CHANNELS + 50).map(|i| format!("#c{i}")).fold(HashMap::new(), |mut m, n| {
            if admit_tracked(&m, &n, &n) { m.insert(n.clone(), n); }
            m
        });
        assert_eq!(short.len(), MAX_TRACKED_CHANNELS, "the count cap still applies");
        let channels: Vec<String> = tracked.into_values().collect();
        // Worst nick clean_nick still accepts: MAX_NICK_LEN backslashes (legal RFC1459
        // nick bytes that JSON-escape to 2 bytes each). The old test hard-coded a benign
        // 32-byte nick, so it could not catch the unbounded server-set nick.
        let worst_nick = clean_nick(&"\\".repeat(MAX_NICK_LEN)).expect("max-length nick of specials is legal");
        let msg = crate::ipc::IpcMessage::SessionSync {
            conn_id: "c".repeat(36),
            nick: worst_nick,
            channels,
            registered: true,
            connected: true,
            lag_ms: Some(u64::MAX),
            message_tags: true,
            echo_message_enabled: true,
            self_userhost: clean_userhost(&format!("u@{}h", "\x1f".repeat(MAX_USERHOST_LEN - 3))).unwrap(),
            casemapping: CaseMapping::StrictRfc1459.token().to_string(),
            registration: Some(worst_registration_facts()),
            dial_server: clean_dial_server(&"s".repeat(255)),
            // r8: the largest CHANMODES/PREFIX ChanModes::learn accepts.
            chanmodes: Some(format!("CHANMODES={a},{a},{a},{a} PREFIX=({p})", a = "a".repeat(64), p = "o".repeat(16))),
            dial_port: u16::MAX,
        };
        let body = serde_json::to_vec(&msg).unwrap();
        assert!(
            body.len() < crate::ipc_framing::MAX_FRAME_LEN as usize,
            "worst-case SessionSync serialized to {} bytes, must be < MAX_FRAME_LEN ({})",
            body.len(), crate::ipc_framing::MAX_FRAME_LEN
        );
    }

    #[test]
    fn clean_nick_filter() {
        assert_eq!(clean_nick("gh0st").as_deref(), Some("gh0st"));
        assert_eq!(clean_nick("[a]\\`_^{|}-").as_deref(), Some("[a]\\`_^{|}-"));
        assert_eq!(clean_nick("Ünïcode").as_deref(), Some("Ünïcode"));
        assert_eq!(clean_nick("nick\r\n").as_deref(), Some("nick")); // CR/LF stripped first
        assert!(clean_nick("").is_none());
        assert!(clean_nick("has space").is_none());
        assert!(clean_nick("ctl\u{01}").is_none());
        assert!(clean_nick(&"x".repeat(MAX_NICK_LEN + 1)).is_none());
        assert!(clean_nick(&"x".repeat(MAX_NICK_LEN)).is_some());
        // The audit's t_bignick payload.
        assert!(clean_nick(&"\u{01}".repeat(8100)).is_none());
    }

    #[test]
    fn sasl_chunks_follow_spec() {
        assert_eq!(sasl_chunks(""), vec!["+"]);
        assert_eq!(sasl_chunks("AGFiYwBwdw=="), vec!["AGFiYwBwdw=="]); // normal PLAIN: one line, unchanged
        let s399 = "A".repeat(399);
        assert_eq!(sasl_chunks(&s399), vec![s399.clone()]);
        let s400 = "B".repeat(400);
        assert_eq!(sasl_chunks(&s400), vec![s400.clone(), "+".to_string()]);
        let s900 = "C".repeat(900);
        let c = sasl_chunks(&s900);
        assert_eq!(c.len(), 3);
        assert_eq!((c[0].len(), c[1].len(), c[2].len()), (400, 400, 100));
        let s800 = "D".repeat(800);
        assert_eq!(sasl_chunks(&s800).len(), 3);
        assert_eq!(sasl_chunks(&s800)[2], "+");
    }

    #[test]
    fn ascii_casemapping_keeps_bracket_channels_apart() {
        // codex P2 irc_daemon.rs:144: on an ascii server #a[b] and #a{b} are two channels.
        let mut k = HashMap::new();
        remember_key_cm(&mut k, "#a[b]", "key1", CaseMapping::Ascii);
        remember_key_cm(&mut k, "#a{b}", "key2", CaseMapping::Ascii);
        assert_eq!(k.len(), 2, "two channels, two keys");
        assert_eq!(k.get(&CaseMapping::Ascii.fold("#A[B]")).map(String::as_str), Some("key1"));
        // rfc1459 (the default) still treats them as one channel, as before.
        let mut r = HashMap::new();
        remember_key_cm(&mut r, "#a[b]", "key1", CaseMapping::Rfc1459);
        remember_key_cm(&mut r, "#a{b}", "key2", CaseMapping::Rfc1459);
        assert_eq!(r.len(), 1);
        // Dial-time keys stored by the web under to_lowercase(): exact only on ascii.
        let mut stored = HashMap::new();
        stored.insert("#a{b}".to_string(), "k2".to_string());
        assert_eq!(channel_key_lookup_cm(&stored, "#a[b]", CaseMapping::Ascii), None);
        assert_eq!(channel_key_lookup_cm(&stored, "#A{B}", CaseMapping::Ascii).map(String::as_str), Some("k2"));
        assert_eq!(channel_key_lookup_cm(&stored, "#a[b]", CaseMapping::Rfc1459).map(String::as_str), Some("k2"));
    }

    /// codex P2 ipc_server.rs:745: a queued web line can no longer pin a whole 64 KiB IPC
    /// frame — the message part is cut to the IRC limit (char-safe), a tag section is kept
    /// up to its own limit, and an over-long tag section is refused.
    #[test]
    fn outbound_lines_are_cut_to_irc_limits() {
        assert_eq!(cap_outbound_line("PRIVMSG #a :hi\r\n").as_deref(), Some("PRIVMSG #a :hi"));
        let big = format!("PING :{}", "x".repeat(60 * 1024));
        assert_eq!(cap_outbound_line(&big).unwrap().len(), OUT_MSG_MAX);
        let wide = format!("PRIVMSG #a :{}", "é".repeat(400));
        let cut = cap_outbound_line(&wide).unwrap();
        assert!(cut.len() <= OUT_MSG_MAX && cut.len() >= OUT_MSG_MAX - 1 && cut.starts_with("PRIVMSG #a :é"));
        let tagged = format!("@+typing=active;+x={} TAGMSG #a", "a".repeat(5000));
        assert_eq!(cap_outbound_line(&tagged).as_deref(), Some(tagged.as_str()));
        let tagged_long_msg = format!("@+t=1 PRIVMSG #a :{}", "b".repeat(2000));
        let c = cap_outbound_line(&tagged_long_msg).unwrap();
        assert_eq!(c.len(), "@+t=1 ".len() + OUT_MSG_MAX);
        assert!(cap_outbound_line(&format!("@x={} TAGMSG #a", "a".repeat(OUT_TAGS_MAX))).is_none());
    }

    #[test]
    fn rawsend_budget_is_bounded_and_released() {
        let conn = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut held = Vec::new();
        while let Some(q) = QueuedLine::charge("x".repeat(500), conn.clone()) { held.push(q); }
        assert!(conn.load(std::sync::atomic::Ordering::Acquire) <= RAWSEND_CONN_BYTE_CAP);
        assert_eq!(held.len(), RAWSEND_CONN_BYTE_CAP / 532);
        assert_eq!(held[0].line().len(), 500);
        drop(held);
        assert_eq!(conn.load(std::sync::atomic::Ordering::Acquire), 0, "dropping a queued line releases its bytes");
    }

    /// agy P2 #30 bypass: the daemon now applies the web's self-NICK/CHGHOST rule.
    #[test]
    fn self_identity_rules_match_the_web() {
        assert!(is_self_nick("Alice[", "alice["));
        assert!(!is_self_nick("alice{", "alice["), "rfc1459-equal but a different nick on an ascii server");
        assert!(!is_self_nick("", ""));
        assert!(self_source_matches("me", "u@h", "me", "u@h"));
        assert!(self_source_matches("ME", "U@H", "me", "u@h"));
        assert!(!self_source_matches("me", "", "me", "u@h"), "bare forged prefix");
        assert!(!self_source_matches("me", "x@y", "me", "u@h"), "someone else's user@host");
        assert!(self_source_matches("me", "u@cloaked.example", "me", "u@h"), "a host change without CHGHOST (vhost/cloak) is still us");
        assert!(!self_source_matches("me", "@h", "me", "u@h"));
        assert!(self_source_matches("me", "", "me", ""), "before our user@host is known (legacy accept)");
        assert_eq!(prefix_userhost(&Some("me!u@h".into())), "u@h");
        assert_eq!(prefix_userhost(&Some("me".into())), "");
        assert_eq!(prefix_userhost(&None), "");
    }

    /// agy P2 irc_daemon.rs:900-945: CAP END only once every REQ is answered and no SASL
    /// exchange is in flight.
    #[test]
    fn cap_end_waits_for_every_req_and_sasl() {
        assert!(!cap_negotiation_done(1, &SaslState::Done));
        assert!(!cap_negotiation_done(0, &SaslState::CapReqSent));
        assert!(!cap_negotiation_done(0, &SaslState::AuthenticateSent));
        assert!(cap_negotiation_done(0, &SaslState::Done));
        assert!(cap_negotiation_done(0, &SaslState::Idle));
        assert!(cap_list_has("multi-prefix sasl", "sasl"));
        assert!(cap_list_has("sasl=PLAIN,EXTERNAL", "sasl"));
        assert!(cap_list_has("-sasl", "sasl"));
        assert!(!cap_list_has("draft/sasl-ir echo-message", "sasl"));
    }

    /// Integrator FAIL-CLOSED decision: the terminal reason names the network and what to
    /// check, and never offers an unauthenticated fallback.
    #[test]
    fn sasl_giveup_reason_is_actionable() {
        let p: DialParams = serde_json::from_value(serde_json::json!({
            "server":"irc.example.org","port":6697,"tls":true,"tls_accept_invalid_certs":false,
            "nick":"n","username":"u","realname":"r","password":null,
            "sasl_plain":{"account":"a","password":"b"},"sasl_external":false,"client_identity":null,
            "oper_login":null,"oper_pass":null,"nickserv_pass":null,"auto_identify":false,"auto_join":[],
            "channel_keys":{},"perform_commands":[],"disabled_caps":[],"label":"Libera\r\nX","auto_reconnect":true
        })).unwrap();
        let r = sasl_giveup_reason(&p);
        assert!(r.starts_with("SASL authentication failed 3 times on LiberaX: check the SASL account name and password"), "{r}");
        assert!(r.contains("press Connect") && r.contains("Not connecting without SASL"));
        let mut e = p.clone();
        e.sasl_external = true;
        e.label = String::new();
        assert!(sasl_giveup_reason(&e).contains("on irc.example.org: check the client certificate"));
    }

    #[test]
    fn dial_server_is_reported_only_when_plausible() {
        assert_eq!(clean_dial_server("irc.libera.chat"), "irc.libera.chat");
        assert_eq!(clean_dial_server(""), "");
        assert_eq!(clean_dial_server("a b"), "");
        assert_eq!(clean_dial_server("x\"y"), "");
        assert_eq!(clean_dial_server(&"h".repeat(256)), "");
    }

    #[test]
    fn join_keys_are_learned_from_outbound_join() {
        let mut k = HashMap::new();
        learn_join_keys("JOIN #Key[X] sekrit\r\n", &mut k);
        assert_eq!(k.get("#key{x}").map(String::as_str), Some("sekrit"));
        learn_join_keys("join #a,#b,#c ka,kb", &mut k);
        assert_eq!(k.get("#a").map(String::as_str), Some("ka"));
        assert_eq!(k.get("#b").map(String::as_str), Some("kb"));
        assert!(!k.contains_key("#c"));
        learn_join_keys("JOIN #nokey", &mut k);
        assert!(!k.contains_key("#nokey"));
        learn_join_keys("PRIVMSG #x :JOIN #y key", &mut k);
        assert!(!k.contains_key("#y"));
        learn_join_keys("JOIN #bad\u{01}name key", &mut k); // untrackable name
        assert!(k.keys().all(|c| !c.contains('\u{01}')));
        learn_join_keys(&format!("JOIN #long {}", "x".repeat(MAX_KEY_LEN + 1)), &mut k);
        assert!(!k.contains_key("#long"));
        // bounded
        let mut b = HashMap::new();
        for i in 0..(MAX_TRACKED_CHANNELS + 50) { learn_join_keys(&format!("JOIN #c{i} k"), &mut b); }
        assert_eq!(b.len(), MAX_TRACKED_CHANNELS);
    }

    /// r5 (codex P2 irc_daemon.rs:717): a /part or /join made during reconnect backoff is
    /// applied to the channels re-joined at the next registration.
    #[test]
    fn part_and_join_during_backoff_take_effect_at_registration() {
        let cm = CaseMapping::Rfc1459;
        let mut persistent = HashMap::from([("#manual".to_string(), "#Manual".to_string())]);
        let (mut parted, mut keys) = (HashMap::new(), HashMap::new());
        assert!(apply_backoff_part_join("PART #Manual,#auto :bye\r\n", &mut persistent, &mut parted, &mut keys, cm));
        assert!(persistent.is_empty() && parted.contains_key("#manual") && parted.contains_key("#auto"));
        assert!(apply_backoff_part_join("JOIN #auto,#new k1,k2", &mut persistent, &mut parted, &mut keys, cm));
        assert!(!parted.contains_key("#auto"));
        assert_eq!(persistent.get("#new").map(String::as_str), Some("#new"));
        assert_eq!(keys.get("#new").map(String::as_str), Some("k2"));
        assert!(!apply_backoff_part_join("PRIVMSG #x :JOIN #y", &mut persistent, &mut parted, &mut keys, cm));
        assert!(!apply_backoff_part_join("JOIN", &mut persistent, &mut parted, &mut keys, cm));
    }

    /// r6 (codex P2 irc_daemon.rs:183): the user's intent for a channel name the web accepts
    /// but the SessionSync filter does not (`"`, `\`) is still recorded.
    #[test]
    fn intent_bookkeeping_accepts_every_name_the_web_accepts() {
        let cm = CaseMapping::Rfc1459;
        assert!(is_intent_channel("#team\\ops") && is_intent_channel("#a\"b") && is_intent_channel("#chan"));
        assert!(is_trackable_channel("#team\\ops"), "r7: tracked (in the SessionSync) too");
        for bad in ["", "nochan", "#with space", "#with,comma", "#ctl\u{01}", "#del\u{7f}"] { assert!(!is_intent_channel(bad), "{bad:?}"); }
        assert!(is_intent_channel(&format!("#{}", "x".repeat(199))) && !is_intent_channel(&format!("#{}", "x".repeat(200))));
        let mut parted = HashMap::new();
        note_user_part_join("PART #team\\ops :bye\r\n", &mut parted, cm);
        assert!(parted.contains_key(&cm.fold("#team\\ops")), "the PART is remembered");
        let (mut persistent, mut keys) = (HashMap::new(), HashMap::new());
        assert!(apply_backoff_part_join("JOIN #a\"b sekrit", &mut persistent, &mut parted, &mut keys, cm));
        assert_eq!(persistent.get(&cm.fold("#a\"b")).map(String::as_str), Some("#a\"b"), "a backoff JOIN is re-joined");
        assert_eq!(keys.get(&cm.fold("#a\"b")).map(String::as_str), Some("sekrit"));
        assert!(apply_backoff_part_join("PART #team\\ops", &mut persistent, &mut parted, &mut keys, cm));
        assert!(parted.contains_key(&cm.fold("#team\\ops")));
    }

    /// r8 (codex P2 irc_daemon.rs:183): a JOIN with IRCv3 tags still teaches its keys.
    #[test]
    fn tagged_joins_teach_their_keys() {
        let mut keys = HashMap::new();
        learn_join_keys("@label=x JOIN #keyed secret\r\n", &mut keys);
        learn_join_keys("@a=1;b=2 :me JOIN #two,#three k2,k3", &mut keys);
        assert_eq!(keys.get("#keyed").map(String::as_str), Some("secret"));
        assert_eq!(keys.get("#three").map(String::as_str), Some("k3"));
        // r8 (codex P2 irc_daemon.rs:97): the size budget can cut a snapshot.
        assert!(!snapshot_may_be_truncated(&["#a".to_string(), "#b".to_string()]));
        let long: Vec<String> = (0..140).map(|i| format!("#{i:03}{}", "\\".repeat(196))).collect();
        assert!(snapshot_may_be_truncated(&long));
        assert!(snapshot_may_be_truncated(&(0..MAX_TRACKED_CHANNELS).map(|i| format!("#c{i}")).collect::<Vec<_>>()));
    }

    /// r4 (codex P2 irc_daemon.rs:1361): the user's own PART / JOIN lines decide whether a
    /// (Dial-time) auto-join channel is re-joined after a daemon-internal reconnect.
    #[test]
    fn user_parts_and_joins_are_tracked_from_outbound_lines() {
        let cm = CaseMapping::Rfc1459;
        let mut p = HashMap::new();
        note_user_part_join("PART #Auto[1],#two :bye\r\n", &mut p, cm);
        assert_eq!(p.get("#auto{1}").map(String::as_str), Some("#Auto[1]"));
        assert!(p.contains_key("#two"));
        note_user_part_join("@label=x :me PART #three", &mut p, cm);
        assert!(p.contains_key("#three"));
        // Joining again (any spelling under the server's fold) forgets the part.
        note_user_part_join("JOIN #AUTO{1} key", &mut p, cm);
        assert!(!p.contains_key("#auto{1}"));
        // Not a part: chat that mentions PART, JOIN 0, an untrackable name.
        note_user_part_join("PRIVMSG #x :PART #y", &mut p, cm);
        note_user_part_join("JOIN 0", &mut p, cm);
        note_user_part_join("PART #bad\u{01}x", &mut p, cm);
        assert_eq!(p.len(), 2);
        // ascii servers: #a[b] and #a{b} are different channels.
        let mut a = HashMap::new();
        note_user_part_join("PART #a[b]", &mut a, CaseMapping::Ascii);
        note_user_part_join("JOIN #a{b}", &mut a, CaseMapping::Ascii);
        assert!(a.contains_key("#a[b]"));
        // bounded
        let mut b = HashMap::new();
        for i in 0..(MAX_TRACKED_CHANNELS + 50) { note_user_part_join(&format!("PART #c{i}"), &mut b, cm); }
        assert_eq!(b.len(), MAX_TRACKED_CHANNELS);
    }
}
