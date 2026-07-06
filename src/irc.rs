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
use tokio::sync::{mpsc, Mutex};
use tracing::{info, warn};

use crate::{network_config_lock, AppState, MessageKind, NetworkConfig, ServerEvent};
use cryptirc::ipc::IpcMessage;
use cryptirc::ircproto::{
    channel_key_from_modes, irc_lower, nick_from_prefix, params_from,
    parse_irc, strip_crlf, strip_pfx, truncate_chars, userhost_from_prefix,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// S3: maximum total channels in names_buf
const NAMES_BUF_MAX_CHANNELS: usize = 512;
/// S3: maximum entries per channel in names_buf
const NAMES_BUF_MAX_PER_CHAN: usize = 4096;
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
// ─── Public types ─────────────────────────────────────────────────────────────
// (ConnCleanup — the old RAII remove-on-drop guard for `state.connections`/
// `conn_owners` — is gone. It existed because run_loop's task was recreated on
// every reconnect attempt, so a fresh entry needed reclaiming on every exit. In
// the daemon-split architecture, IrcConnection is a STABLE per-conn_id record:
// the daemon owns reconnect/backoff and the web side just updates the same
// entry in place (nick/channels/connected/registered) as SessionSync/RawLine
// arrive. The entry is only ever removed when the user actually removes the
// network (ClientMessage::RemoveNetwork), not on every disconnect/reconnect.

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
    /// There is no real socket here anymore — the daemon owns it. Sending a
    /// line means handing an `IpcMessage::RawSend` to whatever IPC connection
    /// is CURRENTLY up. Shares the identical cell `AppState.ipc_out` holds
    /// (cloned in at construction) rather than a frozen sender, so a daemon
    /// reconnect (which mints a brand-new mpsc pair) transparently keeps every
    /// existing IrcConnection able to send — mirrors how the daemon's own
    /// `Daemon::forward_live` looks up "whatever's current" fresh each call.
    pub ipc_out: Arc<tokio::sync::Mutex<Option<mpsc::UnboundedSender<IpcMessage>>>>,
    pub message_tags: bool,
    pub self_userhost: String,
    /// Web-side idempotency guard for a replayed/duplicate 001 (mirrors the old
    /// run_loop-local `registered` bool, now persisted on the connection so it
    /// survives across separate `dispatch_line` calls).
    pub registered: bool,
    /// Was a run_loop-local var; now persists across per-line calls.
    pub echo_message_enabled: bool,
    /// Was a run_loop-local var; accumulates 353 lines until 366 flushes.
    pub names_buf: HashMap<String, Vec<String>>,
    /// Case-folded channel keys with an in-flight self-triggered WHO (JOIN-time only now).
    pub who_pending: HashSet<String>,
    /// Accumulates away nicks per channel for the in-flight WHO.
    pub who_away: HashMap<String, Vec<String>>,
    /// Cached at connection-creation time (Dial or Attach-rehydration) so
    /// `dispatch_line` never needs a disk read per IRC line — the original
    /// single-process code kept this as a stable in-memory variable for the
    /// whole session; this preserves that instead of re-fetching per line.
    /// Refreshed by whichever handler already updates the on-disk config
    /// (UpdateNetwork) — see main.rs.
    pub cfg: NetworkConfig,
}

impl IrcConnection {
    pub async fn send_raw(&mut self, line: &str) -> Result<()> {
        if let Some(tx) = self.ipc_out.lock().await.as_ref() {
            let _ = tx.send(IpcMessage::RawSend { conn_id: self.conn_id.clone(), line: line.to_string() });
        }
        Ok(())
    }
}

// ─── Entry point: reconnect loop ─────────────────────────────────────────────

/// Extract the +k key from a 324-style "<+modes> <param…>" string (the currently-set
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

// ─── Per-line dispatch (web side of the daemon split) ────────────────────────

/// Process one inbound IRC line forwarded from the irc-core daemon
/// (`IpcMessage::RawLine`).
///
/// Mirrors the second half of the old `run_loop`'s per-line match, adapted so
/// it never re-sends anything the daemon already sends. The daemon
/// (`src/irc_daemon.rs`) owns the raw socket and fully handles dial/TLS,
/// registration (PASS/CAP LS/NICK/USER), CAP negotiation (CAP REQ), SASL
/// (AUTHENTICATE/CAP END), pre-registration nick-collision retry, the 001
/// welcome burst (OPER, NickServ IDENTIFY, perform_commands, auto-join), and
/// PING/PONG keepalive (fully consumed there — PING/PONG are never forwarded
/// here) — plus the CTCP VERSION auto-reply. Design principle ("act AND
/// forward", same as the daemon's file header): the daemon forwards nearly
/// every other inbound line to this side as `RawLine` so this (unmodified)
/// parsing logic can independently re-derive whatever state it needs
/// (message_tags, echo_message_enabled, SaslStatus events, the Connected
/// event, nick adoption) by re-parsing the same wire content a second time,
/// rather than the daemon inventing custom translations for every piece of
/// state. `dispatch_line` MAY still send things the daemon does not do:
/// specifically the self-join NAMES/WHO requests (JOIN arm).
/// `replayed`: true when `line` came from the daemon's Attach-time ring-buffer
/// replay rather than live off the socket. Almost every arm treats the two
/// identically (that's the whole point of re-parsing the same wire content),
/// but a couple of side effects are only correct once per real-world event —
/// see the 432/433/436 and JOIN arms — and must not re-fire just because a
/// reattach re-shows a line the web process already processed before it
/// restarted.
pub async fn dispatch_line(
    state: &AppState,
    username: &str,
    conn_id: &str,
    conn: &Arc<Mutex<IrcConnection>>,
    line: &str,
    replayed: bool,
) -> anyhow::Result<()> {
    let p = parse_irc(line);
    // Prefer IRCv3 server-time tag when available
    let ts = p.tags.get("time")
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.timestamp())
        .unwrap_or_else(|| chrono::Utc::now().timestamp());
    let send = |evt: ServerEvent| state.send_to_user(username, evt);

    match p.command.as_str() {

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
                "ACK" => {
                    // L43: Set capability flags on ACK, not on REQ
                    if caps.contains("echo-message") { conn.lock().await.echo_message_enabled = true; }
                    if caps.contains("message-tags") { conn.lock().await.message_tags = true; }
                }
                "NAK" => {
                    let sasl_configured = { let c = conn.lock().await; c.cfg.sasl_external || c.cfg.sasl_plain.is_some() };
                    if sasl_configured && caps.contains("sasl") {
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: "SASL capability rejected".into() });
                    }
                }
                "DEL" => {
                    if caps.contains("echo-message") { conn.lock().await.echo_message_enabled = false; }
                }
                _ => {}
            }
        }

        "900" => {
            let account = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: true, message: format!("Logged in as {}", account) });
        }
        "903" => {
            info!("[{}] SASL 903: authentication successful", conn_id);
            send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: true, message: "SASL authentication successful".into() });
        }
        "902" | "904" | "905" | "906" | "907" => {
            let reason = p.params.last().cloned().unwrap_or_else(|| "SASL failed".into());
            warn!("[{}] SASL {} FAILED: {}", conn_id, p.command, reason);
            send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: reason.clone() });
        }

        // ── Welcome ──────────────────────────────────────────
        // #29/live-tested fix: 001 is deliberately a no-op here (just
        // swallowed, never falls through to the generic numeric display).
        // The daemon's own "001" handling ALWAYS calls its sync() (emitting
        // SessionSync with the adopted nick + registered:true) BEFORE it
        // forwards this raw line — so by the time dispatch_line would see
        // 001, the IPC client's SessionSync handler has already adopted the
        // nick and (on the false→true edge) emitted ServerEvent::Connected.
        // Duplicating that here raced the SessionSync's registered flag
        // (which arrives first) against this arm's own idempotency guard —
        // caught live in a real end-to-end test: the guard read "already
        // registered" before the real 001 line ever arrived, so Connected
        // silently never fired even though the connection worked perfectly.
        // SessionSync is now the single authoritative source for nick/
        // registered/connected/Connected-emission; see ipc_client.rs.
        "001" => {}

        // S4: bounded nick collision retry — ONLY while still registering (pre-001).
        // During registration we need *a* nick to finish connecting, so auto-append
        // "_N". But once registered, a manual /nick that collides must surface the
        // server's message (e.g. "Nickname is already in use") and keep the user's
        // current nick — NOT silently switch it.
        "432" | "433" | "436" => {
            // `!replayed` guard: on a reattach, SessionSync sets `registered=true`
            // BEFORE the ring buffer replays history, so a replayed 432/433/436
            // from the ORIGINAL registration burst (routine nick-collision retry,
            // long since resolved) would otherwise take this branch and show a
            // spurious "Nickname is already in use" error on every reattach even
            // though nothing is wrong. A live occurrence (real `/nick` collision
            // after registration) always has `replayed==false`, so it still shows.
            if !replayed && conn.lock().await.registered {
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
            }
        }

        "PRIVMSG" => {
            let from   = nick_from_prefix(&p.prefix);
            let target = p.params.get(0).cloned().unwrap_or_default();
            let text   = p.params.get(1).cloned().unwrap_or_default();
            let (user_nick, label) = { let c = conn.lock().await; (c.nick.clone(), c.cfg.label.clone()) };
            // echo-message: if server echoes our own PRIVMSG, skip it here —
            // the Send handler already broadcasts IrcEcho for multi-device sync.
            // Suppress regardless of prefix form: a real IRCd echoes the full
            // nick!user@host, but ZNC (and some bouncers) echo self-messages with
            // a bare `:nick` prefix. Gating on `prefix.contains('!')` let those
            // through and the user saw their own line twice. `from == user_nick`
            // (with the authoritative nick adopted from 001) is the real test.
            // Don't suppress echo for batch messages (chathistory/+H playback).
            let in_batch = p.tags.contains_key("batch");
            let echo_message_enabled = { conn.lock().await.echo_message_enabled };
            if echo_message_enabled && from == user_nick && !in_batch {
                return Ok(());
            }
            // Reply to CTCP VERSION
            if text == "\x01VERSION\x01" {
                // The daemon already sends the NOTICE reply (with its own rate
                // limit) — this side just needs to recognize and silently skip
                // displaying the request, not reply to it again.
                return Ok(());
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
                    label, display_target.clone(), from.clone(), clean.clone(),
                );
                tokio::spawn(async move {
                    notifier.maybe_notify(&u, &un, &cid, &lbl, &tgt, &frm, &txt, ts).await;
                });
            }
            // Server-side bot triggers (!w, !ud, …). Only for LIVE channel messages
            // from someone else — never on history replay, never our own lines
            // (those are echo-skipped above anyway). maybe_trigger is a cheap
            // in-memory check; it spawns its own task for any actual fetch/reply.
            if !replayed && from != user_nick && display_target.starts_with(['#','&','+','!']) {
                let full_mask = format!("{}!{}", from, userhost_from_prefix(&p.prefix));
                crate::bots::maybe_trigger(state, username, conn, &display_target, &from, &full_mask, &clean);
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
            let echo_message_enabled = { conn.lock().await.echo_message_enabled };
            if echo_message_enabled && from == user_nick && !in_batch {
                return Ok(());
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
            // `is_self_join` = it was our own JOIN and we should issue NAMES;
            // `is_self` = it's our nick regardless of already-tracked status
            // (used below to suppress a REPLAYED duplicate of our own join log/
            // event — see the `replayed` check after this block).
            let is_self = nick == conn.lock().await.nick;
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
                        let seed_key = c.cfg.channel_keys.get(&chan_key).cloned();
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
                {
                    let mut c = conn.lock().await;
                    if c.who_pending.len() < NAMES_BUF_MAX_CHANNELS || c.who_pending.contains(&chan_key) {
                        c.who_pending.insert(chan_key);
                    }
                }
                conn.lock().await.send_raw(&format!("WHO {}\r\n", strip_crlf(&channel))).await?;
            }
            // Reattach replays SessionSync (which stubs in every channel the
            // daemon says we're currently in) BEFORE the ring buffer replays
            // history — so a replayed copy of our OWN original self-JOIN for a
            // channel we're still in ALWAYS lands here as "already tracked"
            // (is_self_join==false), even though it was already logged once
            // when it first happened live. Suppress just that specific
            // replay-of-our-own-join duplicate; a genuinely LIVE repeated
            // self-JOIN (the #43 abuse case above) still logs normally since
            // `replayed` is false for it, and another user's join replayed
            // after an outage still logs (that's its first-ever processing,
            // not a duplicate — this web process was down when it happened).
            let suppress_replay_dup = replayed && is_self && !is_self_join;
            // Persist for log replay (Lounge-style condense after refresh) —
            // skipped for channels rejected by the cap to bound disk/inode growth.
            if accepted && !suppress_replay_dup {
                let mut join_text = format!("→ {} joined", nick);
                if !account.is_empty() && account != "*" { join_text.push_str(&format!(" ({})", account)); }
                if !realname.is_empty()                  { join_text.push_str(&format!(" — {}", realname)); }
                let _ = state.logger.append(&username, &conn_id, &channel, ts, &nick, &join_text, "join").await;
            }
            // #43: don't surface a JOIN for a channel we refused to track
            // (a cap-rejected forged self-JOIN) — keep client and server state in sync.
            if accepted && !suppress_replay_dup {
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
            let mut c = conn.lock().await;
            if c.names_buf.len() < NAMES_BUF_MAX_CHANNELS {
                let names: Vec<String> = p.params.get(3).cloned().unwrap_or_default()
                    .split_whitespace()
                    // userhost-in-names: strip !user@host from entries like @nick!user@host
                    .map(|s| {
                        if let Some(bang) = s.find('!') { s[..bang].to_string() }
                        else { s.to_string() }
                    })
                    .collect();
                let entry = c.names_buf.entry(channel).or_default();
                for n in names {
                    if entry.len() < NAMES_BUF_MAX_PER_CHAN { entry.push(n); }
                }
            }
        }
        "366" => {
            let channel = p.params.get(1).cloned().unwrap_or_default();
            let names   = { conn.lock().await.names_buf.remove(&channel).unwrap_or_default() };
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
            let is_pending = {
                let mut c = conn.lock().await;
                if status.starts_with('G') && !who_nick.is_empty()
                    && (c.who_away.len() < NAMES_BUF_MAX_CHANNELS || c.who_away.contains_key(&chan_key)) {
                    let v = c.who_away.entry(chan_key.clone()).or_default();
                    if v.len() < NAMES_BUF_MAX_PER_CHAN { v.push(who_nick); }
                }
                c.who_pending.contains(&chan_key)
            };
            // A user-typed /who isn't in who_pending — keep forwarding its raw
            // reply to status so manual WHO still works as before.
            if !is_pending {
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
            let was_auto = { conn.lock().await.who_pending.remove(&chan_key) };
            // Emit a snapshot only for real channels (skip `WHO nick`-style masks).
            if channel.starts_with(['#','&','+','!']) {
                let away_nicks = { conn.lock().await.who_away.remove(&chan_key).unwrap_or_default() };
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
                conn.lock().await.who_away.remove(&chan_key);
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
    Ok(())
}

// ─── IRC line parser ──────────────────────────────────────────────────────────
// (parse_irc/IrcLine/unescape_tag_value/nick_from_prefix/userhost_from_prefix/
//  strip_pfx now live in cryptirc::ircproto — imported at the top of this file)

fn kind_str(k: &MessageKind) -> &'static str {
    match k { MessageKind::Privmsg => "privmsg", MessageKind::Notice => "notice", MessageKind::Action => "action" }
}
