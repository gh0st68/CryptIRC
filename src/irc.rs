//! irc.rs — IRC connection handler
//!
//! Fixes this pass:
//!   B1/B2 — removed unused imports (AtomicBool, Ordering, SaslConfig)
//!   S3    — names_buf bounded (max 512 channels × 4096 entries each)
//!   S4    — nick collision aborts after MAX_NICK_RETRIES attempts
//!   L1    — auto_reconnect flag respected in outer connect() loop
//!   L3    — stale IrcConnection removed from map on run_loop exit

use anyhow::Result;
use std::{collections::{HashMap, HashSet}, sync::Arc, time::{Duration, Instant}};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::{network_config_lock, AppState, MessageKind, NetworkConfig, ServerEvent};
use cryptirc::ipc::IpcMessage;
use cryptirc::ircproto::{
    channel_key_from_modes, channel_key_lookup_cm, nick_from_prefix, params_from, CaseMapping, ChanModes,
    parse_irc, statusmsg_from_isupport, statusmsg_target, strip_crlf, strip_pfx, userhost_from_prefix,
};

// ─── Constants ────────────────────────────────────────────────────────────────

/// S3: maximum total channels in names_buf
pub(crate) const NAMES_BUF_MAX_CHANNELS: usize = 512;
/// S3: maximum entries per channel in names_buf
const NAMES_BUF_MAX_PER_CHAN: usize = 4096;
/// codex P2 irc.rs:824: the S3 caps bounded counts, not bytes — an 8 KB "nick" fits the
/// daemon's 8 KiB line limit, so 512 × 4096 entries could pin gigabytes in the web
/// process. A member-list entry (prefix chars + nick) longer than this is not a real
/// nick on any network (NICKLEN is 9-50; the daemon already refuses >64-byte nicks for
/// itself) and is skipped.
const NAMES_ENTRY_MAX_BYTES: usize = 96;
/// ...and every connection's in-flight NAMES buffers together hold at most this many
/// entries (≈ 3 MiB at the entry cap). A real NAMES burst fills one channel's buffer at
/// a time (353…366), so this only bites a server that withholds 366 on purpose.
const NAMES_BUF_MAX_TOTAL: usize = 32_768;
/// Member lists of all tracked channels of one connection together (366 / JOIN / NICK
/// can't grow them past this; ≈ 17 MiB at the entry cap — far above any real client,
/// e.g. 100 big Libera channels are ~50k entries).
const MEMBERS_MAX_TOTAL: usize = 131_072;

fn members_total(chans: &HashMap<String, ChannelState>) -> usize {
    chans.values().map(|ch| ch.names.len()).sum()
}
/// #43: cap the number of channels a single connection will track. A malicious
/// server can forge unlimited `:<ournick> JOIN #chanN` lines to grow c.channels,
/// create per-channel log dirs, and amplify outbound NAMES requests without bound.
pub(crate) const MAX_CHANNELS_PER_CONN: usize = 256;
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

const LIST_REQUEST_IDLE: Duration = Duration::from_secs(60);
// IRC can burst 1,024 lines into a 128-event WebSocket ring. Batch directory
// rows so a large LIST does not displace earlier rows or unrelated chat events.
const LIST_BATCH_ROWS: usize = 64;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChannelListEntry {
    channel: String,
    users: u32,
    topic: String,
}

pub(crate) struct ChannelListRequest {
    request_id: Option<String>,
    last_activity: Instant,
    entries: Vec<ChannelListEntry>,
    total: usize,
    incomplete: Option<&'static str>,
}

impl ChannelListRequest {
    fn new(request_id: Option<String>) -> Self {
        Self { request_id, last_activity: Instant::now(), entries: Vec::new(), total: 0, incomplete: None }
    }
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
    pub(crate) e2e_bridge: crate::e2e_bridge::Bridge,
    pub(crate) reactions: crate::reactions::Reactions,
    pub(crate) keepnick_retry: crate::keepnick::Retry,
    pub self_userhost: String,
    /// Web-side idempotency guard for a replayed/duplicate 001 (mirrors the old
    /// run_loop-local `registered` bool, now persisted on the connection so it
    /// survives across separate `dispatch_line` calls).
    pub registered: bool,
    /// One unlabelled IRC LIST stream per connection. Browser requests have an ID.
    pub(crate) list_request: Option<ChannelListRequest>,
    /// Was a run_loop-local var; now persists across per-line calls.
    pub echo_message_enabled: bool,
    /// Was a run_loop-local var; accumulates 353 lines until 366 flushes.
    pub names_buf: HashMap<String, Vec<String>>,
    /// Case-folded channel keys with an in-flight self-triggered WHO (JOIN-time only now).
    pub who_pending: HashSet<String>,
    /// Accumulates away nicks per channel for the in-flight WHO.
    pub who_away: HashMap<String, Vec<String>>,
    /// codex P2 ipc_client.rs:294: at most ONE paced SessionSync resync job per
    /// connection at a time (every SessionSync used to spawn another for every still-
    /// memberless channel — the daemon sends one per JOIN/PART/NICK and per 30 s PONG).
    pub resync_busy: bool,
    /// Bumped on every Reconnecting/Disconnected: a running resync job whose generation
    /// no longer matches stops sending (its socket is gone).
    pub resync_gen: u64,
    /// When each channel (irc_lower) was last scheduled for a resync, so a channel whose
    /// server never answers NAMES isn't re-burst on every heartbeat.
    pub resync_recent: HashMap<String, std::time::Instant>,
    /// codex P2 irc_daemon.rs:144 (web side): the server's CASEMAPPING, from a 005 line
    /// or the daemon's SessionSync. Every channel-keyed map here is keyed by its fold.
    pub casemapping: CaseMapping,
    /// The CASEMAPPING the server ANNOUNCED (any 005, or a SessionSync token), None while
    /// unknown. Unlike `casemapping` — which stays rfc1459 under an older irc_core so its
    /// SessionSync names keep matching — this is the server's real rule, used to decide
    /// whether two saved channel-key spellings are the same channel (codex P2 irc.rs:206).
    pub server_casemapping: Option<CaseMapping>,
    /// The endpoint this connection really dials: the daemon's SessionSync report, else
    /// what this web process sent in its Dial, else the config as first seen. E2E network
    /// identity is taken from this, never from `cfg` (which UpdateNetwork refreshes while
    /// the connection runs) — codex P2 main.rs:6834 / agy P2.
    pub dial_endpoint: Option<(String, u16)>,
    /// r4: the server's ISUPPORT STATUSMSG prefixes (from a 005 line), None while unknown
    /// (then ircproto::DEFAULT_STATUSMSG applies) — see `incoming_channel_target`.
    pub statusmsg: Option<String>,
    /// r4 V3I-N1: the channel list of the daemon's latest SessionSync for this connection
    /// (see ipc_client::deferred_membership_check).
    pub daemon_channels: Vec<String>,
    /// r6 (codex P2 irc.rs:366): channels this web asked to JOIN on this connection (folded;
    /// every user /join, Join dialog and the Send path go through send_raw). With the saved
    /// auto-join list they are the channels the user chose — a tracked channel outside both
    /// (a server-forced or spoofed self-JOIN) is not exempt from the log-target budget.
    /// Bounded by USER_JOINS_MAX.
    pub user_joins: HashSet<String>,
    /// r7 (codex P2 ircproto.rs:490): the server's CHANMODES / PREFIX from its 005 lines —
    /// which mode letters carry a parameter (see ircproto::ChanModes).
    pub chanmodes: ChanModes,
    /// Avatars: nicks this connection's server returned in a WHOIS reply recently — they
    /// count as "seen by the viewer" for avatar discovery (avatar::discover).
    pub whois_seen: crate::avatar::SeenNicks,
    /// Avatars: the user@host this connection's server showed for each nick (avatar::observe_line).
    pub seen_userhosts: crate::avatar::SeenHosts,
    /// Avatars: the irc-core link generation of the latest SessionSync for this connection
    /// (ipc_client::current_link) — its live flags are trusted only on that same link.
    pub synced_link: u64,
    /// Avatars: this connection's CAP LS listing was seen (negotiation completed) / one of its
    /// CAP or ISUPPORT lines was a bouncer's (avatar::note_cap_line). Reset on reconnect.
    pub cap_ls_done: bool,
    pub behind_bouncer: bool,
    /// Retained daemon facts are available for attach recovery (never gate live input).
    pub daemon_registration: bool,
    /// Last daemon IRC session whose facts we adopted; zero for older daemons.
    pub registration_epoch: u64,
    /// Live 001 may precede a coalesced snapshot. Adopt its next epoch without
    /// clearing live evidence, but only on this IPC link (never across an outage).
    pub live_registration_link: Option<u64>,
    /// During an Attach replay only: the (nick, user@host) we had when each replayed line
    /// arrived, as 069f376 tracked it in `nick` — set from the snapshot, moved by replayed
    /// self NICK / JOIN / CHGHOST lines under the same ident rule, cleared at AttachComplete.
    /// Used ONLY to tell which REPLAYED lines are ours — echoes among PRIVMSG / NOTICE, our
    /// own JOIN / PART / KICK / typing, where 069f376 read its moving `nick`; the real
    /// identity (`nick`, `self_userhost`) never follows replayed lines (adopt_self_nick).
    /// Known residual, pre-existing and accepted: the view starts from the CURRENT nick (the
    /// snapshot), not the nick we had when the ring began, so lines from someone who held our
    /// current nick earlier in the ring (before we took it) count as ours — 069f376's `nick`
    /// started and moved exactly the same way.
    pub replay_view: Option<(String, String)>,
    /// Remote avatars (avatar::remote): announces other CryptIRC servers' users made on this
    /// connection, and what it negotiated for them. Reset with the IRC session (ipc_client).
    pub avx: crate::avatar::remote::ConnState,
    /// Cached at connection-creation time (Dial or Attach-rehydration) so
    /// `dispatch_line` never needs a disk read per IRC line — the original
    /// single-process code kept this as a stable in-memory variable for the
    /// whole session; this preserves that instead of re-fetching per line.
    /// Refreshed by whichever handler already updates the on-disk config
    /// (UpdateNetwork) — see main.rs.
    pub cfg: NetworkConfig,
}

/// Cap on IrcConnection::user_joins (a real client never nears it; past it, a new channel's
/// first log directory simply counts against the day's channel budget).
const USER_JOINS_MAX: usize = 1024;

impl IrcConnection {
    /// Shared reset for lifecycle reconnects and replacements discovered on Attach.
    pub(crate) fn reset_irc_session(&mut self) {
        self.connected = false;
        self.registered = false;
        self.list_request = None;
        self.e2e_bridge = Default::default();
        self.reactions = Default::default();
        self.keepnick_retry = Default::default();
        self.who_pending.clear();
        self.whois_seen.clear();
        self.seen_userhosts.clear();
        self.cap_ls_done = false;
        self.behind_bouncer = false;
        self.daemon_registration = false;
        self.registration_epoch = 0;
        self.live_registration_link = None;
        self.avx.reset();
        self.resync_gen = self.resync_gen.wrapping_add(1);
        self.resync_busy = false;
    }

    pub(crate) fn note_live_registration(&mut self) {
        self.live_registration_link = Some(crate::ipc_client::current_link());
    }

    /// True when retained state belonged to a different IRC session. A live 001
    /// already establishes the new session even if its snapshot was coalesced.
    pub(crate) fn adopt_registration_epoch(&mut self, epoch: u64) -> bool {
        if epoch == 0 { return false; }
        let replaced = self.registration_epoch != 0 && self.registration_epoch != epoch
            && self.live_registration_link != Some(crate::ipc_client::current_link());
        if replaced { self.reset_irc_session(); }
        self.registration_epoch = epoch;
        self.live_registration_link = None;
        replaced
    }

    /// A registered, connected test connection dialing `server:port` as `nick`.
    #[cfg(test)]
    pub(crate) fn for_test(conn_id: &str, nick: &str, server: &str, port: u16) -> IrcConnection {
        IrcConnection {
            conn_id: conn_id.into(), nick: nick.into(), connected: true, lag_ms: None,
            channels: HashMap::new(), ipc_out: Arc::new(tokio::sync::Mutex::new(None)), message_tags: false, e2e_bridge: Default::default(), reactions: Default::default(), keepnick_retry: Default::default(),
            self_userhost: String::new(), registered: true, list_request: None, echo_message_enabled: false,
            names_buf: HashMap::new(), who_pending: HashSet::new(), who_away: HashMap::new(),
            resync_busy: false, resync_gen: 0, resync_recent: HashMap::new(),
            casemapping: CaseMapping::default(), server_casemapping: None,
            dial_endpoint: Some((server.to_string(), port)),
            statusmsg: None, daemon_channels: Vec::new(), user_joins: HashSet::new(), chanmodes: ChanModes::default(),
            whois_seen: Default::default(), seen_userhosts: Default::default(), synced_link: 1, cap_ls_done: true, behind_bouncer: false, daemon_registration: false, registration_epoch: 0, live_registration_link: None, replay_view: None, avx: Default::default(), cfg: NetworkConfig::default(),
        }
    }

    /// Our own identity (nick, user@host) from a NICK / JOIN / CHGHOST line. A REPLAYED line
    /// never changes it: the attach snapshot (SessionSync, sent before any replayed line) is
    /// the current state, and a historical line could otherwise make this connection "be"
    /// whoever held its nick earlier — e.g. replaying `:Old!u@victim NICK Victim` on the
    /// connection that holds Old NOW (codex re-check H avatar.rs:1005; it fed avatar
    /// discovery, E2E nick resolution, self-echo suppression and the #30 spoof guard).
    /// Live lines keep the #30 rule: the source must carry the ident we recorded (or ours is
    /// not known yet). Returns whether the nick changed.
    pub(crate) fn adopt_self_nick(&mut self, old: &str, new: &str, src_userhost: &str, replayed: bool) -> bool {
        if replayed || !same_nick(old, &self.nick)
            || !(self.self_userhost.is_empty() || cryptirc::irc_daemon::same_ident(src_userhost, &self.self_userhost))
        {
            return false;
        }
        self.nick = strip_crlf(new);
        self.keepnick_retry.clear_pending();
        if !src_userhost.is_empty() { self.self_userhost = src_userhost.to_string(); }
        true
    }
    /// Replayed self NICK: move the replay-only view (see `replay_view`) like 069f376 moved
    /// `nick` — the old nick is ours and the source carries our ident (or ours is unknown).
    pub(crate) fn replay_follow_nick(&mut self, old: &str, new: &str, src_userhost: &str) {
        if let Some((nick, uh)) = self.replay_view.as_mut() {
            if same_nick(old, nick) && (uh.is_empty() || cryptirc::irc_daemon::same_ident(src_userhost, uh)) {
                *nick = strip_crlf(new);
                if !src_userhost.is_empty() { *uh = src_userhost.to_string(); }
            }
        }
    }
    /// Replayed self JOIN / guarded CHGHOST: the replay-only view's user@host.
    pub(crate) fn replay_follow_userhost(&mut self, nick: &str, src_userhost: &str, new_userhost: &str, guarded: bool) {
        if let Some((vn, uh)) = self.replay_view.as_mut() {
            if !same_nick(nick, vn) || new_userhost.is_empty() { return; }
            if guarded && !(uh.is_empty() || cryptirc::irc_daemon::same_ident(src_userhost, uh)) { return; }
            *uh = new_userhost.to_string();
        }
    }
    /// The nick we had when this line arrived — what our own lines (echoes, self JOIN / PART
    /// / KICK) carry: during an Attach replay the replay-only view, otherwise the real nick.
    pub(crate) fn echo_nick(&self, replayed: bool) -> String {
        match (&self.replay_view, replayed) {
            (Some((n, _)), true) => n.clone(),
            _ => self.nick.clone(),
        }
    }

    /// Our own user@host from a live self-JOIN (see adopt_self_nick).
    pub(crate) fn adopt_self_join_userhost(&mut self, nick: &str, userhost: &str, replayed: bool) {
        if !replayed && same_nick(nick, &self.nick) && !userhost.is_empty() { self.self_userhost = userhost.to_string(); }
    }
    /// Update our own user@host from a live, guarded CHGHOST (see adopt_self_nick).
    pub(crate) fn adopt_self_chghost(&mut self, nick: &str, src_userhost: &str, user: &str, host: &str, replayed: bool) -> bool {
        if replayed || !same_nick(nick, &self.nick) { return false; }
        if !(self.self_userhost.is_empty() || cryptirc::irc_daemon::same_ident(src_userhost, &self.self_userhost)) { return false; }
        let Some(userhost) = cryptirc::irc_daemon::clean_userhost(&format!("{}@{}", user, host)) else { return false };
        if self.self_userhost == userhost { return false; }
        self.self_userhost = userhost;
        true
    }

    /// r6: remember the channels of an outgoing `JOIN` (see `user_joins`).
    fn note_user_join(&mut self, line: &str) {
        let mut rest = line.trim_end_matches(['\r', '\n']).trim_start_matches(' ');
        if rest.starts_with('@') { rest = rest.split_once(' ').map_or("", |(_, t)| t).trim_start_matches(' '); }
        let mut it = rest.split(' ').filter(|t| !t.is_empty());
        if !it.next().is_some_and(|v| v.eq_ignore_ascii_case("JOIN")) { return; }
        let Some(chans) = it.next() else { return };
        for ch in chans.trim_start_matches(':').split(',') {
            if !ch.starts_with(['#', '&', '+', '!']) { continue; }
            let k = self.casemapping.fold(ch);
            if self.user_joins.len() < USER_JOINS_MAX || self.user_joins.contains(&k) { self.user_joins.insert(k); }
        }
    }

    /// r6: a channel the user chose on this connection — joined through this web, or on the
    /// saved auto-join list (which the daemon joins at registration without a web JOIN).
    pub fn user_chose_channel(&self, channel: &str) -> bool {
        let k = self.casemapping.fold(channel);
        self.user_joins.contains(&k) || self.cfg.auto_join.iter().any(|a| self.casemapping.fold(a) == k)
    }

    /// Record the CASEMAPPING the server announced (see `server_casemapping`).
    pub fn note_server_casemapping(&mut self, cm: CaseMapping) {
        self.server_casemapping = Some(cm);
        known_casemappings().insert(self.conn_id.clone(), cm);
    }

    /// Adopt a (new) CASEMAPPING and re-key every channel-keyed map under it. Channels
    /// keep their display spelling, from which the new key is derived.
    pub fn set_casemapping(&mut self, cm: CaseMapping) {
        if cm == self.casemapping { return; }
        let spelling: HashMap<String, String> = self.channels.iter()
            .map(|(k, ch)| (k.clone(), ch.name.clone())).collect();
        self.casemapping = cm;
        for (_, ch) in std::mem::take(&mut self.channels) {
            self.channels.entry(cm.fold(&ch.name)).or_insert(ch);
        }
        let refold = |k: &str| cm.fold(spelling.get(k).map_or(k, |s| s.as_str()));
        self.names_buf = std::mem::take(&mut self.names_buf).into_iter().map(|(k, v)| (refold(&k), v)).collect();
        self.who_away = std::mem::take(&mut self.who_away).into_iter().map(|(k, v)| (refold(&k), v)).collect();
        self.who_pending = std::mem::take(&mut self.who_pending).into_iter().map(|k| refold(&k)).collect();
        self.resync_recent = std::mem::take(&mut self.resync_recent).into_iter().map(|(k, v)| (refold(&k), v)).collect();
        self.user_joins = std::mem::take(&mut self.user_joins).into_iter().map(|k| refold(&k)).collect();
    }

    /// Hand one line to the daemon. codex P2 irc.rs:102: this returned Ok even with no
    /// IPC link (or a dead writer), so the Send handler logged + echoed a message that
    /// never left this process. Err now means "definitely not handed to irc-core".
    /// (Ok still can't promise delivery — the daemon may be reconnecting — which is why
    /// Send also checks connected/registered.)
    pub async fn send_raw(&mut self, line: &str) -> Result<()> {
        let mut fields = line.split_ascii_whitespace().peekable();
        if fields.peek().is_some_and(|f| f.starts_with('@')) { fields.next(); }
        if fields.peek().is_some_and(|f| f.starts_with(':')) { fields.next(); }
        let verb = fields.next().unwrap_or("");
        if verb.eq_ignore_ascii_case("LIST") {
            return self.send_list(line, None).await;
        }
        if verb.eq_ignore_ascii_case("NICK") { self.keepnick_retry.clear_pending(); }
        self.note_user_join(line);
        self.send_to_daemon(line).await
    }

    pub(crate) async fn send_list(&mut self, line: &str, request_id: Option<String>) -> Result<()> {
        anyhow::ensure!(self.connected && self.registered, "This network is offline.");
        // Some servers reject a request without sending a terminal numeric.
        // Release an idle slot on retry, but keep it while replies are arriving.
        anyhow::ensure!(self.list_request.as_ref().is_none_or(|list| list.last_activity.elapsed() >= LIST_REQUEST_IDLE),
            "A channel list is already in progress on this connection.");
        self.send_to_daemon(line).await?;
        let mut list = ChannelListRequest::new(request_id);
        if self.list_request.is_some() {
            // An unlabelled server might still return the old reply after a stall.
            // Show the received rows, but do not cache this ambiguous response.
            list.incomplete = Some("An earlier IRC channel list did not finish. Refresh again to cache a fresh list.");
        }
        self.list_request = Some(list);
        Ok(())
    }

    fn note_list_reply(&mut self) -> &mut ChannelListRequest {
        let list = self.list_request.get_or_insert_with(|| ChannelListRequest::new(None));
        list.last_activity = Instant::now();
        list
    }

    async fn send_to_daemon(&self, line: &str) -> Result<()> {
        match self.ipc_out.lock().await.as_ref() {
            Some(tx) => tx
                .send(IpcMessage::RawSend { conn_id: self.conn_id.clone(), line: line.to_string() })
                .map_err(|_| anyhow::anyhow!("irc-core link is down")),
            None => Err(anyhow::anyhow!("irc-core link is down")),
        }
    }
}

// ─── Entry point: reconnect loop ─────────────────────────────────────────────

/// Extract the +k key from a 324-style "<+modes> <param…>" string (the currently-set
/// Persist a learned channel key into the network config's channel_keys (under the
/// per-config lock, mirroring the JoinChannel/PartChannel writers) so auto-rejoin — and
/// a fresh connect after a full server restart — can re-enter a keyed channel whose +k
/// was set/changed AFTER we joined. key=Some(k) saves; key=None removes (-k). Only writes
/// when the value actually changes, so repeated 324s/MODE echoes don't churn the disk.
async fn persist_channel_key(state: &AppState, username: &str, conn_id: &str, channel: &str, key: Option<&str>, cm: Option<CaseMapping>) {
    let lock = network_config_lock(username, conn_id);
    let _guard = lock.lock().await;
    if let Some(mut cfg) = state.get_network_config(conn_id, username).await {
        // Storage form is to_lowercase() (same as main.rs's JOIN/JoinChannel writers). If
        // the server spells the channel in a different RFC1459 fold than the stored entry
        // (`#key{x}` vs a stored `#key[x]`) AND folds specials itself, update THAT entry
        // rather than adding a second, stale-able one next to it.
        let lc = existing_key_slot(&cfg.channel_keys, channel, cm);
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

/// The `channel_keys` map key to read/update/delete for `channel`: its exact
/// to_lowercase() storage form if present; else an existing entry that is the same
/// channel under the server's CASEMAPPING `cm` (rfc1459: `#a{b}` = `#a[b]`; ascii: only
/// letter case); else the to_lowercase() form (a new entry). codex P2 irc.rs:206 / w-srv
/// #14: this used to fold rfc1459 unconditionally, so on an ascii-casemapping server
/// (ergo, UnrealIRCd 6, InspIRCd 4) parting keyless `#x{y}` deleted `#x[y]`'s key and
/// +k on `#x{y}` overwrote it. With the mapping unknown (`None`) only the exact spelling
/// is touched — leaving a stale key is harmless, deleting another channel's is not.
pub(crate) fn existing_key_slot(keys: &HashMap<String, String>, channel: &str, cm: Option<CaseMapping>) -> String {
    let lc = channel.to_lowercase();
    if keys.contains_key(&lc) { return lc; }
    let Some(cm) = cm else { return lc };
    let folded = cm.fold(channel);
    keys.keys().find(|k| cm.fold(k) == folded).cloned().unwrap_or(lc)
}

/// The last CASEMAPPING each connection's server announced (this process), so a part
/// while the connection is down still decides key slots by the server's rule.
fn known_casemappings() -> &'static dashmap::DashMap<String, CaseMapping> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, CaseMapping>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}
pub(crate) fn known_casemapping(conn_id: &str) -> Option<CaseMapping> {
    known_casemappings().get(conn_id).map(|v| *v)
}

/// CHGHOST from someone else: did the host change at all? Not when the line's own source prefix
/// already carries the new host. An unknown source host counts as a change (as before).
fn chghost_host_changed(src_userhost: &str, new_host: &str) -> bool {
    let old = src_userhost.rsplit_once('@').map_or("", |(_, h)| h);
    old.is_empty() || !old.eq_ignore_ascii_case(new_host)
}

/// The join-time key seed for `channel` from the cached config: exact spelling first,
/// then the server's fold (exact-only while its CASEMAPPING is unknown). A still-
/// encrypted value (the cfg was read while the vault was locked) is no key — judged with
/// the validated blob check, so a real key that merely starts with "enc:" still counts
/// (codex P2 ipc_client.rs:857 / agy P2).
fn seed_channel_key(keys: &HashMap<String, String>, channel: &str, cm: Option<CaseMapping>) -> Option<String> {
    channel_key_lookup_cm(keys, channel, cm.unwrap_or(CaseMapping::Ascii))
        .filter(|k| !crate::AppState::is_enc_blob(k))
        .cloned()
}

// ─── Lines that arrive while the owner's vault is locked (codex P2 ipc_server.rs:979) ──
// The logger cannot encrypt without the vault key, so such a line used to be dropped from
// history for good — notably the whole Attach-replay backlog right after a web restart,
// when every vault starts locked (and the daemon then counts those lines as delivered).
// They are now HELD in memory (bounded) and written at the next unlock, with their
// original timestamps. r4 (w3-irc V3I-C2-5 partial): EVERY such line is held, also one a
// connected session already displayed (id-less) — that used to be dropped from history when
// a tab was open while the vault was locked. The browser now stamps the id-less row with the
// id when the flushed line comes back from history (r4/web IRC-H2: an id'd history line
// whose ts|from|text matches an id-less row stamps it), so it is not shown twice.

/// Per-account and process-wide bounds on held lines.
const HELD_LINES_PER_USER: usize = 4000;
const HELD_BYTES_PER_USER: usize = 2 * 1024 * 1024;
const HELD_BYTES_TOTAL: usize = 32 * 1024 * 1024;
static HELD_BYTES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// `ack`: the daemon line this was (IPC link generation, RawLine.seq) when it came from an
/// irc_core that keeps such a line undelivered until we say it was logged (r5, see AckCtx).
struct HeldLine { conn_id: String, target: String, ts: i64, from: String, text: String, kind: String, ack: Option<(u64, u64)> }
impl HeldLine {
    fn weight(&self) -> usize { 96 + self.conn_id.len() + self.target.len() + self.from.len() + self.text.len() + self.kind.len() }
    fn same(&self, conn_id: &str, target: &str, ts: i64, from: &str, text: &str, kind: &str) -> bool {
        self.ts == ts && self.conn_id == conn_id && self.target == target && self.from == from && self.text == text && self.kind == kind
    }
}

// ─── r5 (codex P2 ipc_client.rs:293): hold-aware acknowledgements ─────────────────────
// A line held in memory (vault locked) is not durable: a web restart before the unlock loses
// it. With a proc_ack irc_core every processed line is acknowledged, so the daemon counted
// such a line as delivered and a later replay treated it as already logged — lost for good.
// Now ipc_client dispatches each numbered line inside ACK_CTX; when log_line queues it, it
// tells a `hold_ack` daemon (IpcMessage::Held, r8: at that moment, see announce_held) to keep
// it undelivered until flush_held_logs has written it (IpcMessage::Released). A web that dies before the unlock
// therefore gets those lines again, as backlog, from the daemon's ring.
// Across an IPC link reset (same daemon) the ring replays them: a replayed copy of a line
// still held is matched by content and only re-pointed at the new link's seq (written once);
// lines of an earlier link that the replay did not bring back (the daemon restarted) are
// released from that link at AttachComplete (settle_stale_held) and written normally.

/// The numbered daemon line being dispatched (see above).
#[derive(Default, Clone, Copy)]
pub(crate) struct AckCtx { pub link: u64, pub seq: u64, pub replay: bool }
tokio::task_local! { pub(crate) static ACK_CTX: std::cell::Cell<AckCtx>; }

/// `epoch` (r5, agy P1 main.rs:326): the account generation (AuthManager::account_epoch) the
/// lines were held for. held_logs is keyed by username, so lines held for an account that was
/// deleted since must never be written to — or counted against — a later same-name account.
#[derive(Default)]
struct HeldLogs { lines: std::collections::VecDeque<HeldLine>, bytes: usize, dropped: u64, epoch: u64 }

fn held_logs() -> &'static dashmap::DashMap<String, HeldLogs> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, HeldLogs>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}

/// r5 (codex P2 irc.rs:865 HIGH, backstop; security-hook follow-up): every NEW log target is
/// a new directory + daily file (src/logs.rs), so a hostile server streaming lines for unique
/// nicks / channels could exhaust the shared disk's space or inodes. Targets that already
/// exist are never limited: "status", a tracked channel the user chose (r6: joined through
/// this web or on the saved auto-join list — not one a server JOINed us to), and any target
/// with a log directory already (an earlier conversation — including everything the user
/// wrote: their own lines are logged with log_own_line, which creates the directory). Only
/// NEW targets count, per connection and UTC day, in two budgets (DM partners; other channel
/// names); past a
/// budget a line is not dropped but written to ONE per-connection overflow target
/// (`*overflow*`, open it with /query *overflow*), prefixed with its real target, and the
/// user gets one status notice per connection and day.
const NEW_DM_TARGETS_PER_CONN_DAY: usize = 256;
const NEW_CHAN_TARGETS_PER_CONN_DAY: usize = 64;
pub(crate) const OVERFLOW_TARGET: &str = "*overflow*";

#[derive(Default)]
struct TargetBudget { day: i64, dms: HashSet<String>, chans: HashSet<String>, noticed: bool }

fn log_targets() -> &'static dashmap::DashMap<String, TargetBudget> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, TargetBudget>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}

/// Budget check for a NEW target (see above): Ok(()) = counted / already counted today;
/// Err(first) = over budget (first = the first refusal today for this connection).
/// The key is exactly what names the directory logger.append creates — the encoded,
/// case-PRESERVING path component — so every distinct directory costs one slot (a flood of
/// case variants `Bob`/`BOB`/`bOb`… used to cost one slot but create a directory each).
fn new_target_budget(conn_id: &str, target: &str) -> Result<(), bool> {
    let day = chrono::Utc::now().timestamp().div_euclid(86_400);
    let key = crate::logs::encode_path_component(target).unwrap_or_else(|_| target.to_string());
    let mut b = log_targets().entry(conn_id.to_string()).or_default();
    if b.day != day { *b = TargetBudget { day, ..Default::default() }; }
    let is_chan = target.starts_with(['#', '&', '+', '!']);
    let (set, cap) = if is_chan { (&mut b.chans, NEW_CHAN_TARGETS_PER_CONN_DAY) } else { (&mut b.dms, NEW_DM_TARGETS_PER_CONN_DAY) };
    if set.contains(&key) { return Ok(()); }
    if set.len() < cap { set.insert(key); return Ok(()); }
    let first = !b.noticed;
    b.noticed = true;
    Err(first)
}

/// r9 (astra P2 irc.rs:412): per connection, the spelling each chosen channel's lines are
/// logged under (by the connection's case fold) — fixed the first time and kept across
/// PART/JOIN: a self-PART drops the ChannelState and the next self-JOIN may come back in
/// another capitalization, which would otherwise be a new exempt directory. At most
/// USER_JOINS_MAX per connection.
fn log_spellings() -> &'static dashmap::DashMap<String, HashMap<String, String>> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, HashMap<String, String>>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new)
}

/// If `target` is an existing log target of `conn_id` (never limited, see above): the exact
/// name to log it under.
/// r7 (codex P2 irc.rs:404): a channel the user chose is matched under the connection's case
/// fold, but its lines are logged under the ONE spelling it is tracked with — the logger's
/// directories are case-preserving, so logging each incoming spelling (`#Chan`, `#CHAN`,
/// `#cHaN`…) made a new exempt directory per variant. One chosen channel = one directory.
async fn existing_log_target(state: &AppState, conn_id: &str, target: &str) -> Option<String> {
    if target == "status" || target == OVERFLOW_TARGET { return Some(target.to_string()); }
    let conn = state.connections.get(conn_id).map(|c| c.clone());
    if let Some(conn) = conn {
        let c = conn.lock().await;
        let k = c.casemapping.fold(target);
        // r9 (astra P2 irc.rs:412): a chosen channel keeps the spelling it was first logged
        // under — also across a self-PART + self-JOIN in another capitalization.
        if let Some(name) = log_spellings().get(conn_id).and_then(|m| m.get(&k).cloned()) { return Some(name); }
        // r6 (codex P2 irc.rs:366): tracked is not enough — a hostile server's
        // `:me JOIN #uniqueN` / `:me PART #uniqueN` churn keeps the tracked set small while
        // every JOIN would make a new directory. Exempt only a channel the user chose.
        if let Some(ch) = c.channels.get(&k) {
            if c.user_chose_channel(target) {
                let mut m = log_spellings().entry(conn_id.to_string()).or_default();
                if m.len() < USER_JOINS_MAX { m.insert(k, ch.name.clone()); }
                return Some(ch.name.clone());
            }
        }
    }
    let canon = crate::auth::validate_uuid(conn_id);
    let (Ok(enc_conn), Ok(enc_target)) = (crate::logs::encode_path_component(canon.as_deref().unwrap_or(conn_id)),
                                          crate::logs::encode_path_component(target)) else { return None };
    let dir = std::path::Path::new(state.logger.data_dir()).join("logs").join(enc_conn).join(enc_target);
    tokio::fs::metadata(&dir).await.map(|m| m.is_dir()).unwrap_or(false).then(|| target.to_string())
}

/// Where a line for `target` is logged: itself, or — a new target past today's budget —
/// the overflow target with the real target in front of the text.
async fn route_log_target<'a>(state: &AppState, username: &str, conn_id: &str, target: &'a str, text: &'a str)
    -> (std::borrow::Cow<'a, str>, std::borrow::Cow<'a, str>) {
    use std::borrow::Cow;
    if let Some(name) = existing_log_target(state, conn_id, target).await {
        return (if name == target { Cow::Borrowed(target) } else { Cow::Owned(name) }, Cow::Borrowed(text));
    }
    match new_target_budget(conn_id, target) {
        Ok(()) => (Cow::Borrowed(target), Cow::Borrowed(text)),
        Err(first) => {
            if first {
                warn!("[{}] new log targets over today's budget — further new conversations go to {}", conn_id, OVERFLOW_TARGET);
                state.send_to_user(username, ServerEvent::IrcMessage {
                    replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: "status".into(),
                    text: format!("⚠ Logging limited: too many new conversations from this network today. Further private messages from new nicks (and lines for unknown channels) are saved under {} — open it with /query {}. Nothing is lost; known conversations and your channels are logged as usual.", OVERFLOW_TARGET, OVERFLOW_TARGET),
                    ts: chrono::Utc::now().timestamp(), kind: MessageKind::Notice, msg_id: 0, prefix: None,
                });
            }
            (Cow::Borrowed(OVERFLOW_TARGET), Cow::Owned(format!("[{}] {}", target, text)))
        }
    }
}

/// r7: the window around the receive time in which a server-time tag is believed (see
/// dispatch_line).
const SERVER_TIME_MAX_PAST: i64 = 7 * 86_400;
const SERVER_TIME_MAX_FUTURE: i64 = 5 * 60;

/// Write one chat/status line to `username`'s history — or, while the vault is locked,
/// hold it for the next unlock (see above). Returns the log id (0 = not written now).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_line(state: &AppState, username: &str, conn_id: &str, target: &str, ts: i64, from: &str, text: &str, kind: &str) -> u64 {
    log_line_as(state, username, conn_id, target, ts, from, text, kind, false).await
}

/// r5 (agy P2 main.rs:6036): the user's OWN outgoing line (Send handler). It used to go to
/// logger.append directly, which writes nothing while the vault is locked (the user's side
/// of the conversation was lost) and, right after an unlock, could be written before the
/// lines still held from the locked period. Now it takes the same hold path as every other
/// line — held while locked, flushed in arrival order; written only after what is held — but
/// it is never budgeted or routed to *overflow*: what the user wrote lands in its own
/// conversation. Returns the log id (0 while held: the browser's id-less echo row is stamped
/// when the flushed line comes back from history, r4/web IRC-H2).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn log_own_line(state: &AppState, username: &str, conn_id: &str, target: &str, ts: i64, from: &str, text: &str, kind: &str) -> u64 {
    log_line_as(state, username, conn_id, target, ts, from, text, kind, true).await
}

#[allow(clippy::too_many_arguments)]
async fn log_line_as(state: &AppState, username: &str, conn_id: &str, target: &str, ts: i64, from: &str, text: &str, kind: &str, own: bool) -> u64 {
    let (target, text) = if own {
        (std::borrow::Cow::Borrowed(target), std::borrow::Cow::Borrowed(text))
    } else {
        route_log_target(state, username, conn_id, target, text).await
    };
    let (target, text): (&str, &str) = (target.as_ref(), text.as_ref());
    let ctx = ACK_CTX.try_with(|c| c.get()).ok();
    let replay = ctx.map_or(false, |c| c.replay);
    if state.crypto.is_unlocked(username).await {
        if held_logs().contains_key(username) {
            // r5: the daemon's replayed copy of a line still held from an earlier link is
            // written now, once — drop the held copy.
            if replay {
                if let Some(mut h) = held_logs().get_mut(username) {
                    if let Some(i) = h.lines.iter().position(|l| l.same(conn_id, target, ts, from, text, kind)) {
                        if let Some(old) = h.lines.remove(i) {
                            let ow = old.weight();
                            h.bytes -= ow;
                            HELD_BYTES.fetch_sub(ow, std::sync::atomic::Ordering::AcqRel);
                        }
                    }
                }
            }
            // Anything held from a locked period first, so ids follow arrival order.
            flush_held_logs(state, username).await;
        }
        // r7 (codex P2 / agy P1 irc.rs:483): the vault may have been locked again while this
        // line waited for the flush (or during the write itself) — then it is held like any
        // line arriving while locked, never handed to a logger that writes nothing.
        if state.crypto.is_unlocked(username).await {
            let id = state.logger.append(username, conn_id, target, ts, from, text, kind).await;
            if id > 0 { return id; }
            // r8 (codex P2 irc.rs:505): a write that failed with the vault still open (disk
            // full, I/O error) is held like a locked-vault line — retried by the next flush,
            // its daemon copy kept unacknowledged — not acknowledged as processed and lost.
            // A name the logger can never write is not held.
            if crate::logs::encode_path_component(target).is_err() { return 0; }
        }
    }
    // r5 (srv-a): nothing is held for an account whose deletion is running (its lines can
    // never be written; purge_account discards what was held before). Not marked held: the
    // daemon may count it delivered.
    if state.auth.is_being_deleted(username) { return 0; }
    // Not durable from here on. r7 (agy P1 irc.rs:492): the line is reported `held` to
    // ipc_client (see AckCtx: the daemon then keeps it until released) only once it is really
    // in the queue — a line the process-wide hold budget drops is acknowledged normally, never
    // parked in irc-core with no one left to release it.
    let ack = ctx.filter(|c| c.seq > 0).map(|c| (c.link, c.seq));
    // r8 (codex P2 ipc_client.rs:339): Held goes out the moment the line is queued — under the
    // queue's lock, on the same IPC channel as any later Released — so a flush can never
    // release it before the daemon knows it is held.
    let mark_held = || { if let Some((link, seq)) = ack { crate::ipc_client::announce_held(link, seq); } };
    if replay {
        // A replayed copy of a line already held (an earlier link): re-point it, don't add —
        // unless what is held belongs to an earlier account of this name (cleared below).
        let epoch = state.auth.account_epoch(username);
        if let Some(mut h) = held_logs().get_mut(username) {
            if h.epoch == epoch {
                if let Some(l) = h.lines.iter_mut().find(|l| l.same(conn_id, target, ts, from, text, kind)) {
                    l.ack = ack;
                    mark_held();
                    return 0;
                }
            }
        }
    }
    let line = HeldLine { conn_id: conn_id.into(), target: target.into(), ts, from: from.into(), text: text.into(), kind: kind.into(), ack };
    let w = line.weight();
    if HELD_BYTES.fetch_add(w, std::sync::atomic::Ordering::AcqRel) + w > HELD_BYTES_TOTAL {
        HELD_BYTES.fetch_sub(w, std::sync::atomic::Ordering::AcqRel);
        // At most one warning a minute (this path runs per line while the budget is full).
        static LAST_WARN: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);
        let now = chrono::Utc::now().timestamp();
        let prev = LAST_WARN.load(std::sync::atomic::Ordering::Acquire);
        if now - prev >= 60 && LAST_WARN.compare_exchange(prev, now, std::sync::atomic::Ordering::AcqRel, std::sync::atomic::Ordering::Acquire).is_ok() {
            warn!("vault-locked lines not held: process-wide hold budget ({} MiB) exhausted", HELD_BYTES_TOTAL >> 20);
        }
        return 0;
    }
    let epoch = state.auth.account_epoch(username);
    let mut h = held_logs().entry(username.to_string()).or_insert_with(|| HeldLogs { epoch, ..Default::default() });
    let mut stale_acks: Vec<(u64, u64)> = Vec::new();
    if h.epoch != epoch {
        // r5: left over from an earlier account of this name — drop it, never carry it over
        // (and let the daemon forget those lines: they are discarded on purpose).
        HELD_BYTES.fetch_sub(h.bytes, std::sync::atomic::Ordering::AcqRel);
        stale_acks.extend(h.lines.iter().filter_map(|l| l.ack));
        h.lines.clear(); h.bytes = 0; h.dropped = 0; h.epoch = epoch;
    }
    h.lines.push_back(line);
    h.bytes += w;
    mark_held();
    while h.lines.len() > HELD_LINES_PER_USER || h.bytes > HELD_BYTES_PER_USER {
        let Some(old) = h.lines.pop_front() else { break };
        let ow = old.weight();
        h.bytes -= ow;
        HELD_BYTES.fetch_sub(ow, std::sync::atomic::Ordering::AcqRel);
        h.dropped += 1;
        // r7: dropped by the per-account bound — the daemon must not keep it parked (unless a
        // sibling record of the same IRC line is still held, see unshared_acks).
        stale_acks.extend(old.ack);
    }
    let stale_acks = unshared_acks(&h, stale_acks);
    drop(h);
    crate::ipc_client::release_held(&stale_acks);
    0
}

/// r7 (codex P2 irc.rs:673): one IRC line can be held as several records sharing its IPC
/// seq (a QUIT or NICK lands in every channel it concerns). Of the acks about to be released,
/// keep back those another record still held in `h` carries — the last sibling to be
/// written or discarded releases it.
fn unshared_acks(h: &HeldLogs, acks: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    if acks.is_empty() || h.lines.is_empty() { return acks; }
    let still: HashSet<(u64, u64)> = h.lines.iter().filter_map(|l| l.ack).collect();
    let mut acks = acks;
    acks.retain(|a| !still.contains(a));
    acks.sort_unstable();
    acks.dedup();
    acks
}

/// r6: one flush at a time per account. A line logged while a flush runs waits for it (the
/// unlocked path of log_line flushes first), so ids follow arrival order.
fn flush_lock(username: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    static M: std::sync::OnceLock<dashmap::DashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>> = std::sync::OnceLock::new();
    M.get_or_init(dashmap::DashMap::new).entry(username.to_string()).or_default().clone()
}

/// Does `username` still own the network `conn_id`? The live owner map when it has an entry;
/// otherwise the saved network (r6, codex P2 irc.rs:533: an explicit Disconnect removes the
/// conn_owners entry and reconnect_for_user skips such a network, so "no live entry" is NOT
/// "not the account's network"). The account generation is checked by the caller.
async fn account_owns_network(state: &AppState, username: &str, conn_id: &str) -> bool {
    if let Some(o) = state.conn_owners.get(conn_id) { return o.as_str() == username; }
    let Some(id) = crate::auth::validate_uuid(conn_id) else { return false };
    let path = std::path::Path::new(&state.data_dir).join("networks").join(username).join(format!("{}.json", id));
    tokio::fs::metadata(&path).await.map(|m| m.is_file()).unwrap_or(false)
}

/// TEST HOOK (r6): `CRYPTIRC_TEST_SLOW_FLUSH_MS=<1..10000>` makes every held-line write in
/// flush_held_logs wait that long first, so a test can lock, clear or delete in the middle of
/// a flush. Unset (production) it does nothing; read once.
fn test_slow_flush() -> Option<std::time::Duration> {
    static D: std::sync::OnceLock<Option<std::time::Duration>> = std::sync::OnceLock::new();
    *D.get_or_init(|| std::env::var("CRYPTIRC_TEST_SLOW_FLUSH_MS").ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|ms| (1..=10_000).contains(ms))
        .map(std::time::Duration::from_millis))
}

/// Put lines back at the FRONT of `username`'s held queue, in the given order (they are
/// older than anything queued meanwhile) — only while the account is still the generation
/// `epoch` they were held for (`current` = its generation now) and the queue is that
/// generation's. Otherwise they are dropped and their acknowledgements returned for release
/// (r6 security follow-up: never into a re-registered same-name account's queue).
fn requeue_front(username: &str, epoch: u64, current: u64, lines: Vec<HeldLine>) -> Vec<(u64, u64)> {
    if lines.is_empty() { return Vec::new(); }
    let mut h = held_logs().entry(username.to_string()).or_insert_with(|| HeldLogs { epoch: current, ..Default::default() });
    if current != epoch || h.epoch != epoch {
        let empty = h.lines.is_empty();
        drop(h);
        if empty { held_logs().remove_if(username, |_, h| h.lines.is_empty() && h.dropped == 0); }
        return lines.iter().filter_map(|l| l.ack).collect();
    }
    for l in lines.into_iter().rev() {
        let w = l.weight();
        h.bytes += w;
        HELD_BYTES.fetch_add(w, std::sync::atomic::Ordering::AcqRel);
        h.lines.push_front(l);
    }
    Vec::new()
}

/// Write everything held for `username` (call with the vault unlocked). A line of a network
/// the account no longer owns (removed meanwhile, or the account was deleted and its name
/// taken again) is discarded, never written.
/// r6 (codex P1 irc.rs:537): lines are taken one at a time and only a written (or deliberately
/// discarded) line leaves the queue — if the vault is locked again meanwhile (another device),
/// the line being written and everything after it stay held for the next unlock (the user's
/// own lines have no daemon copy to fall back on), and their acknowledgements stay unsent.
pub(crate) async fn flush_held_logs(state: &AppState, username: &str) {
    if !held_logs().contains_key(username) { return; }
    let lock = flush_lock(username);
    let _flushing = lock.lock().await;
    let epoch = state.auth.account_epoch(username);
    // r5 (agy P1 main.rs:326): held for an earlier account of this name (deleted since), or
    // the account is being deleted: never written.
    let other_gen = held_logs().get(username).map_or(false, |h| h.epoch != epoch);
    if other_gen || state.auth.is_being_deleted(username) {
        let Some((_, held)) = held_logs().remove(username) else { return };
        HELD_BYTES.fetch_sub(held.bytes, std::sync::atomic::Ordering::AcqRel);
        if !held.lines.is_empty() {
            info!("discarded {} line(s) held for an earlier account named {}", held.lines.len(), username);
        }
        let released: Vec<(u64, u64)> = held.lines.iter().filter_map(|l| l.ack).collect();
        crate::ipc_client::release_held(&released);   // discarded on purpose
        return;
    }
    if let Some(mut h) = held_logs().get_mut(username) {
        if h.dropped > 0 {
            warn!("{} line(s) received while {}'s vault was locked exceeded the hold bound and were not logged", h.dropped, username);
            h.dropped = 0;
        }
    }
    // r5: a line of an EARLIER IPC link waits for that link's settlement (the replay may bring
    // the daemon's copy back — writing ours now would duplicate it); see settle_stale_held.
    let cur = crate::ipc_client::current_link();
    let mut back: Vec<HeldLine> = Vec::new();
    let mut owns: HashMap<String, bool> = HashMap::new();
    let mut released: Vec<(u64, u64)> = Vec::new();
    let (mut n, mut written, mut relocked, mut aborted, mut write_failed) = (0usize, 0usize, false, false, false);
    loop {
        let line = {
            let Some(mut h) = held_logs().get_mut(username) else { break };
            let Some(l) = h.lines.pop_front() else { break };
            let w = l.weight();
            h.bytes -= w;
            HELD_BYTES.fetch_sub(w, std::sync::atomic::Ordering::AcqRel);
            l
        };
        if line.ack.map_or(false, |(link, _)| link != cur) { back.push(line); continue; }
        n += 1;
        let owned = match owns.get(&line.conn_id) {
            Some(o) => *o,
            None => {
                let o = account_owns_network(state, username, &line.conn_id).await;
                owns.insert(line.conn_id.clone(), o);
                o
            }
        };
        if !owned {
            if let Some(a) = line.ack { released.push(a); }   // deliberately not written
            continue;
        }
        if let Some(d) = test_slow_flush() { tokio::time::sleep(d).await; }
        // r6 security follow-up: the account may have been deleted (and its name taken again)
        // while this flush awaited — checked before EVERY write, never only at the start.
        if state.auth.account_epoch(username) != epoch || state.auth.is_being_deleted(username) {
            released.extend(line.ack);
            released.extend(back.drain(..).filter_map(|l| l.ack));
            // r7 (agy P1 irc.rs:662): atomically, only the old generation's queue — never a
            // queue a re-registered same-name account has created meanwhile.
            if let Some((_, h)) = held_logs().remove_if(username, |_, h| h.epoch == epoch) {
                HELD_BYTES.fetch_sub(h.bytes, std::sync::atomic::Ordering::AcqRel);
                released.extend(h.lines.iter().filter_map(|l| l.ack));
            }
            aborted = true;
            break;
        }
        if state.logger.append(username, &line.conn_id, &line.target, line.ts, &line.from, &line.text, &line.kind).await > 0 {
            written += 1;
            if let Some(a) = line.ack { released.push(a); }
        } else if !state.crypto.is_unlocked(username).await {
            back.push(line);
            relocked = true;
            break;
        } else if crate::logs::encode_path_component(&line.conn_id).is_err() || crate::logs::encode_path_component(&line.target).is_err() {
            // r6 (agy P2 irc.rs:537): a name the logger can never write — dropped on purpose,
            // and the daemon is told so it does not keep the line parked forever.
            warn!("a line held for {} can never be logged ({} / {}) — dropped", username, line.conn_id, line.target);
            released.extend(line.ack);
        } else {
            // r6 (agy P2 irc.rs:537): a write error (disk full, I/O): the line stays held — in
            // order, its daemon copy still unacknowledged — and the next flush retries it.
            warn!("a line held for {} could not be written now ({} / {}) — kept for the next try", username, line.conn_id, line.target);
            back.push(line);
            write_failed = true;
            break;
        }
    }
    let current = if state.auth.is_being_deleted(username) { epoch.wrapping_add(1) } else { state.auth.account_epoch(username) };
    released.extend(requeue_front(username, epoch, current, back));
    // r7: a seq whose sibling record is still held is released by that sibling, later.
    let released = match held_logs().get(username) { Some(h) => unshared_acks(&h, released), None => released };
    held_logs().remove_if(username, |_, h| h.lines.is_empty() && h.dropped == 0);
    crate::ipc_client::release_held(&released);
    if n > 0 {
        info!("logged {} of {} line(s) held while {}'s vault was locked{}", written, n, username,
              if aborted { " — the account was deleted meanwhile; the rest is discarded" }
              else if relocked { " — locked again meanwhile; the rest stays held" }
              else if write_failed { " — a write failed; the rest stays held for the next try" } else { "" });
    }
}

/// r5: after an Attach cycle (its replay is done): held lines of an earlier IPC link that the
/// replay did not re-point are no longer in the daemon (it restarted) — they become plain
/// held lines (no ack) and are written now if their owner's vault is unlocked.
pub(crate) async fn settle_stale_held(state: &AppState) {
    let cur = crate::ipc_client::current_link();
    let users: Vec<String> = held_logs().iter().map(|e| e.key().clone()).collect();
    for u in users {
        if let Some(mut h) = held_logs().get_mut(&u) {
            for l in h.lines.iter_mut() {
                if l.ack.map_or(false, |(link, _)| link != cur) { l.ack = None; }
            }
        }
        if state.crypto.is_unlocked(&u).await { flush_held_logs(state, &u).await; }
    }
}

/// Forget held lines (Clear All Data / clear a target's history): `conn_id`/`target`
/// None = all.
/// r6 security follow-up: serialized with flush_held_logs (the same per-account lock) — a
/// flush in progress finishes first and nothing it holds in hand survives the discard; the
/// callers delete the log files AFTER this returns, so a clear always wins over a flush.
pub(crate) async fn discard_held_logs(username: &str, conn_id: Option<&str>, target: Option<&str>) {
    let lock = flush_lock(username);
    let _flushing = lock.lock().await;
    let mut released: Vec<(u64, u64)> = Vec::new();
    {
        let Some(mut h) = held_logs().get_mut(username) else { return };
        let before = h.bytes;
        h.lines.retain(|l| {
            let gone = conn_id.map_or(true, |c| c == l.conn_id) && target.map_or(true, |t| t.eq_ignore_ascii_case(&l.target));
            if gone { if let Some(a) = l.ack { released.push(a); } }
            !gone
        });
        h.bytes = h.lines.iter().map(HeldLine::weight).sum();
        HELD_BYTES.fetch_sub(before - h.bytes, std::sync::atomic::Ordering::AcqRel);
        released = unshared_acks(&h, std::mem::take(&mut released));
    }
    // r5 (srv-a): an emptied entry goes too (account deletion discards everything).
    held_logs().remove_if(username, |_, h| h.lines.is_empty());
    // r5 (irc): discarded on purpose — the daemon must not replay them as backlog.
    crate::ipc_client::release_held(&released);
}

#[cfg(test)]
mod r5_held_tests {
    use super::*;
    /// r5 (agy P1 main.rs:326): discarding everything (account deletion) removes the entry and
    /// gives its bytes back to the process-wide budget.
    /// r7 (codex P2 irc.rs:673): records sharing one IRC line's seq (a QUIT in two channels)
    /// release it only when the last of them leaves the queue.
    #[test]
    fn a_shared_seq_is_released_by_its_last_record() {
        let mk = |t: &str, seq: u64| HeldLine { conn_id: "c".into(), target: t.into(), ts: 1, from: "f".into(), text: "quit".into(), kind: "quit".into(), ack: Some((1, seq)) };
        let h = HeldLogs { lines: vec![mk("#b", 7), mk("#c", 9)].into(), bytes: 0, dropped: 0, epoch: 1 };
        assert_eq!(unshared_acks(&h, vec![(1, 7), (1, 8)]), vec![(1, 8)], "7 still has a sibling held");
        let empty = HeldLogs::default();
        assert_eq!(unshared_acks(&empty, vec![(1, 7), (1, 7)]), vec![(1, 7), (1, 7)], "nothing held: unchanged");
        assert_eq!(unshared_acks(&h, vec![(1, 8), (1, 8)]), vec![(1, 8)], "deduplicated");
    }

    /// r6 security follow-up: lines a flush hands back go in front of their own generation's
    /// queue only — never into a re-registered same-name account's queue (acks are returned).
    #[test]
    fn requeue_never_crosses_an_account_generation() {
        let mk = |seq: u64| HeldLine { conn_id: "c".into(), target: "#t".into(), ts: seq as i64, from: "f".into(), text: format!("l{seq}"), kind: "privmsg".into(), ack: Some((1, seq)) };
        let fresh = || format!("rq-{}", uuid::Uuid::new_v4().simple());
        let u = fresh();
        let l3 = mk(3); let w = l3.weight();
        HELD_BYTES.fetch_add(w, std::sync::atomic::Ordering::AcqRel);
        held_logs().insert(u.clone(), HeldLogs { lines: vec![l3].into(), bytes: w, dropped: 0, epoch: 5 });
        assert!(requeue_front(&u, 5, 5, vec![mk(1), mk(2)]).is_empty());
        assert_eq!(held_logs().get(&u).map(|h| h.lines.iter().map(|l| l.ts).collect::<Vec<_>>()), Some(vec![1, 2, 3]), "back in front, in order");
        let u2 = fresh();
        held_logs().insert(u2.clone(), HeldLogs { epoch: 6, ..Default::default() });
        assert_eq!(requeue_front(&u2, 5, 6, vec![mk(7)]), vec![(1, 7)], "a newer account's queue takes nothing");
        assert!(held_logs().get(&u2).map_or(true, |h| h.lines.is_empty()));
        let u3 = fresh();
        assert_eq!(requeue_front(&u3, 5, 6, vec![mk(8)]), vec![(1, 8)], "the account changed: no queue is created");
        assert!(held_logs().get(&u3).is_none());
        let u4 = fresh();
        held_logs().insert(u4.clone(), HeldLogs { epoch: 5, ..Default::default() });
        assert_eq!(requeue_front(&u4, 5, 6, vec![mk(9)]), vec![(1, 9)], "the account was deleted meanwhile");
        discard_all_for_test(&[u, u2, u3, u4]);
    }

    fn discard_all_for_test(users: &[String]) {
        for u in users {
            if let Some((_, h)) = held_logs().remove(u) { HELD_BYTES.fetch_sub(h.bytes, std::sync::atomic::Ordering::AcqRel); }
        }
    }

    #[tokio::test]
    async fn discarding_everything_removes_the_entry() {
        let u = format!("heldtest-{}", uuid::Uuid::new_v4().simple());
        let line = HeldLine { conn_id: "c".into(), target: "#t".into(), ts: 1, from: "f".into(), text: "x".repeat(100), kind: "privmsg".into(), ack: None };
        let w = line.weight();
        HELD_BYTES.fetch_add(w, std::sync::atomic::Ordering::AcqRel);
        held_logs().insert(u.clone(), HeldLogs { lines: vec![line].into(), bytes: w, dropped: 0, epoch: 7 });
        assert_eq!(held_logs().get(&u).map(|h| (h.lines.len(), h.bytes, h.epoch)), Some((1, w, 7)));
        discard_held_logs(&u, Some("other"), None).await;
        assert!(held_logs().get(&u).is_some(), "a partial discard keeps the rest");
        discard_held_logs(&u, None, None).await;
        assert!(held_logs().get(&u).is_none(), "entry removed");
    }
}

// ─── Outgoing chat lines: what is logged/echoed = what goes on the wire (r4 C1-9) ───────
// codex P1 main.rs:5882: the Send handler logged and echoed the WHOLE text, while irc-core
// cuts the message part of every line to 510 bytes and the IRC server relays at most 512
// bytes INCLUDING our `:nick!user@host` prefix — recipients got a prefix of what the
// sender's devices and history showed. fit_outgoing_line decides, before anything is
// sent, the exact lines that go out: a PRIVMSG/NOTICE text that would not reach the
// recipients whole is split into pieces that do (each piece is then logged and echoed as
// its own line), and a line that cannot be sent as written is refused with a reason.

/// IRCv3 message-tags: a client's tag data (without the leading `@` and the separating
/// space) is at most 4094 bytes; servers reject longer (ERR_INPUTTOOLONG).
pub(crate) const CLIENT_TAG_DATA_MAX: usize = 4094;
/// Bytes assumed for our own `user@host` while it is unknown (it is learned from our own
/// JOIN / CHGHOST): USERLEN 10 + `~`, `@`, HOSTLEN 63.
const UNKNOWN_USERHOST_LEN: usize = 75;
/// Slack for a host change the server announced only by numeric (a cloak via 396).
const RELAY_MARGIN: usize = 10;
/// A text is cut into at most this many lines. More would arrive as a burst that IRC
/// servers' flood protection answers with "Excess Flood" (irc-core does not pace);
/// longer text is refused (a paste is the tool for it).
pub(crate) const MAX_SPLIT_LINES: usize = 4;
/// Smallest piece budget ever used (a pathological nick/target length).
const MIN_PIECE_BUDGET: usize = 64;

/// What one outgoing raw line becomes on the wire: Ok(lines to send, in order — the input
/// itself when it fits) or Err(reason it is refused; nothing is sent). `nick` /
/// `self_userhost` = our identity on the connection (the relay prefix the server adds).
pub(crate) fn fit_outgoing_line(line: &str, nick: &str, self_userhost: &str) -> Result<Vec<String>, String> {
    let skip_sp = |s: &str| s.trim_start_matches(' ').len();
    // Byte offset of the message part (after an optional `@tags` section).
    let lead = line.len() - skip_sp(line);
    let mut msg_start = lead;
    if line[lead..].starts_with('@') {
        let tag_end = line[lead..].find(' ').map_or(line.len(), |i| lead + i);
        let data = tag_end - lead - 1;
        if data > CLIENT_TAG_DATA_MAX {
            return Err(format!("Message tags too long ({} bytes; IRC allows {}). Nothing was sent.", data, CLIENT_TAG_DATA_MAX));
        }
        msg_start = line.len() - skip_sp(&line[tag_end..]);
    }
    let msg = &line[msg_start..];
    let too_long = || -> Result<Vec<String>, String> {
        Err(format!("Line too long for IRC ({} bytes; at most {}). Nothing was sent.", msg.len(), cryptirc::irc_daemon::OUT_MSG_MAX))
    };
    // The verb and, for PRIVMSG/NOTICE, the target and a `:` text.
    let mut rest = msg;
    if rest.starts_with(':') { rest = &rest[rest.len() - skip_sp(rest.split_once(' ').map_or("", |(_, t)| t))..]; }
    let (verb, after_verb) = rest.split_once(' ').unwrap_or((rest, ""));
    let is_chat = verb.eq_ignore_ascii_case("PRIVMSG") || verb.eq_ignore_ascii_case("NOTICE");
    let after_verb = &after_verb[after_verb.len() - skip_sp(after_verb)..];
    let (target, after_target) = after_verb.split_once(' ').unwrap_or((after_verb, ""));
    let after_target_trim = &after_target[after_target.len() - skip_sp(after_target)..];
    let text = after_target_trim.strip_prefix(':');
    let max = cryptirc::irc_daemon::OUT_MSG_MAX;
    let (Some(text), true, false) = (text, is_chat, target.is_empty()) else {
        // Not a chat line with a `:` text: nothing to split. A chat line irc-core would cut
        // is refused (chat is logged and echoed); any other line goes out as before
        // (irc-core cuts it to the IRC limit; none of it is logged or echoed).
        return if is_chat && msg.len() > max { too_long() } else { Ok(vec![line.to_string()]) };
    };
    // Everything up to and including the `:` that starts the text, exactly as written.
    let head = &line[..line.len() - text.len()];
    let head_msg_len = head.len() - msg_start;
    // What each recipient receives: `:nick!user@host VERB target :text` ≤ 510 bytes.
    let uh = if self_userhost.is_empty() { UNKNOWN_USERHOST_LEN } else { self_userhost.len() + RELAY_MARGIN };
    let relay_over = 1 + nick.len() + 1 + uh + 1 + verb.len() + 1 + target.len() + 2;
    let room = max.saturating_sub(relay_over).min(max.saturating_sub(head_msg_len));
    if room > 0 && text.len() <= room { return Ok(vec![line.to_string()]); }
    // r7 (codex P2 irc.rs:863): the recipients alone leave (almost) no room for the text. A
    // floor of MIN_PIECE_BUDGET here let a short text through that irc-core then cut off.
    if room < MIN_PIECE_BUDGET {
        return Err(format!("Too many recipients for one IRC line (they leave {} bytes for the text). Nothing was sent — send to fewer recipients at a time.", room));
    }
    let budget = room;
    // E2E ciphertext (sized by the browser) and CTCP other than ACTION are opaque: never cut.
    let opaque = text.starts_with("sd8~") || text.starts_with("[e2edm") || text.starts_with("[e2ex3dh]")
        || (text.starts_with('\u{1}') && !text.starts_with("\u{1}ACTION "));
    if opaque {
        // r8 (codex P2 irc.rs:935): it does not fit what the recipients receive (`room`
        // counts the server-added `:nick!user@host` prefix) — the server would cut it and the
        // ciphertext could not be decrypted, so it is refused, never sent whole-looking.
        return Err(format!("Encrypted message too long for this target ({} bytes; at most {} fit once the server adds your nick and host). Nothing was sent.", text.len(), room));
    }
    let (pre, body, suf) = match text.strip_prefix("\u{1}ACTION ") {
        Some(b) => match b.strip_suffix('\u{1}') { Some(b2) => ("\u{1}ACTION ", b2, "\u{1}"), None => ("\u{1}ACTION ", b, "") },
        None => ("", text, ""),
    };
    let piece_budget = budget.saturating_sub(pre.len() + suf.len()).max(MIN_PIECE_BUDGET / 2);
    let pieces = split_text_bytes(body, piece_budget);
    if pieces.len() > MAX_SPLIT_LINES {
        return Err(format!(
            "Message too long ({} bytes; at most about {} fit in {} IRC lines). Nothing was sent — use a paste for long text.",
            body.len(), piece_budget * MAX_SPLIT_LINES, MAX_SPLIT_LINES));
    }
    Ok(pieces.into_iter().map(|p| format!("{}{}{}{}", head, pre, p, suf)).collect())
}

/// Cut `text` into pieces of at most `max` bytes on char boundaries, at the last space
/// of a piece when that keeps more than 60% of it (the space is dropped there).
fn split_text_bytes(text: &str, max: usize) -> Vec<&str> {
    let max = max.max(4);
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > max {
        let mut end = max;
        while !rest.is_char_boundary(end) { end -= 1; }
        match rest[..end].rfind(' ') {
            Some(sp) if sp * 10 > end * 6 => { out.push(&rest[..sp]); rest = &rest[sp + 1..]; }
            _ => { out.push(&rest[..end]); rest = &rest[end..]; }
        }
    }
    if !rest.is_empty() || out.is_empty() { out.push(rest); }
    out
}

/// r4 (codex P1 irc.rs:591 MED / P2 irc.rs:591 LOW): the channel conversation an incoming
/// PRIVMSG/NOTICE/TAGMSG addressed to `target` belongs to, or None for a private target.
/// A STATUSMSG target (`@#staff`, `+#staff`, …) is a message to that channel's members
/// holding the status, so it belongs to the channel (`true` in the result) — it used to be
/// filed as a private message from the sender: logged into the DM, notified as a DM, and
/// answerable by the private AI path. Order: a channel we track under exactly this name
/// (a channel whose name starts with a prefix-like character), then a STATUSMSG prefix,
/// then a plain channel name.
pub(crate) fn incoming_channel_target(c: &IrcConnection, target: &str) -> Option<(String, bool)> {
    if target.is_empty() { return None; }
    if c.channels.contains_key(&c.casemapping.fold(target)) { return Some((target.to_string(), false)); }
    if let Some((_, chan)) = statusmsg_target(target, c.statusmsg.as_deref()) {
        return Some((chan.to_string(), true));
    }
    target.starts_with(['#', '&', '+', '!']).then(|| (target.to_string(), false))
}

/// Remote avatars: drop announces of nicks this connection no longer sees (after a PART /
/// KICK — v1's rule: a nick outside the viewer's channels is not vouched for).
/// `left`: the nick that left (someone else), or None for our own PART / KICK.
async fn prune_remote_avatars(send: &impl Fn(ServerEvent), conn: &Arc<Mutex<IrcConnection>>, conn_id: &str, left: Option<&str>) {
    let gone = {
        let mut c = conn.lock().await;
        crate::avatar::remote::on_departure(&mut c, left)
    };
    if !gone.is_empty() {
        send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: gone });
    }
}

fn ctcp_request(text: &str) -> Option<String> {
    let body = text.strip_prefix('\x01')?;
    let body = body.strip_suffix('\x01').unwrap_or(body);
    let command = body.split(' ').next()?;
    if body.contains('\x01') || command.is_empty() || command.len() > 32
        || !command.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || command.eq_ignore_ascii_case("ACTION")
    { return None; }
    Some(command.to_ascii_uppercase())
}

/// Route incoming NOTICEs to a channel, the server view, the recipient for an
/// outgoing NOTICE, or the sender. Ignore live echoes of our own NOTICEs.
pub(crate) fn notice_display_target(c: &IrcConnection, from: &str, target: &str, has_prefix: bool, replayed: bool, in_batch: bool) -> Option<String> {
    let user_nick = c.echo_nick(replayed);
    if c.echo_message_enabled && same_nick(from, &user_nick) && !in_batch { return None; }
    Some(if let Some((ch, _)) = incoming_channel_target(c, target) {
        ch
    } else if from == "*" || from.contains('.') || !has_prefix {
        "status".to_string()
    } else if same_nick(from, &user_nick) {
        target.to_string()
    } else {
        from.to_string()
    })
}

/// Forget our membership of a channel the server says we are not in (a refused rejoin,
/// or the daemon's snapshot), and tell the account's sessions so they stop showing it as
/// joined. `nick` = our nick, for the synthesized self-PART.
pub(crate) fn forget_channel_membership(state: &AppState, username: &str, conn_id: &str, c: &mut IrcConnection, key: &str, reason: &str) -> bool {
    let Some(ch) = c.channels.remove(key) else { return false };
    c.names_buf.remove(key);
    c.who_pending.remove(key);
    c.who_away.remove(key);
    state.send_to_user(username, ServerEvent::IrcPart {
        conn_id: conn_id.to_string(), nick: c.nick.clone(), channel: ch.name, reason: reason.to_string(),
        ts: chrono::Utc::now().timestamp(),
    });
    true
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
/// `backlog` / `recv_ts`: see IpcMessage::RawLine. A backlog line is replay the daemon
/// never handed to any web before (it arrived while no web was attached): it is NEW to
/// history, so it is logged (codex P2 irc.rs:359) and shown to browsers as new, while
/// replay-only side effects (bots, automode, AI capture, the 433 notice) still skip it.
/// `recv_ts` (> 0 only from a daemon that sends it) is when the daemon read the line.
#[allow(clippy::too_many_arguments)]
pub async fn dispatch_line(
    state: &AppState,
    username: &str,
    conn_id: &str,
    conn: &Arc<Mutex<IrcConnection>>,
    line: &str,
    replayed: bool,
    backlog: bool,
    recv_ts: i64,
) -> anyhow::Result<()> {
    let p = parse_irc(line);
    // Correlate live nick failures with this connection's automatic attempt.
    // Only dedicated nick-change numerics can be correlated without a nick.
    if !replayed && matches!(p.command.as_str(), "432" | "433" | "435" | "436" | "437" | "438" | "447" | "484") {
        let nickless = p.command == "447" || (matches!(p.command.as_str(), "435" | "438") && p.params.len() <= 2);
        let mut c = conn.lock().await;
        let mapping = c.casemapping;
        if c.registered && c.keepnick_retry.matches_refusal(&p.params, mapping, nickless) {
            if p.command != "432" { return Ok(()); }
            // A permanent bad-nick refusal is surfaced once in the status tab.
            c.keepnick_retry.pause();
        }
    }
    // Avatars: what this Attach replay says about the irc-core session (avatar::restorable).
    if replayed { crate::avatar::note_replayed_line(conn_id, backlog, recv_ts, &p.command, &p.params); }
    // The channel-name fold for this connection (adopting a CASEMAPPING announced now).
    // Only with a daemon that folds the same way (it sends recv_ts): an older irc_core
    // folds everything rfc1459 and sends SessionSync channel names in that fold, so on an
    // ascii server switching the web to ascii would turn such a stub (`#a{b}` for
    // `#a[b]`) into a separate phantom channel. With an old daemon nothing changes.
    let mut isupport_bouncer = false;
    let promoted: Vec<String>;
    let cm = {
        let mut c = conn.lock().await;
        if !replayed && matches!(p.command.as_str(), "401" | "403" | "404" | "439" | "531") {
            if let Some(target) = p.params.get(1) {
                crate::reactions::refuse_echo(&mut c, target);
            }
        }
        if p.command == "005" {
            if !replayed { c.keepnick_retry.learn_limit(&p.params); }
            if let Some(n) = CaseMapping::from_isupport(&p.params) {
                c.note_server_casemapping(n);
                if recv_ts > 0 { c.set_casemapping(n); }
            }
            if let Some(s) = statusmsg_from_isupport(&p.params) { c.statusmsg = Some(s); }
            c.chanmodes.learn(&p.params);
            isupport_bouncer = crate::avatar::note_isupport_line(&mut c, &p.params);
        }
        // Avatars: the user@host this line shows for a nick (see avatar::discover rule 5).
        crate::avatar::observe_line(&mut c, p.prefix.as_deref(), &p.command, &p.params);
        // Remote avatars: metadata values held until their nick's user@host was known.
        promoted = crate::avatar::remote::promote_held(&mut c);
        c.casemapping
    };
    if isupport_bouncer { state.avatars.mark_session_bouncer(conn_id); }
    // First time this web process (or any web, for backlog) handles this line: the only
    // case in which it is written to history.
    let first_seen = !replayed || backlog;
    // An old daemon (no recv_ts) can't say what was delivered: keep the old behaviour
    // for push (every line); a new one: only first-seen lines (a web restart used to
    // re-push every DM/mention still in the replay ring).
    let push_ok = first_seen || recv_ts == 0;
    // E2E (F10/F11): remember the ISUPPORT NETWORK= name so E2E nick→account lookups
    // can be scoped to "the same IRC network" even when users configured different
    // server hostnames. Observational only — the 005 line is still handled below.
    if p.command == "005" { crate::e2e::note_isupport(conn_id, &p.params); }
    // Feed WHOIS/WHO/NAMES/JOIN/LIST replies to the AI's result-capture when it's
    // armed (owner /aido agent loop). No-op on the hot path when nothing is armed,
    // and never on replayed history.
    if !replayed {
        crate::bots::ai_capture_feed(conn_id, &p.command, &p.params, line);
    }
    // Prefer IRCv3 server-time tag when available
    // ...else the daemon's receive time (replayed lines used to be stamped "now").
    // r7 (codex P2 irc.rs:1015): the tag is the server's word and its date picks the day file
    // (YYYY-MM-DD.log), so a hostile server could make one file per line. It is used only
    // within SERVER_TIME_MAX_PAST .. SERVER_TIME_MAX_FUTURE of the receive time (bouncer and
    // chathistory playback stays dated; a target gets at most ~8 day files a day); outside,
    // the receive time.
    let received = if recv_ts > 0 { recv_ts } else { chrono::Utc::now().timestamp() };
    let ts = p.tags.get("time")
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|dt| dt.timestamp())
        .filter(|t| (received - SERVER_TIME_MAX_PAST..=received + SERVER_TIME_MAX_FUTURE).contains(t))
        .unwrap_or(received);
    // Remote avatars: announces count only on a classified, non-bouncer connection and never
    // on playback (avatar::remote::announce_is_fresh); a restricted connection (behind a
    // bouncer, or not classified) learns no remote avatar at all and never answers CTCP AVATAR.
    let arrival = crate::avatar::remote::Arrival { replayed, restricted: crate::avatar::remote::restricted(&*conn.lock().await) };
    let announce_fresh = crate::avatar::remote::announce_is_fresh(&p.tags, received, arrival);
    // What browsers are told: backlog is news to them.
    let ui_replayed = replayed && !backlog;
    let send = |evt: ServerEvent| {
        // Stamp the dispatch-level replay flag onto every forwarded chat message
        // so the browser can deterministically silence notifications/unread for
        // ring-buffer history. Every construction site below passes a `false`
        // placeholder; this is the single source of truth. (Live lines →
        // replayed=false, ring-replay lines → replayed=true.)
        let evt = match evt {
            ServerEvent::IrcMessage { conn_id, from, target, text, ts, kind, msg_id, prefix, .. } =>
                ServerEvent::IrcMessage { conn_id, from, target, text, ts, kind, msg_id, prefix, replayed: ui_replayed },
            other => other,
        };
        state.send_to_user(username, evt)
    };

    if !promoted.is_empty() { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: promoted }); }
    // Remote avatars: draft/metadata-2 lines about the `avatar` key (and our subscription)
    // are consumed here — learned, never shown.
    if matches!(p.command.as_str(), "760" | "761" | "766" | "770" | "771" | "772" | "774" | "METADATA" | "FAIL" | "WARN" | "NOTE") {
        let consumed = {
            let mut c = conn.lock().await;
            let own = c.echo_nick(replayed);
            crate::avatar::remote::metadata_line(&mut c, &state.avatar_remote, &p.command, &p.tags, &p.params, &own, received, arrival)
        };
        if let Some(changed) = consumed {
            if let Some(n) = changed { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![n] }); }
            return Ok(());
        }
    }

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
            if !replayed && caps.split_ascii_whitespace().any(|cap| cap == crate::e2e_bridge::CAP) {
                let mut c = conn.lock().await;
                if matches!(sub, "LS" | "NEW") { c.e2e_bridge.advertised = true; }
                if sub == "DEL" { c.e2e_bridge = Default::default(); }
            }
            let prior_reactions = crate::reactions::available(&*conn.lock().await);
            if !replayed && caps.split_ascii_whitespace().any(|cap| cap == crate::reactions::CAP) {
                let mut c = conn.lock().await;
                if matches!(sub, "LS" | "NEW") { c.reactions.advertised = true; }
                if sub == "DEL" { c.reactions = Default::default(); }
            }
            match sub {
                // Avatars: classify this connection from what it negotiated (behind a bouncer /
                // CAP negotiation completed) — avatar::note_cap_line, discover rule 3.
                "LS" | "NEW" => {
                    let mut c = conn.lock().await;
                    crate::avatar::note_cap_line(&mut c, p.prefix.as_deref(), sub, is_multiline, &caps, replayed);
                    // A LIVE negotiation is recorded so a web-only restart keeps it
                    // (avatar::SessionRecord); replayed CAP lines can only add a bouncer mark.
                    if sub == "LS" && !is_multiline && !replayed {
                        let (host, port) = c.dial_endpoint.clone().unwrap_or_else(|| (c.cfg.server.clone(), c.cfg.port));
                        state.avatars.record_session(conn_id, &username, (&host, port), c.behind_bouncer, &state.conn_owners);
                    } else if c.behind_bouncer {
                        state.avatars.mark_session_bouncer(conn_id);
                    }
                    // Remote avatars: the server offers draft/metadata-2 (live lines only; not
                    // when the network config disables it). Requested once registered (001),
                    // or now for a CAP NEW after registration — never during irc-core's own
                    // CAP negotiation.
                    crate::avatar::remote::note_meta2_offer(&mut c, sub, &caps, replayed).await;
                }
                "ACK" => {
                    // L43: Set capability flags on ACK, not on REQ
                    if caps.contains("echo-message") { conn.lock().await.echo_message_enabled = true; }
                    if caps.contains("message-tags") { conn.lock().await.message_tags = true; }
                    let meta_ack = { let mut c = conn.lock().await; crate::avatar::remote::note_meta2_cap(&mut c, sub, &caps, replayed) };
                    if meta_ack {
                        crate::avatar::remote::ensure_meta2_initialized(state, username, conn).await;
                    }
                }
                "NAK" => {
                    let sasl_configured = { let c = conn.lock().await; c.cfg.sasl_external || c.cfg.sasl_plain.is_some() };
                    if sasl_configured && caps.contains("sasl") {
                        send(ServerEvent::SaslStatus { conn_id: conn_id.to_string(), success: false, message: "SASL capability rejected".into() });
                    }
                }
                "DEL" => {
                    if caps.contains("echo-message") { conn.lock().await.echo_message_enabled = false; }
                    let mut c = conn.lock().await;
                    if !replayed && caps.split_ascii_whitespace().any(|cap| cap == "message-tags") { c.message_tags = false; }
                    crate::avatar::remote::note_meta2_cap(&mut c, sub, &caps, replayed);
                    if !replayed && crate::avatar::remote::cap_list_has(&caps, crate::avatar::remote::META_CAP) {
                        state.avatars.set_session_meta2(conn_id, false);
                    }
                }
                _ => {}
            }
            let enabled = crate::reactions::available(&*conn.lock().await);
            if !replayed && enabled != prior_reactions {
                send(ServerEvent::ReactionSupport { conn_id: conn_id.to_string(), enabled });
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
        // #29: SessionSync alone adopts nick/registered/connected and emits Connected.
        // The daemon emits it before 001, but coalescing can delay its delivery until
        // after live registration lines. Remember that boundary for epoch adoption
        // without racing the snapshot's connection-status transition.
        "001" => {
            // Remote avatars: ask for draft/metadata-2 now that registration is over.
            if !replayed {
                let mut c = conn.lock().await;
                c.note_live_registration();
                crate::avatar::remote::request_meta2(&mut c).await;
            }
        }

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
                    send(ServerEvent::IrcMessage { replayed: false,
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
            // On replay, the nick we had when the line arrived (IrcConnection::echo_nick).
            let (user_nick, label) = { let c = conn.lock().await; (c.echo_nick(replayed), c.cfg.label.clone()) };
            // Remote avatars: an announce tag from the line's sender (never a server source,
            // never ourselves) — avatar::remote::learn_from_prefix.
            if let Some(v) = p.tags.get(crate::avatar::remote::TAG_KEY).filter(|_| announce_fresh) {
                let learned = { let mut c = conn.lock().await; crate::avatar::remote::learn_from_prefix(&mut c, &state.avatar_remote, p.prefix.as_deref(), v, crate::avatar::remote::Source::Tag, &user_nick) };
                if let Some(n) = learned { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![n] }); }
            }
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
            if echo_message_enabled && same_nick(&from, &user_nick) && !in_batch {
                if !replayed {
                    if let Some(reference) = p.tags.get("msgid") {
                        let mut c = conn.lock().await;
                        if !incoming_channel_target(&c, &target).is_some_and(|(_, restricted)| restricted) {
                            let clean = text.strip_prefix("\x01ACTION ").and_then(|s| s.strip_suffix('\x01')).unwrap_or(&text);
                            if let Some(event) = crate::reactions::own_wire(&mut c, &target, clean, reference)
                                .and_then(|id| crate::reactions::anchor_event(conn_id, &target, id, reference)) {
                                send(event);
                            }
                        }
                    }
                }
                return Ok(());
            }
            // Requests become private UI events. Replies still use the NOTICE path,
            // and the daemon continues to handle the VERSION reply.
            if let Some(command) = ctcp_request(&text) {
                let from_self = same_nick(&from, &user_nick);
                if !replayed && !in_batch && ts >= received - 60 && !from_self && from != "*" && !from.contains('.')
                    && state.auth.check_ws_kdf_rate_limit(username, &format!("ctcp_notice:{conn_id}")).is_ok() {
                    send(ServerEvent::CtcpRequest { conn_id: conn_id.to_string(), from: from.clone(), command, prefix: p.prefix.clone() });
                }
                if crate::avatar::remote::ctcp_avatar(&text).is_some() {
                    let direct = { let c = conn.lock().await; incoming_channel_target(&c, &target).is_none() };
                    if crate::avatar::remote::may_answer_ctcp(replayed, announce_fresh, direct, from_self, arrival.restricted) {
                        crate::avatar::remote::answer_ctcp(state, username, conn, conn_id, p.prefix.as_deref()).await;
                    }
                }
                return Ok(());
            }
            let (kind, clean) = if text.starts_with("\x01ACTION ") && text.ends_with('\x01') {
                (MessageKind::Action, text[8..text.len()-1].to_string())
            } else { (MessageKind::Privmsg, text) };
            // Route PMs to sender's nick, not our own nick; a channel (incl. a STATUSMSG
            // target such as `@#chan`, r4) to the channel.
            let chan_target = { let c = conn.lock().await; incoming_channel_target(&c, &target) };
            let is_statusmsg = chan_target.as_ref().map_or(false, |(_, st)| *st);
            let display_target = chan_target.map_or_else(|| from.clone(), |(ch, _)| ch);
            // I1: never re-append replayed ring history to the on-disk log — it already
            // exists, and re-appending mints a fresh msg_id per unlocked re-Attach →
            // duplicate chat on the next page load + unbounded log growth. On replay,
            // msg_id 0 (the frontend routes replayed events through its silent/dedup path).
            let msg_id = if first_seen { log_line(state, username, conn_id, &display_target, ts, &from, &clean, kind_str(&kind)).await } else { 0 };
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: from.clone(), target: display_target.clone(), text: clean.clone(), ts, kind, msg_id, prefix: p.prefix.clone() });
            if first_seen && !in_batch && !is_statusmsg && !from.contains('.') && from != "*" && crate::reactions::anchorable_wire(&clean) {
                if let Some(reference) = p.tags.get("msgid") {
                    let mut c = conn.lock().await;
                    if crate::reactions::available(&c) {
                        crate::reactions::remember(&mut c, &display_target, reference, crate::reactions::encrypted_wire(&clean));
                        if let Some(event) = crate::reactions::anchor_event(conn_id, &display_target, msg_id, reference) { send(event); }
                    }
                }
            }
            // Push notification for DMs and mentions — only if no active (non-idle) sessions
            // Fires when: no WS connected at all, OR all connected sessions are idle (20m timeout)
            if push_ok && !same_nick(&from, &user_nick) && (state.user_events.get(username).map_or(true, |tx| tx.receiver_count() == 0) || state.user_is_idle(username)) {
                // #11: spawn the push fan-out DETACHED so it can never block the IRC
                // read loop (which must keep answering PINGs). maybe_notify is now
                // internally concurrent + deadline-bounded + rate-limited.
                let notifier = state.notifier.clone();
                let (u, un, cid, lbl, tgt, frm, txt) = (
                    username.to_string(), user_nick.clone(), conn_id.to_string(),
                    label, display_target.clone(), from.clone(), clean.clone(),
                );
                // Full nick!user@host so host-based /ignore masks also gate push.
                let pfx = p.prefix.clone();
                tokio::spawn(async move {
                    notifier.maybe_notify_with_prefix(&u, &un, &cid, &lbl, &tgt, &frm, pfx.as_deref(), &txt, ts).await;
                });
            }
            // Server-side bot triggers (!w, !ud, …). Only for LIVE channel messages
            // from someone else — never on history replay, never our own lines
            // (those are echo-skipped above anyway). maybe_trigger is a cheap
            // in-memory check; it spawns its own task for any actual fetch/reply.
            // r4: never for a STATUSMSG line (`@#chan`): a channel bot would answer the
            // whole channel (disclosing a message meant for its operators), and it is not
            // a private message either, so the private AI path must not answer it.
            if !replayed && !same_nick(&from, &user_nick) && !is_statusmsg {
                let full_mask = format!("{}!{}", from, userhost_from_prefix(&p.prefix));
                if display_target.starts_with(['#','&','+','!']) {
                    crate::bots::maybe_trigger(state, username, conn_id, conn, &display_target, &from, &full_mask, &clean);
                } else {
                    // A private message TO us — let the AI bot answer in PM if enabled.
                    crate::bots::maybe_ai_pm(state, username, conn_id, conn, &from, &full_mask, &clean);
                }
            }
        }
        "NOTICE" => {
            let from   = nick_from_prefix(&p.prefix);
            let target = p.params.get(0).cloned().unwrap_or_default();
            let text   = p.params.get(1).cloned().unwrap_or_default();
            // Never log the NOTICE text: private notices, services replies (some echo a
            // freshly set password) and CTCP replies would land in plaintext in the
            // journal of an app sold on encrypted logs. Metadata only, at debug.
            debug!("[{}] NOTICE: from={} target={} ({} chars)", conn_id, from, target, text.chars().count());
            let in_batch = p.tags.contains_key("batch");
            // Remote avatars: a CTCP AVATAR answer counts only from the nick we just asked
            // (live); an announce tag counts like on PRIVMSG. CTCP AVATAR lines are never shown.
            let own = { conn.lock().await.echo_nick(replayed) };
            let ctcp = crate::avatar::remote::ctcp_avatar(&text).map(str::to_string);
            // A negative CTCP answer (ERRMSG, …) also voids our query to that nick.
            if ctcp.is_none() && text.starts_with('\u{1}') { state.avatar_remote.forget_query(conn_id, &from); }
            let tagged = p.tags.get(crate::avatar::remote::TAG_KEY).filter(|_| announce_fresh).cloned();
            if ctcp.is_some() || tagged.is_some() {
                let mut learned = None;
                {
                    let mut c = conn.lock().await;
                    if let Some(args) = &ctcp {
                        // Any answer voids our query (once); it counts only on a live, fresh,
                        // non-playback line from the user we asked (same user@host), within
                        // 20 s — and never on a restricted connection (announce_fresh).
                        let asked = state.avatar_remote.take_ctcp_answer(conn_id, &from);
                        if let Some(asked) = asked {
                            let ok = !replayed && !in_batch && announce_fresh && !same_nick(&from, &own)
                                && crate::avatar::remote::answer_matches(asked.as_deref(), &userhost_from_prefix(&p.prefix));
                            if let (true, Some(url)) = (ok, crate::avatar::remote::reply_url(args)) {
                                learned = crate::avatar::remote::learn_from_prefix(&mut c, &state.avatar_remote, p.prefix.as_deref(), url, crate::avatar::remote::Source::Ctcp, &own);
                            }
                        }
                    }
                    if let Some(v) = &tagged {
                        learned = learned.or(crate::avatar::remote::learn_from_prefix(&mut c, &state.avatar_remote, p.prefix.as_deref(), v, crate::avatar::remote::Source::Tag, &own));
                    }
                }
                if let Some(n) = learned { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![n] }); }
                if ctcp.is_some() { return Ok(()); }
            }
            let routed = { let c = conn.lock().await; notice_display_target(&c, &from, &target, p.prefix.is_some(), replayed, in_batch) };
            let Some(display_target) = routed else { return Ok(()) };   // our own echo
            let msg_id = if first_seen { log_line(state, username, conn_id, &display_target, ts, &from, &text, "notice").await } else { 0 };
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from, target: display_target, text, ts, kind: MessageKind::Notice, msg_id, prefix: None });
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
            // Self = the nick we had when the line arrived (replay: the replay-only view, like
            // the echo checks; live: the real nick — 069f376's moving `nick` on both).
            let is_self = { let c = conn.lock().await; same_nick(&nick, &c.echo_nick(replayed)) };
            let (accepted, is_self_join) = {
                let mut c = conn.lock().await;
                let chan_key = cm.fold(&channel); // #92
                if same_nick(&nick, &c.nick) {
                    // #30: learn our own user@host from a self-JOIN so a later forged
                    // `:<ournick> NICK <x>` whose prefix does not match us cannot rewrite c.nick.
                    // Live lines only (see IrcConnection::adopt_self_nick).
                    c.adopt_self_join_userhost(&nick, &userhost_from_prefix(&p.prefix), replayed);
                }
                if replayed {
                    let uh = userhost_from_prefix(&p.prefix);
                    c.replay_follow_userhost(&nick, &uh, &uh, false);
                }
                if is_self {
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
                        // Fold-tolerant (keys are stored under to_lowercase, chan_key is
                        // the irc_lower fold — a `#Key[X]` missed its key).
                        // (An "enc:" blob = still encrypted: the cfg was cached while the
                        // vault was locked — not a usable key, so not a dedup seed either.)
                        let seed_key = seed_channel_key(&c.cfg.channel_keys, &channel, c.server_casemapping);
                        // Seed the member list with OURSELVES rather than leaving it empty.
                        // We are provably a member (this is our own JOIN echo), and an empty
                        // `names` is what ipc_client's resync test reads as "this channel needs
                        // rebuilding" — so any SessionSync landing in the window between this
                        // JOIN and its 366 (the daemon emits one on every JOIN/PART/NICK and on
                        // every 30s heartbeat PONG) fired a whole NAMES/WHO/MODE/TOPIC burst for
                        // a channel we were already resyncing, and the bare MODE in that burst
                        // is what produced the duplicate RPL_CREATIONTIME lines. The 366 below
                        // replaces this list wholesale, so it costs nothing but the race.
                        c.channels.insert(chan_key.clone(), ChannelState { name: channel.clone(), topic: String::new(), names: vec![nick.clone()], key: seed_key });
                        (true, true)
                    } else {
                        warn!("[{}] Ignoring self-JOIN {} — channel cap ({}) reached", conn_id, channel, MAX_CHANNELS_PER_CONN);
                        (false, false)
                    }
                } else {
                    // r5 (codex P2 irc.rs:865 HIGH): someone else's JOIN counts only for a
                    // channel we track. One for any other channel — which a real server never
                    // sends us — used to be logged (a new log target each) and broadcast.
                    let total = members_total(&c.channels);
                    match c.channels.get_mut(&chan_key) {
                        Some(ch) => {
                            if ch.names.len() < NAMES_BUF_MAX_PER_CHAN && nick.len() <= NAMES_ENTRY_MAX_BYTES
                                && total < MEMBERS_MAX_TOTAL { ch.names.push(nick.clone()); }
                            (true, false)
                        }
                        None => (false, false),
                    }
                }
            };
            // Only issue the outbound NAMES amplification for an accepted self-JOIN.
            if is_self_join {
                // strip_crlf: `channel` is a server-supplied JOIN param; an interior
                // \r would otherwise be reflected into the outbound NAMES/WHO (CRLF
                // injection). The reader splits on \n, so a bare \r survives parsing.
                let _ = conn.lock().await.send_raw(&format!("NAMES {}\r\n", strip_crlf(&channel))).await;
                // Seed the nick panel's away state immediately (don't wait for the
                // periodic WHO_INTERVAL tick). Marked pending so the reply is consumed
                // silently rather than dumped to the status buffer.
                // Cap who_pending independently of the c.channels 256-cap: a self-PART
                // removes the channel from c.channels (freeing the #43 slot) but NOT from
                // who_pending, and the removing 315 reply is server-controlled. Without
                // this guard a malicious peer's JOIN/PART churn (never sending 315) grows
                // who_pending without bound → heap exhaustion. Mirrors the who_away guard.
                let chan_key = cm.fold(&channel);
                {
                    let mut c = conn.lock().await;
                    if c.who_pending.len() < NAMES_BUF_MAX_CHANNELS || c.who_pending.contains(&chan_key) {
                        c.who_pending.insert(chan_key);
                    }
                }
                let _ = conn.lock().await.send_raw(&format!("WHO {}\r\n", strip_crlf(&channel))).await;
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
            let suppress_replay_dup = replayed && !backlog && is_self && !is_self_join;
            // Persist for log replay (Lounge-style condense after refresh) —
            // skipped for channels rejected by the cap to bound disk/inode growth.
            // A new daemon (recv_ts > 0) says which replayed lines are new to history
            // (backlog); with an old one keep logging other users' replayed JOINs as before.
            if accepted && !suppress_replay_dup && (first_seen || recv_ts == 0) {
                let mut join_text = format!("→ {} joined", nick);
                if !account.is_empty() && account != "*" { join_text.push_str(&format!(" ({})", account)); }
                if !realname.is_empty()                  { join_text.push_str(&format!(" — {}", realname)); }
                let _ = log_line(state, &username, &conn_id, &channel, ts, &nick, &join_text, "join").await;
            }
            // Enforcement: auto-op / auto-voice a matching joiner. Live joins only
            // (not replay), never ourselves. Fires-and-forgets a MODE + audit entry.
            if accepted && !replayed && !is_self {
                let mask = format!("{}!{}", nick, userhost_from_prefix(&p.prefix));
                crate::bots::maybe_automode(state, username, conn_id, conn, &channel, &nick, &mask);
                // IP/host logging, seen-tracking, pending-tell delivery on join.
                crate::bots::maybe_join_bots(state, username, conn_id, conn, &channel, &nick, &mask);
                // Remote avatars: a bounded, delayed, invisible welcome to the joiner.
                crate::avatar::remote::on_other_join(state, username, conn, conn_id, &channel, &nick).await;
            }
            // Remote avatars: our own live JOIN announces us to the channel (invisibly).
            if accepted && !replayed && is_self {
                crate::avatar::remote::on_self_join(state, username, conn, conn_id, &channel).await;
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
            // r5 (codex P2 irc.rs:865): only for a channel we track (an untracked one is
            // neither logged — a new log target each — nor shown; our own PART is still shown).
            let (tracked, is_self) = { let mut c = conn.lock().await; let k = cm.fold(&channel); if same_nick(&nick, &c.echo_nick(replayed)) { (c.channels.remove(&k).is_some(), true) } else if let Some(ch) = c.channels.get_mut(&k) { ch.names.retain(|n| !same_nick(strip_pfx(n), &nick)); (true, false) } else { (false, false) } };
            prune_remote_avatars(&send, conn, conn_id, (!is_self).then_some(nick.as_str())).await;
            if is_self && !replayed { state.avatar_remote.forget_target(conn_id, &channel); }
            if !is_self && !replayed { state.avatar_remote.forget_welcome(conn_id, &nick); }
            if !is_self { state.avatar_remote.forget_query(conn_id, &nick); }
            crate::bots::member_changed(conn_id, cm, Some(&channel), &nick);   // r9: queued auto op/voice
            let part_text = if reason.is_empty() { format!("← {} left", nick) } else { format!("← {} left ({})", nick, reason) };
            if first_seen && tracked { let _ = log_line(state, &username, &conn_id, &channel, ts, &nick, &part_text, "part").await; }
            if tracked || is_self { send(ServerEvent::IrcPart { conn_id: conn_id.to_string(), nick, channel, reason, ts }); }
        }
        "QUIT" => {
            let nick   = nick_from_prefix(&p.prefix);
            let reason = p.params.get(0).cloned().unwrap_or_default();
            let affected: Vec<String> = {
                let mut c = conn.lock().await;
                // IRC nicks are case-insensitive — match members case-insensitively so a
                // QUIT is logged to the shared channel(s), not misfiled to the status buffer.
                let chans: Vec<String> = c.channels.iter().filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n).eq_ignore_ascii_case(&nick))).map(|(_, ch)| ch.name.clone()).collect();
                for ch in c.channels.values_mut() { ch.names.retain(|n| !strip_pfx(n).eq_ignore_ascii_case(&nick)); }
                // Remote avatars: whatever this nick announced is gone with it (and it may be
                // welcomed again when it comes back).
                if c.avx.forget(&nick) { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![nick.clone()] }); }
                if !replayed { state.avatar_remote.forget_welcome(conn_id, &nick); }
                state.avatar_remote.forget_query(conn_id, &nick);
                chans
            };
            crate::bots::member_changed(conn_id, cm, None, &nick);   // r9: queued auto op/voice
            let quit_text = if reason.is_empty() { format!("⊗ {} quit", nick) } else { format!("⊗ {} quit ({})", nick, reason) };
            if affected.is_empty() {
                if first_seen { let _ = log_line(state, &username, &conn_id, "status", ts, &nick, &quit_text, "quit").await; }
            } else {
                for ch in &affected {
                    if first_seen { let _ = log_line(state, &username, &conn_id, ch, ts, &nick, &quit_text, "quit").await; }
                }
            }
            send(ServerEvent::IrcQuit { conn_id: conn_id.to_string(), nick, reason, ts });
        }
        "NICK" => {
            let old = nick_from_prefix(&p.prefix);
            let new = p.params.get(0).cloned().unwrap_or_default();
            crate::bots::member_changed(conn_id, cm, None, &old); crate::bots::member_changed(conn_id, cm, None, &new);   // r9: no grant follows or lands on a nick
            // #30: source user@host, used to verify a self-NICK really identifies us.
            let src_userhost = userhost_from_prefix(&p.prefix);
            let ours;
            let affected: Vec<String> = {
                let mut c = conn.lock().await;
                let chans: Vec<String> = c.channels.iter().filter(|(_, ch)| ch.names.iter().any(|n| strip_pfx(n).eq_ignore_ascii_case(&old))).map(|(_, ch)| ch.name.clone()).collect();
                // #30: only adopt a self-NICK into our authoritative nick when the
                // source identifies us — it carries the ident of the user@host we recorded
                // (from self-JOIN/CHGHOST). Before we have learned our own user@host
                // (pre-JOIN) fall back to the legacy accept so a genuine early self-NICK
                // still lands. This blocks a forged `:<ournick> NICK <x>` (bare or another
                // user's prefix) from corrupting self-echo suppression and the nick-retry
                // base. The host is not compared (same rule as irc-core): a vhost/cloak can
                // change it without a CHGHOST, and since a snapshot no longer pre-applies
                // the nick (agy P2 #30 bypass), rejecting our own NICK would desync us.
                // Live lines only: a replayed NICK never rewrites our identity
                // (IrcConnection::adopt_self_nick).
                ours = !replayed && c.adopt_self_nick(&old, &new, &src_userhost, replayed);
                if replayed { c.replay_follow_nick(&old, &new, &src_userhost); }
                // Remote avatars: the old nick's announce goes (a metadata value follows the
                // user); after our own nick change other servers forget ours — announce anew.
                if c.avx.renamed(&old, &new) { send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![old.clone(), new.clone()] }); }
                state.avatar_remote.forget_query(conn_id, &old);
                state.avatar_remote.forget_query(conn_id, &new);
                if ours { state.avatar_remote.forget_conn(conn_id); }
                // An implausibly long new nick (NAMES_ENTRY_MAX_BYTES) is dropped from the
                // member lists rather than stored — renames can't inflate them either.
                let new_ok = new.len() <= NAMES_ENTRY_MAX_BYTES;
                for ch in c.channels.values_mut() {
                    if !new_ok {
                        ch.names.retain(|n| !strip_pfx(n).eq_ignore_ascii_case(&old));
                        continue;
                    }
                    for n in ch.names.iter_mut() {
                        if strip_pfx(n).eq_ignore_ascii_case(&old) {
                            let pfx: String = n.chars().take_while(|c| "@+~&%".contains(*c)).collect();
                            *n = format!("{}{}", pfx, new);
                        }
                    }
                }
                chans
            };
            let nick_text = format!("• {} is now known as {}", old, new);
            if affected.is_empty() {
                if first_seen { let _ = log_line(state, &username, &conn_id, "status", ts, &new, &nick_text, "nick").await; }
            } else {
                for ch in &affected {
                    if first_seen { let _ = log_line(state, &username, &conn_id, ch, ts, &new, &nick_text, "nick").await; }
                }
            }
            send(ServerEvent::IrcNick { conn_id: conn_id.to_string(), old, new, ts });
            if ours { crate::avatar::remote::reannounce(state, username, conn, conn_id).await; }
        }
        "CHGHOST" => {
            let nick = nick_from_prefix(&p.prefix);
            let new_host = p.params.get(1).cloned().unwrap_or_else(|| p.params.get(0).cloned().unwrap_or_default());
            let src_userhost = userhost_from_prefix(&p.prefix);
            let mut c = conn.lock().await;
            // #30: keep our recorded identity current across host cloaks so a later
            // genuine self-NICK (which carries the NEW user@host) still matches. agy P2:
            // guarded like NICK — only a CHGHOST whose source is us as we know us (or
            // before our user@host is known) may rewrite it; a forged `:<ournick> CHGHOST`
            // could otherwise re-arm the NICK guard with an attacker-chosen user@host.
            let nu = p.params.first().map(String::as_str).unwrap_or_default();
            let nh = p.params.get(1).map(String::as_str).unwrap_or_default();
            let own_host_changed = c.adopt_self_chghost(&nick, &src_userhost, nu, nh, replayed);
            if replayed && !nu.is_empty() && !nh.is_empty() {
                c.replay_follow_userhost(&nick, &src_userhost, &format!("{}@{}", nu, nh), true);
            }
            // Drop the previous remote binding and refresh local lookups for
            // nicks this connection can currently see.
            let forgot_remote = c.avx.forget(&nick);
            let live_change = !replayed && !arrival.restricted && !src_userhost.is_empty()
                && !nu.is_empty() && !nh.is_empty() && src_userhost != format!("{}@{}", nu, nh)
                && crate::avatar::remote::sees(&c, &nick);
            if forgot_remote || (state.avatars.enabled() && live_change) {
                send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![nick.clone()] });
            }
            if !replayed && same_nick(&nick, &c.nick) {
                let refresh = own_host_changed && !arrival.restricted
                    && state.avatars.meta(username).is_some_and(|meta| meta.visible)
                    && c.connected && c.registered && c.synced_link == crate::ipc_client::attached_link();
                let identity = refresh.then(|| (crate::avatar::conn_host(&c), c.self_userhost.clone()));
                state.avatar_remote.forget_conn(conn_id);
                drop(c);
                if let Some((host, userhost)) = identity {
                    crate::avatar::hint_local_host_change(state, conn_id, &host, &nick, &userhost).await;
                }
                crate::avatar::remote::reannounce(state, username, conn, conn_id).await;
                return Ok(());   // our own host change is never shown (see below)
            }
            // Our own host change (our nick) is never announced: services re-apply a vhost on
            // every (re)connect, so it was shown again in every channel each time. Someone
            // else's is, unless the host did not actually change.
            if same_nick(&nick, &c.nick) || !chghost_host_changed(&src_userhost, &new_host) {
                return Ok(());
            }
            let chans: Vec<String> = c.channels.iter()
                .filter(|(_, ch)| ch.names.iter().any(|n| same_nick(strip_pfx(n), &nick)))
                .map(|(_, ch)| ch.name.clone())
                .collect();
            drop(c);
            for ch in &chans {
                send(ServerEvent::IrcMessage { replayed: false,
                    conn_id: conn_id.to_string(), from: "*".into(), target: ch.clone(),
                    text: format!("*** {} has changed hostname to {}", nick, new_host),
                    ts, kind: MessageKind::Notice, msg_id: 0,
                    prefix: None,
                });
            }
            if chans.is_empty() {
                send(ServerEvent::IrcMessage { replayed: false,
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
            if first_seen { let _ = log_line(state, &username, &conn_id, "status", ts, &nick, &log_text, kind_str).await; }
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
            if p.tags.contains_key(crate::e2e_bridge::TAG) {
                if !replayed && ts >= received - 60 { crate::e2e_bridge::receive(state, username, conn, &p).await; }
            }
            let from = nick_from_prefix(&p.prefix);
            let target = p.params.get(0).cloned().unwrap_or_default();
            if let Some(event) = crate::reactions::receive(&*conn.lock().await, &p, &from, replayed || p.tags.contains_key("batch")) {
                send(event);
            }
            // Remote avatars: an invisible announce (a join announce to a channel, or a
            // welcome to us) — learned like the tag on PRIVMSG.
            if let Some(v) = p.tags.get(crate::avatar::remote::TAG_KEY).filter(|_| announce_fresh) {
                let (learned, to_channel) = {
                    let mut c = conn.lock().await;
                    let own = c.echo_nick(replayed);
                    let to_channel = incoming_channel_target(&c, &target).is_some();
                    (crate::avatar::remote::learn_from_prefix(&mut c, &state.avatar_remote, p.prefix.as_deref(), v, crate::avatar::remote::Source::Tag, &own), to_channel)
                };
                tracing::debug!("avatars: TAGMSG announce from {} on {} (to channel: {}, new: {})", from, conn_id, to_channel, learned.is_some());
                if let Some(n) = learned {
                    send(ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks: vec![n.clone()] });
                    // A peer's new channel announce: it may not know us — answer privately.
                    if to_channel && !replayed { crate::avatar::remote::on_peer_announce(state, username, conn, conn_id, &n).await; }
                }
            }
            // Check for typing indicator (+typing or +draft/typing tag)
            if let Some(typing_state) = p.tags.get("+typing").or_else(|| p.tags.get("+draft/typing")) {
                let (our_nick, chan_target) = { let c = conn.lock().await; (c.echo_nick(replayed), incoming_channel_target(&c, &target)) };
                if !same_nick(&from, &our_nick) {
                    let display_target = chan_target.map_or_else(|| from.clone(), |(ch, _)| ch);
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
            // Remote avatars: which open batches are metadata ones (avatar::remote::metadata_line).
            {
                let mut c = conn.lock().await;
                if let Some(r) = ref_tag.strip_prefix('+') { c.avx.batch_open(r, &batch_type, p.tags.get("batch").map(String::as_str)); }
                else if let Some(r) = ref_tag.strip_prefix('-') { c.avx.batch_close(r); }
            }
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
            send(ServerEvent::IrcMessage { replayed: false,
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
            send(ServerEvent::IrcMessage { replayed: false,
                conn_id: conn_id.to_string(), from: "*".into(),
                target: "status".into(), text, ts,
                kind: MessageKind::Notice, msg_id: 0,
                prefix: None,
            });
        }
        // 734 ERR_MONLISTFULL
        "734" => {
            let text = p.params.last().cloned().unwrap_or("Monitor list full".into());
            send(ServerEvent::IrcMessage { replayed: false,
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
            // r5 (codex P2 irc.rs:865): only for a channel we track (see PART).
            let (tracked, is_self) = { let mut c = conn.lock().await; let k = cm.fold(&channel); if same_nick(&kicked, &c.echo_nick(replayed)) { (c.channels.remove(&k).is_some(), true) } else if let Some(ch) = c.channels.get_mut(&k) { ch.names.retain(|n| !same_nick(strip_pfx(n), &kicked)); (true, false) } else { (false, false) } };
            prune_remote_avatars(&send, conn, conn_id, (!is_self).then_some(kicked.as_str())).await;
            if is_self && !replayed { state.avatar_remote.forget_target(conn_id, &channel); }
            if !is_self && !replayed { state.avatar_remote.forget_welcome(conn_id, &kicked); }
            if !is_self { state.avatar_remote.forget_query(conn_id, &kicked); }
            crate::bots::member_changed(conn_id, cm, Some(&channel), &kicked);   // r9: queued auto op/voice
            let kick_text = if reason.is_empty() { format!("✗ {} kicked by {}", kicked, by) } else { format!("✗ {} kicked by {} ({})", kicked, by, reason) };
            if first_seen && tracked { let _ = log_line(state, &username, &conn_id, &channel, ts, &kicked, &kick_text, "kick").await; }
            if tracked || is_self { send(ServerEvent::IrcKick { conn_id: conn_id.to_string(), channel, kicked, by, reason, ts }); }
        }
        "TOPIC" => {
            let set_by  = nick_from_prefix(&p.prefix);
            let channel = p.params.get(0).cloned().unwrap_or_default();
            let topic   = p.params.get(1).cloned().unwrap_or_default();
            // #28: only surface a topic for a channel we actually track. A malicious
            // server can forge TOPIC for unlimited untracked channels to grow client
            // state unbounded, bypassing the #43 256-channel JOIN cap.
            let tracked = { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&cm.fold(&channel)) { ch.topic = topic.clone(); true } else { false } };
            if tracked {
                send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by, ts });
            }
        }
        "332" => {
            let channel = p.params.get(1).cloned().unwrap_or_default();
            let topic   = p.params.get(2).cloned().unwrap_or_default();
            // #28: gate forged 332 for untracked channels (see TOPIC arm).
            let tracked = { let mut c = conn.lock().await; if let Some(ch) = c.channels.get_mut(&cm.fold(&channel)) { ch.topic = topic.clone(); true } else { false } };
            if tracked {
                send(ServerEvent::IrcTopic { conn_id: conn_id.to_string(), channel, topic, set_by: String::new(), ts });
            }
        }

        // S3: bounded names accumulation
        "353" => {
            let channel = p.params.get(2).cloned().unwrap_or_default();
            let mut c = conn.lock().await;
            let chan_key = cm.fold(&channel);
            // codex P2 irc.rs:824: only buffer NAMES for a channel we track. The 366 arm
            // already discards the buffer of an untracked channel (#28), so buffering it
            // was pure memory for a forged/unsolicited 353 stream that never sends 366.
            let tracked = c.channels.contains_key(&chan_key);
            let buffered: usize = c.names_buf.values().map(|v| v.len()).sum();
            if tracked && (c.names_buf.len() < NAMES_BUF_MAX_CHANNELS || c.names_buf.contains_key(&chan_key)) {
                let mut room = NAMES_BUF_MAX_TOTAL.saturating_sub(buffered);
                let names: Vec<String> = p.params.get(3).cloned().unwrap_or_default()
                    .split_whitespace()
                    // userhost-in-names: strip !user@host from entries like @nick!user@host
                    .map(|s| {
                        if let Some(bang) = s.find('!') { s[..bang].to_string() }
                        else { s.to_string() }
                    })
                    .filter(|n| n.len() <= NAMES_ENTRY_MAX_BYTES)
                    .collect();
                // Key the buffer by the case-folded channel name. IRC channels are
                // case-insensitive, and a server can echo a DIFFERENT case in the 353
                // (canonical, e.g. #Channel) than in the terminating 366 (whatever case
                // the NAMES query used, e.g. #channel from a case-folded resync request).
                // Keying by raw case meant the 366 remove missed the buffered names and
                // clobbered the real member list to empty — see the matching 366 arm.
                let entry = c.names_buf.entry(chan_key).or_default();
                for n in names {
                    if room == 0 { break; }
                    if entry.len() < NAMES_BUF_MAX_PER_CHAN { entry.push(n); room -= 1; }
                }
            }
        }
        "366" => {
            let channel = p.params.get(1).cloned().unwrap_or_default();
            // Case-folded lookup so a 366 whose channel case differs from the 353's
            // (see the 353 arm) still finds the buffered names.
            let names   = { conn.lock().await.names_buf.remove(&cm.fold(&channel)).unwrap_or_default() };
            // An EMPTY NAMES reply for a channel we're in is spurious — you're always a
            // member of your own channels, so a real reply has >=1 entry. An empty 366
            // comes from a duplicate/overlapping NAMES request whose buffer was already
            // flushed (or an odd server). Never let it clobber the populated member list
            // (web-side ch.names OR the client, via an emitted empty IrcNames). Skip it.
            if !names.is_empty() {
                // #28: gate forged 366 for untracked channels (see TOPIC arm).
                // Also adopt the server's spelling of the name. A channel we learned from
                // a SessionSync placeholder (web restart / re-Attach) carries the daemon's
                // case-FOLDED name, because that set is keyed by irc_lower — and `ch.name`
                // is what the QUIT arm and the 315 away snapshot use as the display/log
                // target, so a mixed-case channel's quits were being logged to a second,
                // all-lowercase buffer of their own.
                // This lookup is already case-insensitive, so the only thing that can
                // change here is the case, and the server's is the canonical one.
                let tracked = {
                    let mut c = conn.lock().await;
                    let key = cm.fold(&channel);
                    // Bounded across channels too (MEMBERS_MAX_TOTAL), not just per channel.
                    let others = members_total(&c.channels)
                        - c.channels.get(&key).map_or(0, |ch| ch.names.len());
                    if let Some(ch) = c.channels.get_mut(&key) {
                        let mut names = names.clone();
                        names.truncate(MEMBERS_MAX_TOTAL.saturating_sub(others));
                        ch.names = names;
                        // r8 (codex P2 irc.rs:413): only a case-FOLDED placeholder name adopts
                        // the server's spelling — once. ch.name is the log directory of a chosen
                        // channel (existing_log_target), so a hostile server alternating 353/366
                        // case variants must not keep changing it (one directory each).
                        if ch.name != channel && ch.name == cm.fold(&ch.name) { ch.name = channel.clone(); }
                        true
                    } else { false }
                };
                if tracked {
                    send(ServerEvent::IrcNames { conn_id: conn_id.to_string(), channel, names });
                }
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
            // r5 (codex P2 irc.rs:865): a channel MODE only for a channel we track — one for
            // any other channel (never sent by a real server) is neither logged (a new log
            // target each) nor shown.
            if target.starts_with(['#','&','+','!']) && !conn.lock().await.channels.contains_key(&cm.fold(&target)) {
                return Ok(());
            }
            // Update nick prefixes in server-side names list so reconnecting
            // clients get accurate op/voice/etc. status from the State event.
            if target.starts_with(['#','&','+','!']) {
                let mode_map: &[(char,char)] = &[('o','@'),('v','+'),('h','%'),('a','&'),('q','~')];
                let parts: Vec<&str> = modes.split_whitespace().collect();
                let mode_str = parts.first().copied().unwrap_or("");
                let mut arg_idx = 1usize;
                let mut adding = true;
                let mut c = conn.lock().await;
                let chm = c.chanmodes.clone();
                if let Some(ch) = c.channels.get_mut(&cm.fold(&target)) {
                    for mc in mode_str.chars() {
                        if mc == '+' { adding = true; continue; }
                        if mc == '-' { adding = false; continue; }
                        // r8 (codex P1 irc.rs:1845): a letter is a prefix (status) mode only if the
                        // server's PREFIX says so — `a` in CHANMODES group D takes no nick.
                        if let Some(&(_, pfx)) = mode_map.iter().find(|(m,_)| *m == mc).filter(|_| chm.is_prefix_mode(mc)) {
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
                            // r8 (agy P1 irc.rs:1883): `-k` takes a parameter only when the
                            // server lists k in a group that has one when unset (B, the default).
                            if chm.takes_param('k', adding) != Some(false) { arg_idx += 1; }
                        } else {
                            // r7 (codex P2 ircproto.rs:490): the server's CHANMODES decide which
                            // letters carry a parameter; at an unknown one, stop — every
                            // parameter after it might be its own (a wrong key or a wrong nick
                            // would follow).
                            match chm.takes_param(mc, adding) {
                                Some(true) => arg_idx += 1,
                                Some(false) => {}
                                None => break,
                            }
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
                let scm = conn.lock().await.server_casemapping;
                persist_channel_key(&state, &username, &conn_id, &target, kc.as_deref(), scm).await;
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
            if first_seen { let _ = log_line(state, &username, &conn_id, &display_target, ts, &log_from, &log_text, "mode").await; }
            send(ServerEvent::IrcMode { conn_id: conn_id.to_string(), target: display_target, modes: display, ts });
        }
        // 311-318 = WHOIS replies — route to nick's query buffer
        "311" => { // RPL_WHOISUSER: nick user host * :realname
            let nick = p.params.get(1).cloned().unwrap_or_default();
            // Avatars: the viewer's server just showed this nick (a live reply, not ring
            // replay), so avatar discovery may answer for it for a while.
            if !replayed { conn.lock().await.whois_seen.note(&nick); }
            let user = p.params.get(2).cloned().unwrap_or_default();
            let host = p.params.get(3).cloned().unwrap_or_default();
            let real = p.params.get(5).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("{}!{}@{} ({})", p.params.get(1).cloned().unwrap_or_default(), user, host, real), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "312" => { // RPL_WHOISSERVER
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = params_from(&p.params, 2); // #19: guard against <2 params
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Server: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "313" => { // RPL_WHOISOPERATOR
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "317" => { // RPL_WHOISIDLE
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let idle: u64 = p.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let signon: i64 = p.params.get(3).and_then(|s| s.parse().ok()).unwrap_or(0);
            let idle_str = if idle >= 3600 { format!("{}h {}m {}s", idle/3600, (idle%3600)/60, idle%60) } else if idle >= 60 { format!("{}m {}s", idle/60, idle%60) } else { format!("{}s", idle) };
            let signon_str = chrono::DateTime::from_timestamp(signon, 0).map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string()).unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Idle: {} | Signon: {}", idle_str, signon_str), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "318" => { // RPL_ENDOFWHOIS
            let nick = p.params.get(1).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "End of WHOIS".into(), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "319" => { // RPL_WHOISCHANNELS
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let chans = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Channels: {}", chans), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "330" => { // RPL_WHOISACCOUNT (logged in as)
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let account = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Logged in as: {}", account), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "338" => { // RPL_WHOISACTUALLY (actual host/IP)
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = params_from(&p.params, 2); // #19: guard against <2 params
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Actually: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "671" => { // RPL_WHOISSECURE
            let nick = p.params.get(1).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: "Using secure connection (TLS)".into(), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        // Additional WHOIS numerics — route to nick's query buffer
        "301" => { // RPL_AWAY
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let msg = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Away: {}", msg), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "307" => { // RPL_WHOISREGNICK
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or("is a registered nick".into());
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "378" => { // RPL_WHOISHOST (connecting from)
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "379" => { // RPL_WHOISMODES
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "320" => { // RPL_WHOISSPECIAL (identified, bot, etc)
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text, ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "275" | "276" => { // RPL_WHOISCERTFP — TLS certificate fingerprint
            let nick = p.params.get(1).cloned().unwrap_or_default();
            let text = p.params.get(2).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "*".into(), target: nick, text: format!("Certificate: {}", text), ts, kind: MessageKind::Notice, msg_id: 0, prefix: None });
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
        "321" if !ui_replayed => { conn.lock().await.note_list_reply(); }
        // 322 = RPL_LIST — channel list entry
        "322" if !ui_replayed => {
            let channel = p.params.get(1).cloned().unwrap_or_default();
            if channel.is_empty() { return Ok(()); }
            let users: u32 = p.params.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
            let topic = p.params.get(3).cloned().unwrap_or_default();
            let mut connection = conn.lock().await;
            let list = connection.note_list_reply();
            if let Some(request_id) = &list.request_id {
                list.total += 1;
                list.entries.push(ChannelListEntry { channel, users, topic });
                if list.entries.len() == LIST_BATCH_ROWS {
                    send(ServerEvent::IrcListBatch { conn_id: conn_id.to_string(), request_id: request_id.clone(),
                        entries: std::mem::take(&mut list.entries) });
                }
            } else {
                send(ServerEvent::IrcListEntry { conn_id: conn_id.to_string(), channel, users, topic });
            }
        }
        // 323 = RPL_LISTEND
        "323" if !ui_replayed => {
            let list = conn.lock().await.list_request.take();
            let (request_id, total, message) = match list {
                Some(ChannelListRequest { request_id: Some(request_id), entries, total, incomplete, .. }) => {
                    if !entries.is_empty() {
                        send(ServerEvent::IrcListBatch { conn_id: conn_id.to_string(), request_id: request_id.clone(), entries });
                    }
                    (Some(request_id), Some(total), incomplete.map(str::to_owned))
                }
                _ => (None, None, None),
            };
            send(ServerEvent::IrcListEnd { conn_id: conn_id.to_string(), request_id, total, message });
        }
        "416" if !ui_replayed && p.params.get(1).is_some_and(|verb| verb.eq_ignore_ascii_case("LIST")) => {
            if let Some(list) = conn.lock().await.list_request.as_mut() {
                list.incomplete = Some("The IRC server stopped the channel list early. Try a narrower /list pattern.");
            }
            send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "server".into(),
                target: "status".into(), text: p.params.last().cloned().unwrap_or_default(), ts,
                kind: MessageKind::Notice, msg_id: 0, prefix: None });
        }
        "263" | "421" if !ui_replayed && p.params.get(1).is_some_and(|verb| verb.eq_ignore_ascii_case("LIST")) => {
            if let Some(request_id) = conn.lock().await.list_request.take().and_then(|list| list.request_id) {
                send(ServerEvent::IrcListError { conn_id: conn_id.to_string(), request_id,
                    message: "The IRC server did not accept the channel list request.".into() });
            } else {
                send(ServerEvent::IrcMessage { replayed: false, conn_id: conn_id.to_string(), from: "server".into(),
                    target: "status".into(), text: p.params.last().cloned().unwrap_or_default(), ts,
                    kind: MessageKind::Notice, msg_id: 0, prefix: None });
            }
        }
        "321" | "322" | "323" => {}
        // 364 = RPL_LINKS
        "364" => {
            let server = p.params.get(1).cloned().unwrap_or_default();
            let hub = p.params.get(2).cloned().unwrap_or_default();
            let info = p.params.get(3).cloned().unwrap_or_default();
            send(ServerEvent::IrcMessage { replayed: false,
                conn_id: conn_id.to_string(), from: "links".into(),
                target: "status".into(),
                text: format!("\x02{}\x02 → {} ({})", server, hub, info),
                ts, kind: MessageKind::Notice, msg_id: 0,
                prefix: None,
            });
        }
        // 365 = RPL_ENDOFLINKS
        "365" => {
            send(ServerEvent::IrcMessage { replayed: false,
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
                let chm = conn.lock().await.chanmodes.clone();
                if let Some(key) = channel_key_from_modes(&modes, &chm) {
                    // F5: only persist for a channel we're actually tracking (gate
                    // like TOPIC/332/366) and only when the key changed in memory —
                    // this short-circuits BEFORE the expensive get/save so a server
                    // streaming distinct/repeated 324s can't force unbounded growth
                    // or O(n) disk I/O on the read loop's critical path.
                    let (need_persist, scm) = {
                        let mut c = conn.lock().await;
                        let scm = c.server_casemapping;
                        match c.channels.get_mut(&cm.fold(&chan)) {
                            Some(ch) if ch.key.as_deref() != Some(key.as_str()) => {
                                ch.key = Some(key.clone());
                                (true, scm)
                            }
                            _ => (false, scm),
                        }
                    };
                    if need_persist {
                        persist_channel_key(&state, &username, &conn_id, &chan, Some(key.as_str()), scm).await;
                    }
                }
            }
            // Structured event so the Channel Modes GUI can parse current
            // modes; the frontend also shows a sysMsg for manual /mode users.
            send(ServerEvent::IrcChannelModes {
                conn_id: conn_id.to_string(), channel: chan, modes,
            });
        }
        // 329 RPL_CREATIONTIME — structured, not a notice.
        // This used to be an ordinary Notice, which meant it was neither condensed
        // (`notice` is not a _STATUS_KINDS kind) nor de-duplicated (`msg_id: 0` skips the
        // id-dedup, and the content-dedup is status-kinds-only) — so every bare `MODE
        // #chan` WE send on the user's behalf (reattach resync burst, Channel Modes
        // dialog refresh) stacked another permanent "Channel created" line in the
        // channel. Its 324 twin was invisible the whole time because `mode` IS a status
        // kind. Handing the client a typed event lets it apply the same policy to both
        // halves of the reply. Formatting moved to the client so it can render in the
        // user's own timestamp preference instead of a hardcoded UTC string.
        "329" => {
            let chan = p.params.get(1).cloned().unwrap_or_default();
            let created = p.params.get(2).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            if chan.starts_with(['#','&','+','!']) {
                send(ServerEvent::IrcChannelCreated {
                    conn_id: conn_id.to_string(), channel: chan, created,
                });
            } else {
                // A 329 whose param isn't a channel is malformed/forged. Keep the old
                // behaviour of surfacing it in status rather than swallowing it silently
                // — but only when there is actually something to show.
                let text = params_from(&p.params, 1);
                if !text.is_empty() {
                    send(ServerEvent::IrcMessage { replayed: false,
                        conn_id: conn_id.to_string(), from: "*".into(),
                        target: "status".into(), text, ts,
                        kind: MessageKind::Notice, msg_id: 0, prefix: None,
                    });
                }
            }
        }
        // 403 ERR_NOSUCHCHANNEL — route to channel if it looks like one
        "403" => {
            let chan = p.params.get(1).cloned().unwrap_or_default();
            let reason = p.params.get(2).cloned().unwrap_or("No such channel".into());
            let display_target = if chan.starts_with(['#','&','+','!']) { chan } else { "status".to_string() };
            send(ServerEvent::IrcMessage { replayed: false,
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
            let chan_key = cm.fold(&channel);
            // 'G' = gone/away, 'H' = here. Accumulate away nicks for the snapshot;
            // here-nicks are implied by absence (the frontend has the member list).
            let is_pending = {
                let mut c = conn.lock().await;
                // Same byte/aggregate bounds as the NAMES buffers (a server that never
                // sends 315 can't pin unbounded memory here either).
                let away_total: usize = c.who_away.values().map(|v| v.len()).sum();
                if status.starts_with('G') && !who_nick.is_empty()
                    && who_nick.len() <= NAMES_ENTRY_MAX_BYTES && away_total < NAMES_BUF_MAX_TOTAL
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
                    let msg_id = if first_seen { log_line(state, username, conn_id, "status", ts, "*", &text, "notice").await } else { 0 };
                    send(ServerEvent::IrcMessage { replayed: false,
                        conn_id: conn_id.to_string(), from: "*".into(),
                        target: "status".into(), text, ts,
                        kind: MessageKind::Notice, msg_id, prefix: None,
                    });
                }
            }
        }
        "315" => { // RPL_ENDOFWHO: <me> <chan/mask> :End of /WHO list.
            let channel  = p.params.get(1).cloned().unwrap_or_default();
            let chan_key = cm.fold(&channel);
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
                    let msg_id = if first_seen { log_line(state, username, conn_id, "status", ts, "*", &text, "notice").await } else { 0 };
                    send(ServerEvent::IrcMessage { replayed: false,
                        conn_id: conn_id.to_string(), from: "*".into(),
                        target: "status".into(), text, ts,
                        kind: MessageKind::Notice, msg_id, prefix: None,
                    });
                }
            }
        }
        // codex P2 ipc_client.rs:302: a JOIN the server REFUSED (full / invite-only /
        // banned / bad key) for a channel we still track — typically the daemon's rejoin
        // after a reconnect — means we are not in it any more. Drop it (and tell the
        // sessions) instead of showing it joined, with stale members, forever. The line is
        // still shown in status below. Not for already-handled ring replay (an old refusal
        // followed by a later successful join).
        // r4 V3I-N5 (w3-irc LOW): more "you did not get in" replies than 471/473/474/475 —
        // 477 (registered nick needed), 470 (forwarded elsewhere), 405 (too many channels),
        // 480/489 (TLS only), 520 (opers only), 437 (channel temporarily unavailable).
        // (403 keeps its own arm above: it answers PART/MODE/TOPIC/… as well.)
        "471" | "473" | "474" | "475" | "405" | "437" | "470" | "477" | "480" | "489" | "520" => {
            let chan = p.params.get(1).cloned().unwrap_or_default();
            if first_seen && chan.starts_with(['#','&','+','!']) {
                let mut c = conn.lock().await;
                let key = cm.fold(&chan);
                // 471/473/474/475 only ever answer a JOIN. The others also answer other
                // commands on some ircds (477 a message to a +M/+R channel on InspIRCd or a
                // MODE on a modeless one, 480 a KNOCK on Unreal, 489 ircu's "voice needed",
                // 437 a nick), so they count only for a channel that the daemon's latest
                // snapshot does not list as joined — never for one we are really in.
                let join_only = matches!(p.command.as_str(), "471" | "473" | "474" | "475");
                let daemon_has = c.daemon_channels.iter().any(|n| cm.fold(n) == key);
                let reason = match (p.command.as_str(), p.params.get(2)) {
                    ("470", Some(to)) if to.starts_with(['#','&','+','!']) => format!("Not joined (the server forwarded it to {})", to),
                    _ => "Cannot rejoin (refused by the server)".to_string(),
                };
                if (join_only || !daemon_has) && forget_channel_membership(state, username, conn_id, &mut c, &key, &reason) {
                    info!("[{}] rejoin of a tracked channel refused ({}) — no longer joined", conn_id, p.command);
                }
            }
            let text = params_from(&p.params, 1);
            if !text.is_empty() {
                let msg_id = if first_seen { log_line(state, username, conn_id, "status", ts, "*", &text, "notice").await } else { 0 };
                send(ServerEvent::IrcMessage { replayed: false,
                    conn_id: conn_id.to_string(), from: "*".to_string(), target: "status".to_string(),
                    text, ts, kind: MessageKind::Notice, msg_id, prefix: None,
                });
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
                let msg_id = if first_seen { log_line(state, username, conn_id, "status", ts, "*", &text, "notice").await } else { 0 };
                send(ServerEvent::IrcMessage { replayed: false,
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
                send(ServerEvent::IrcMessage { replayed: false,
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

/// agy P2 irc.rs:445: IRC nicks are case-insensitive, so every "is this us / this
/// member" test compares case-insensitively (a server, bouncer or op can spell our nick
/// in another case than the 001 one: KICK by a typed `ghost`, `/nick GHOST`, a ZNC echo).
/// ASCII folding only: it never equates two nicks that are distinct under ANY server
/// casemapping (ascii, rfc1459, strict-rfc1459), unlike an rfc1459 fold on an ascii
/// server (`a[b` vs `a{b`), which could suppress another user's line as our echo.
pub(crate) fn same_nick(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn kind_str(k: &MessageKind) -> &'static str {
    match k { MessageKind::Privmsg => "privmsg", MessageKind::Notice => "notice", MessageKind::Action => "action" }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// codex P2 irc.rs:206 / w-srv #14: which saved key is "this channel" follows the
    /// server's CASEMAPPING; unknown = exact spelling only.
    #[test]
    fn key_slot_follows_server_casemapping() {
        let mut keys = HashMap::new();
        keys.insert("#x[y]".to_string(), "k1".to_string());
        // ascii (ergo, UnrealIRCd 6, InspIRCd 4): #x{y} is another channel — a new slot.
        assert_eq!(existing_key_slot(&keys, "#x{y}", Some(CaseMapping::Ascii)), "#x{y}");
        assert_eq!(existing_key_slot(&keys, "#X[Y]", Some(CaseMapping::Ascii)), "#x[y]");
        // rfc1459: the same channel, so the stored slot is reused.
        assert_eq!(existing_key_slot(&keys, "#X{Y}", Some(CaseMapping::Rfc1459)), "#x[y]");
        assert_eq!(existing_key_slot(&keys, "#X{Y}", Some(CaseMapping::StrictRfc1459)), "#x[y]");
        // unknown: exact (to_lowercase) only.
        assert_eq!(existing_key_slot(&keys, "#x{y}", None), "#x{y}");
        assert_eq!(existing_key_slot(&keys, "#X[Y]", None), "#x[y]");
        // strict-rfc1459 does not fold ~/^.
        let mut t = HashMap::new();
        t.insert("#a~".to_string(), "k".to_string());
        assert_eq!(existing_key_slot(&t, "#a^", Some(CaseMapping::StrictRfc1459)), "#a^");
        assert_eq!(existing_key_slot(&t, "#a^", Some(CaseMapping::Rfc1459)), "#a~");
    }

    /// codex P2 ipc_client.rs:857 / agy P2: a real key that merely starts with "enc:" is
    /// a key; only a genuine vault blob (still encrypted) is not.
    #[test]
    fn join_seed_uses_the_validated_blob_check() {
        let mut keys = HashMap::new();
        keys.insert("#a".to_string(), "enc:hunter2".to_string());
        keys.insert("#b".to_string(), format!("enc:{}", "QUFB".repeat(12))); // 36 decoded bytes
        keys.insert("#x[y]".to_string(), "k1".to_string());
        assert_eq!(seed_channel_key(&keys, "#A", None).as_deref(), Some("enc:hunter2"));
        assert_eq!(seed_channel_key(&keys, "#b", None), None);
        assert_eq!(seed_channel_key(&keys, "#x{y}", Some(CaseMapping::Ascii)), None);
        assert_eq!(seed_channel_key(&keys, "#x{y}", Some(CaseMapping::Rfc1459)).as_deref(), Some("k1"));
    }

    /// r5 (codex P2 irc.rs:865 + security hook): NEW targets are budgeted per connection and
    /// day, DM partners and channel names separately; a target already counted stays allowed;
    /// the first refusal is reported once.
    #[test]
    fn new_log_targets_are_budgeted_separately_per_connection() {
        let cid = "r5-cap-test-conn";
        for i in 0..NEW_DM_TARGETS_PER_CONN_DAY { assert_eq!(new_target_budget(cid, &format!("nick{i}")), Ok(())); }
        assert_eq!(new_target_budget(cid, "nick0"), Ok(()), "already counted today");
        assert_eq!(new_target_budget(cid, "NICK0"), Err(true), "a case variant is another directory → another slot; first refusal: notice");
        assert_eq!(new_target_budget(cid, "flood1"), Err(false), "notice only once");
        assert_eq!(new_target_budget(cid, "#somechan"), Ok(()), "channel names have their own budget");
        assert_eq!(new_target_budget("r5-cap-test-other", "flood1"), Ok(()), "per connection");
    }

    /// r6 (codex P2 irc.rs:366): only a channel the user chose is exempt from the log-target
    /// budget — one this web sent a JOIN for (any spelling, list form, tags) or on the saved
    /// auto-join list; a server-forced self-JOIN is not.
    #[test]
    fn user_joins_come_from_outgoing_joins_and_auto_join() {
        let mut c = test_conn();
        c.cfg.auto_join = vec!["#Saved".into()];
        c.note_user_join("JOIN #Mine,#two k1\r\n");
        c.note_user_join("@label=x JOIN :#tagged");
        c.note_user_join("PRIVMSG #notajoin :JOIN #x");
        c.note_user_join("PART #mine");
        assert!(c.user_chose_channel("#mine") && c.user_chose_channel("#TWO") && c.user_chose_channel("#tagged"));
        assert!(c.user_chose_channel("#saved"), "the saved auto-join list counts");
        assert!(!c.user_chose_channel("#notajoin") && !c.user_chose_channel("#x") && !c.user_chose_channel("#forced"));
        for k in 0..(USER_JOINS_MAX + 10) { c.note_user_join(&format!("JOIN #b{k}")); }
        assert!(c.user_joins.len() <= USER_JOINS_MAX, "bounded");
    }

    /// CHGHOST from someone else: announced only when the host really changed. (Our own —
    /// the line's nick is our current nick — is never announced; see the CHGHOST arm.)
    #[test]
    fn chghost_unchanged_host_is_not_announced() {
        assert!(chghost_host_changed("u@cloak.example", "vhost.example"));
        assert!(!chghost_host_changed("u@vhost.example", "vhost.example"), "identical host");
        assert!(!chghost_host_changed("u@VHost.Example", "vhost.example"), "case-insensitive");
        assert!(chghost_host_changed("", "vhost.example"), "unknown source host: shown as before");
    }

    /// While no web was attached we went Alice → Away, someone took Alice and spoke, then we
    /// took Alice back. The snapshot says we are Alice; on replay the other person's line is
    /// kept (as at 069f376), and the real identity never moves (codex final check).
    #[test]
    fn replay_view_tells_our_echoes_from_an_earlier_holder_of_our_nick() {
        let mut c = test_conn();
        c.nick = "Alice".into();
        c.self_userhost = "me@my.host".into();
        c.replay_view = Some((c.nick.clone(), c.self_userhost.clone()));
        c.replay_follow_nick("Alice", "Away", "me@my.host");
        assert!(!same_nick("Alice", &c.echo_nick(true)), "the other Alice's line is not our echo");
        c.replay_follow_nick("Bob", "Alice", "other@host");   // someone else taking Alice
        assert_eq!(c.echo_nick(true), "Away");
        c.replay_follow_nick("Away", "Alice", "me@my.host");
        assert!(same_nick("Alice", &c.echo_nick(true)), "our lines after we took Alice back are");
        assert_eq!((c.nick.as_str(), c.self_userhost.as_str()), ("Alice", "me@my.host"), "real identity untouched");
        assert_eq!(c.echo_nick(false), "Alice", "live lines use the real nick");
        c.replay_view = None;
        assert_eq!(c.echo_nick(true), "Alice", "no replay view outside an Attach replay");
    }

    /// Our vhost changed (reapplied on connect); a replayed echo of our own X3DH header from
    /// before it carries the OLD host — still our echo (codex final check).
    #[test]
    fn a_replayed_own_echo_from_before_a_host_change_is_still_suppressed() {
        let mut c = test_conn();
        c.nick = "Alice".into();
        c.self_userhost = "me@new.vhost".into();
        c.replay_view = Some((c.nick.clone(), c.self_userhost.clone()));
        // ":Alice!me@old.host PRIVMSG Bob :+E2E-HDR…" — echo-message suppression is by nick.
        assert!(same_nick("Alice", &c.echo_nick(true)));
        // A replayed CHGHOST to the new host and a replayed self-JOIN keep the view consistent.
        c.replay_follow_userhost("Alice", "me@old.host", "me@new.vhost", true);
        c.replay_follow_userhost("Alice", "me@new.vhost", "me@new.vhost", false);
        assert_eq!(c.replay_view.as_ref().map(|v| v.1.as_str()), Some("me@new.vhost"));
        c.replay_follow_userhost("Alice", "evil@x", "evil@x", true);
        assert_eq!(c.replay_view.as_ref().map(|v| v.1.as_str()), Some("me@new.vhost"), "a CHGHOST from another ident is ignored");
    }

    /// Replayed NOTICEs decide "ours" by the replay view, exactly like PRIVMSG (codex narrow
    /// check: NOTICE read the real nick — while we were Away, another Alice's channel notice
    /// was dropped as our echo and our own Away notices were routed as foreign).
    #[test]
    fn replayed_notices_use_the_replay_view_like_privmsg() {
        let mut c = test_conn();
        c.nick = "Alice".into();
        c.self_userhost = "me@my.host".into();
        c.echo_message_enabled = true;
        c.replay_view = Some((c.nick.clone(), c.self_userhost.clone()));
        let route = |c: &IrcConnection, from: &str, target: &str, replayed: bool| notice_display_target(c, from, target, true, replayed, false);
        // Ring: we go Alice → Away; another Alice speaks; we take Alice back.
        c.replay_follow_nick("Alice", "Away", "me@my.host");
        assert_eq!(route(&c, "Alice", "#chan", true).as_deref(), Some("#chan"), "the other Alice's channel notice is kept");
        assert_eq!(route(&c, "Alice", "Away", true).as_deref(), Some("Alice"), "her private notice goes to her window");
        assert_eq!(route(&c, "Away", "#chan", true), None, "our own notice as Away is our echo");
        c.echo_message_enabled = false;
        assert_eq!(route(&c, "Away", "Bob", true).as_deref(), Some("Bob"), "without echo-message, our own notice goes to its recipient");
        c.echo_message_enabled = true;
        c.replay_follow_nick("Away", "Alice", "me@my.host");
        assert_eq!(route(&c, "Alice", "#chan", true), None, "after we took Alice back, Alice's notices are ours");
        // Live lines are unchanged: the real nick decides.
        c.replay_follow_nick("Alice", "Away", "me@my.host");
        assert_eq!(route(&c, "Alice", "#chan", false), None, "live: Alice is us");
        assert_eq!(route(&c, "Away", "Alice", false).as_deref(), Some("Away"), "live: Away is someone else");
        // Batch (playback) notices and server notices are unaffected.
        assert_eq!(notice_display_target(&c, "Away", "#chan", true, true, true).as_deref(), Some("#chan"), "a batch notice is never an echo");
        assert_eq!(notice_display_target(&c, "irc.example.net", "Alice", true, true, false).as_deref(), Some("status"));
        assert_eq!(notice_display_target(&c, "Bob", "Alice", false, true, false).as_deref(), Some("status"), "no prefix → status");
        c.replay_view = None;
        assert_eq!(route(&c, "Alice", "#chan", true), None, "no replay view outside an Attach replay: the real nick");
    }

    fn test_conn() -> IrcConnection {
        IrcConnection {
            conn_id: "c0".into(), nick: "me".into(), connected: true, lag_ms: None,
            channels: HashMap::new(), ipc_out: Arc::new(Mutex::new(None)), message_tags: false, e2e_bridge: Default::default(), reactions: Default::default(), keepnick_retry: Default::default(),
            self_userhost: String::new(), registered: true, list_request: None, echo_message_enabled: false,
            names_buf: HashMap::new(), who_pending: HashSet::new(), who_away: HashMap::new(),
            resync_busy: false, resync_gen: 0, resync_recent: HashMap::new(),
            casemapping: CaseMapping::default(), server_casemapping: None, dial_endpoint: None,
            statusmsg: None, daemon_channels: Vec::new(), user_joins: HashSet::new(), chanmodes: ChanModes::default(),
            whois_seen: Default::default(), seen_userhosts: Default::default(), synced_link: 0, cap_ls_done: false, behind_bouncer: false, daemon_registration: false, registration_epoch: 0, live_registration_link: None, replay_view: None, avx: Default::default(), cfg: NetworkConfig::default(),
        }
    }

    #[tokio::test]
    async fn channel_lists_serialize_on_the_irc_connection() {
        let mut conn = test_conn();
        let (tx, mut rx) = mpsc::unbounded_channel();
        *conn.ipc_out.lock().await = Some(tx);
        conn.send_list("LIST #one\r\n", Some("first".into())).await.unwrap();
        assert!(conn.send_list("LIST #two\r\n", Some("second".into())).await.is_err());
        assert!(conn.send_raw("@label=other list #two\r\n").await.is_err());
        assert_eq!(conn.list_request.as_ref().unwrap().request_id.as_deref(), Some("first"));
        assert!(matches!(rx.try_recv(), Ok(IpcMessage::RawSend { line, .. }) if line == "LIST #one\r\n"));
        assert!(rx.try_recv().is_err());
        conn.list_request.as_mut().unwrap().last_activity -= LIST_REQUEST_IDLE;
        conn.send_raw("list\r\n").await.unwrap();
        assert!(conn.list_request.as_ref().unwrap().request_id.is_none());
        assert!(conn.list_request.as_ref().unwrap().incomplete.is_some());
        conn.reset_irc_session();
        assert!(conn.list_request.is_none());
    }

    /// r4 (codex P1 irc.rs:591 / P2 irc.rs:591): a STATUSMSG line (`@#staff`) belongs to
    /// the channel, not to a private conversation with its sender.
    #[test]
    fn statusmsg_lines_belong_to_the_channel() {
        let mut c = test_conn();
        assert_eq!(incoming_channel_target(&c, "@#staff"), Some(("#staff".to_string(), true)));
        assert_eq!(incoming_channel_target(&c, "%#staff"), Some(("#staff".to_string(), true)));
        assert_eq!(incoming_channel_target(&c, "+#staff"), Some(("#staff".to_string(), true)));
        assert_eq!(incoming_channel_target(&c, "#staff"), Some(("#staff".to_string(), false)));
        assert_eq!(incoming_channel_target(&c, "&local"), Some(("&local".to_string(), false)));
        assert_eq!(incoming_channel_target(&c, "me"), None);
        assert_eq!(incoming_channel_target(&c, "alice"), None);
        assert_eq!(incoming_channel_target(&c, ""), None);
        // Announced STATUSMSG=@+: '%' is no status prefix there (and `%#x` is no channel).
        c.statusmsg = Some("@+".into());
        assert_eq!(incoming_channel_target(&c, "%#staff"), None);
        assert_eq!(incoming_channel_target(&c, "@+#staff"), Some(("#staff".to_string(), true)));
        // A tracked channel whose own name starts with a prefix-like character stays itself.
        c.channels.insert(c.casemapping.fold("+#odd"), ChannelState { name: "+#odd".into(), topic: String::new(), names: vec![], key: None });
        assert_eq!(incoming_channel_target(&c, "+#odd"), Some(("+#odd".to_string(), false)));
    }

    /// r4 C1-9 (codex P1 main.rs:5882): every line that goes out reaches the recipients
    /// whole (so logging/echoing it is the truth), or the line is refused.
    /// r8 (codex P2 irc.rs:935): opaque ciphertext that the relayed line could not carry whole
    /// (the server adds `:nick!user@host`) is refused, not sent to be cut.
    #[test]
    fn oversized_opaque_text_is_refused() {
        let nick = "n".repeat(30);
        let uh = format!("u@{}", "h".repeat(88));
        let chan = format!("#{}", "c".repeat(199));
        let line = format!("PRIVMSG {} :sd8~{}", chan, "A".repeat(180));
        assert!(line.len() <= cryptirc::irc_daemon::OUT_MSG_MAX, "the command alone fits");
        let e = fit_outgoing_line(&line, &nick, &uh).unwrap_err();
        assert!(e.starts_with("Encrypted message too long"), "{e}");
        // Short enough for the relayed line: sent as is.
        let ok = format!("PRIVMSG #c :sd8~{}", "A".repeat(180));
        assert_eq!(fit_outgoing_line(&ok, &nick, &uh).unwrap(), vec![ok.clone()]);
    }

    /// r7 (codex P2 irc.rs:863): a recipient list that leaves no room for the text is refused,
    /// never sent for irc-core to cut the text off.
    #[test]
    fn too_many_recipients_for_one_line_is_refused() {
        let nicks: Vec<String> = (0..20).map(|i| format!("{:027}", i)).collect();
        let line = format!("PRIVMSG {} :hello", nicks.join(","));
        let e = fit_outgoing_line(&line, "me", "u@h").unwrap_err();
        assert!(e.starts_with("Too many recipients"), "{e}");
        let few = format!("PRIVMSG {} :hello", nicks[..3].join(","));
        assert_eq!(fit_outgoing_line(&few, "me", "u@h").unwrap(), vec![few.clone()]);
        // A long text to a few recipients is still split, as before.
        let long = format!("PRIVMSG {} :{}", nicks[..3].join(","), "word ".repeat(150));
        assert!(fit_outgoing_line(&long, "me", "u@h").unwrap().len() > 1);
    }

    #[test]
    fn outgoing_lines_fit_the_wire_or_are_refused() {
        let relay = |nick: &str, uh: &str, l: &str| {
            let msg = if l.starts_with('@') { l.split_once(' ').unwrap().1 } else { l };
            format!(":{}!{} {}", nick, uh, msg).len()
        };
        // Short lines are untouched.
        assert_eq!(fit_outgoing_line("PRIVMSG #c :hi", "me", "u@h").unwrap(), vec!["PRIVMSG #c :hi"]);
        assert_eq!(fit_outgoing_line("JOIN #a,#b ka,kb", "me", "").unwrap(), vec!["JOIN #a,#b ka,kb"]);
        // 599 bytes of words: split at spaces; every piece relays whole; nothing is lost.
        let words = (0..120).map(|i| format!("w{:03}", i)).collect::<Vec<_>>().join(" ");
        let out = fit_outgoing_line(&format!("PRIVMSG #chan :{}", words), "nick", "user@host.example").unwrap();
        assert!(out.len() >= 2 && out.len() <= MAX_SPLIT_LINES, "{} lines", out.len());
        for l in &out {
            assert!(l.starts_with("PRIVMSG #chan :"));
            assert!(relay("nick", "user@host.example", l) <= 510, "{}", l.len());
        }
        let joined: Vec<&str> = out.iter().map(|l| &l["PRIVMSG #chan :".len()..]).collect();
        assert_eq!(joined.join(" "), words);
        // Multibyte text: never cut inside a character; unknown user@host = worst case.
        let accents = "é".repeat(400);
        let out = fit_outgoing_line(&format!("NOTICE bob :{}", accents), "n", "").unwrap();
        assert!(out.len() >= 2);
        for l in &out { assert!(relay("n", &"x".repeat(75), l) <= 510); }
        assert_eq!(out.iter().map(|l| &l["NOTICE bob :".len()..]).collect::<String>(), accents);
        // ACTION keeps its CTCP wrapper on every piece; tags ride on every piece.
        for l in fit_outgoing_line(&format!("PRIVMSG #c :\u{1}ACTION {}\u{1}", words), "n", "u@h").unwrap() {
            assert!(l.starts_with("PRIVMSG #c :\u{1}ACTION ") && l.ends_with('\u{1}'), "{:?}", l);
        }
        for l in fit_outgoing_line(&format!("@+draft/reply=abc PRIVMSG #c :{}", words), "n", "u@h").unwrap() {
            assert!(l.starts_with("@+draft/reply=abc PRIVMSG #c :"));
        }
        // Tag data over the IRCv3 client limit: refused (the server would reject it).
        assert!(fit_outgoing_line(&format!("@+x={} TAGMSG #c", "a".repeat(4100)), "n", "").is_err());
        assert!(fit_outgoing_line(&format!("@+x={} TAGMSG #c", "a".repeat(4000)), "n", "").is_ok());
        // More than MAX_SPLIT_LINES pieces: refused, nothing sent.
        assert!(fit_outgoing_line(&format!("PRIVMSG #c :{}", "x ".repeat(2000)), "n", "u@h").is_err());
        // E2E ciphertext / CTCP are never cut: sent as-is when the RELAYED line keeps them
        // whole (r8: the server-added `:nick!user@host` counts — 75 bytes assumed while our
        // user@host is unknown), refused otherwise.
        let e2e = format!("PRIVMSG #c :sd8~{}", "A".repeat(410));
        assert_eq!(fit_outgoing_line(&e2e, "n", "").unwrap(), vec![e2e.clone()]);
        assert!(fit_outgoing_line(&format!("PRIVMSG #c :sd8~{}", "A".repeat(420)), "n", "").is_err());
        assert!(fit_outgoing_line(&format!("PRIVMSG #c :sd8~{}", "A".repeat(600)), "n", "").is_err());
        assert!(fit_outgoing_line(&format!("PRIVMSG bob :\u{1}PING {}\u{1}", "1".repeat(600)), "n", "").is_err());
        // A chat line without a `:` text is not split, but refused if irc-core would cut it.
        assert_eq!(fit_outgoing_line("PRIVMSG #c hello", "n", "").unwrap(), vec!["PRIVMSG #c hello"]);
        assert!(fit_outgoing_line(&format!("PRIVMSG #c {}", "h".repeat(600)), "n", "").is_err());
        // Other long lines go out as before (irc-core cuts them; nothing of them is logged).
        let topic = format!("TOPIC #c :{}", "t".repeat(600));
        assert_eq!(fit_outgoing_line(&topic, "n", "").unwrap(), vec![topic.clone()]);
    }
}
