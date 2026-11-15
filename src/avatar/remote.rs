//! Avatars across CryptIRC instances (v2). v1 (`super`) vouches for accounts of THIS
//! instance; this module lets an account's picture reach people on OTHER CryptIRC servers
//! who share an IRC network with it.
//!
//! - Publish: an owner who opts in ("Share my avatar with people on other CryptIRC
//!   servers") gets a public URL `<CRYPTIRC_BASE_URL>/avatar/pub/<id>-<version>.png`
//!   (`super::route_public_image`). The id is random and rotates when sharing is turned off
//!   or the avatar is removed.
//! - Announce: the URL travels on IRC, from the CURRENT holder of the nick (the network
//!   routes messages to whoever holds a nick now; that is the whole binding — the holder
//!   chooses their own picture, as with any avatar system):
//!   * the client-only message tag `+cryptirc.com/avatar` (needs `message-tags`), on our
//!     user's PRIVMSG / NOTICE (first line to a target, then on a URL change or every 30
//!     min), on an invisible `TAGMSG #chan` when they join a channel, and on an invisible
//!     private `TAGMSG <joiner>` to someone who joins a channel they are in (bounded);
//!   * an answer to `CTCP AVATAR` (KVIrc's query): `NOTICE <asker> :\x01AVATAR <url>\x01`;
//!   * IRCv3 `draft/metadata-2`, key `avatar` (published with METADATA SET, read through
//!     SUB / GET), where the server offers it.
//!   Opted-out owners announce nothing and never answer.
//! - Learn: what arrives is kept per viewer connection and nick (`Binding`), with the
//!   sender's user@host, and dropped on NICK / QUIT / CHGHOST from that nick, on PART / KICK
//!   when the viewer no longer sees it, and on reconnect.
//! - Fetch: only when a viewer's app asks for a nick it can see (a lookup), the viewer's
//!   SERVER fetches the URL once per TTL (public addresses only, DNS pinned, no redirects,
//!   HTTPS on port 443, 2 MB, timeouts, shared outbound permits, global / per-host /
//!   per-viewer limits), decodes it with the v1 pipeline (smaller dimension limit, its own
//!   decode slot), keeps the re-encoded 128 / 48 px PNGs on disk and serves them same-origin
//!   (`route_remote_image`, session header, no-store). The viewer's browser never contacts
//!   the other server.
//! - Queries (CTCP / METADATA GET) are sent only for an explicit nick menu or WHOIS of a
//!   nick with nothing known, rate-limited; never for a channel's member list.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use tokio::sync::{Mutex, Semaphore};

use super::{AvatarRouteState, AvatarStore, Processed};
use crate::irc::IrcConnection;

/// The client-only message tag that carries an announce (vendor-prefixed with the project's
/// domain), and its name as CLIENTTAGDENY lists it.
pub const TAG_KEY: &str = "+cryptirc.com/avatar";
const TAG_NAME: &str = "cryptirc.com/avatar";
pub const META_CAP: &str = "draft/metadata-2";
const META_KEY: &str = "avatar";
/// Longest announced URL accepted (ours are ~100 bytes).
pub const URL_MAX: usize = 400;
/// IRCv3: tag data a client may send (without the `@` and the separating space).
const CLIENT_TAG_DATA_MAX: usize = 4094;

const BINDINGS_MAX: usize = 2048;
/// Metadata values that arrived before the nick's user@host was known (e.g. a join sync
/// before NAMES): held this long, at most this many per connection, then dropped.
const META_HELD_MAX: usize = 256;
const META_HELD_TTL: Duration = Duration::from_secs(30);
const JOINED_MAX: usize = 1024;
/// Re-announce on speech / join at most this often per target (unless the URL changes).
const ANNOUNCE_EVERY: Duration = Duration::from_secs(30 * 60);
const ANNOUNCED_MAX: usize = 16384;
/// Welcome TAGMSGs: one per joiner per window, few per channel / connection / process.
const WELCOME_EVERY: Duration = Duration::from_secs(30 * 60);
const WELCOME_PER_CHANNEL_MIN: u32 = 5;
const WELCOME_PER_CONN_MIN: u32 = 10;
const WELCOME_GLOBAL_MIN: u32 = 200;
/// No welcomes this long after our own JOIN of the channel (the join burst).
const WELCOME_BURST: Duration = Duration::from_secs(10);
const WELCOME_DELAY_MS: u64 = 5000;
/// A CryptIRC peer's channel announce is answered privately (it may not know us), once per
/// peer per window, capped per connection and process — not when a welcome to it was just
/// scheduled (its JOIN came first). The peer itself announces at most every 30 min per
/// channel (or after a PART / nick / host change / reconnect), so the window is short (it only
/// stops a ping-pong); a peer that varies its URL to provoke answers gets at most one per
/// window from each member, within the per-connection and process caps.
const PEER_REPLY_EVERY: Duration = Duration::from_secs(10);
const PEER_REPLY_AFTER_WELCOME: Duration = Duration::from_secs(15);
const PEER_REPLY_PER_CONN_MIN: u32 = 20;
const PEER_REPLY_GLOBAL_MIN: u32 = 300;
const PEER_REPLY_DELAY_MS: u64 = 2000;
/// After our own nick / host change, at most this many channels are re-announced.
const REANNOUNCE_MAX_CHANNELS: usize = 20;
/// On-demand queries: one per nick per window; few per viewer and process.
const PROBE_EVERY: Duration = Duration::from_secs(15 * 60);
const PROBE_VIEWER_10MIN: u32 = 10;
const PROBE_GLOBAL_MIN: u32 = 60;
const PROBES_PER_LOOKUP: usize = 3;
/// An answer to our own query (CTCP AVATAR / METADATA GET) counts only this long after it.
const ANSWER_WINDOW: Duration = Duration::from_secs(20);
/// CTCP AVATAR answers: one per asker per window, few per connection and process.
const REPLY_EVERY: Duration = Duration::from_secs(120);
const REPLY_PER_CONN_MIN: u32 = 10;
const REPLY_GLOBAL_MIN: u32 = 120;
/// Fetching: fresh for OK_TTL (then refreshed on the next view, If-None-Match), shown at
/// most STALE_MAX without a successful refresh; a failure is remembered for FAIL_TTL.
const OK_TTL: Duration = Duration::from_secs(60 * 60);
const STALE_MAX: Duration = Duration::from_secs(6 * 60 * 60);
const FAIL_TTL: Duration = Duration::from_secs(30 * 60);
const FETCH_STUCK: Duration = Duration::from_secs(90);
const CACHE_MAX_ENTRIES: usize = 1000;
const WAITERS_MAX: usize = 32;
const FETCH_CONCURRENT: usize = 2;
const FETCH_GLOBAL_MIN: u32 = 20;
const FETCH_HOST_10MIN: u32 = 30;
const FETCH_VIEWER_10MIN: u32 = 60;
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
const FETCH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PERMIT_WAIT: Duration = Duration::from_secs(5);
const REMOTE_MAX_BYTES: usize = super::MAX_UPLOAD_BYTES;
/// Remote pictures are meant to be small; this keeps one decode near 16 MiB of pixels.
pub const REMOTE_MAX_DIMENSION: u32 = 2048;
const REMOTE_DECODE_ALLOC: u64 = 64 * 1024 * 1024;
const RATES_MAX: usize = 16384;
/// An announce on a line the server stamped more than this before it was received (bouncer
/// / chathistory playback), or inside a batch, is ignored: the nick may have changed hands
/// since, and the playback need not show that. Stamps further ahead than irc.rs accepts
/// (SERVER_TIME_MAX_FUTURE) are refused too.
const ANNOUNCE_MAX_AGE_SECS: i64 = 120;
const ANNOUNCE_MAX_AHEAD_SECS: i64 = 5 * 60;

/// Open BATCHes tracked per connection (more → all forgotten: no line counts as metadata).
const BATCHES_MAX: usize = 64;
/// The only batch types whose lines may concern nicks the connection does not see yet: the
/// server's metadata sync for a channel being joined, and the answer to our METADATA GET.
const META_BATCH_TYPES: &[&str] = &["metadata", "draft/metadata"];
const MINUTE: Duration = Duration::from_secs(60);
const TEN_MINUTES: Duration = Duration::from_secs(600);

// ─── Line-level helpers ───────────────────────────────────────────────────────

/// The arguments of a CTCP AVATAR (`\x01AVATAR[ args]\x01`), or None for anything else.
pub fn ctcp_avatar(text: &str) -> Option<&str> {
    let inner = text.strip_prefix('\u{1}')?;
    let inner = inner.strip_suffix('\u{1}').unwrap_or(inner);
    let (cmd, args) = inner.split_once(' ').unwrap_or((inner, ""));
    cmd.eq_ignore_ascii_case("AVATAR").then(|| args.trim())
}

/// The URL of a CTCP AVATAR answer (`AVATAR <url> [size]`, KVIrc's form).
pub fn reply_url(args: &str) -> Option<&str> {
    args.split_whitespace().next()
}

/// IRCv3 tag-value escaping.
pub fn escape_tag_value(v: &str) -> String {
    let mut o = String::with_capacity(v.len() + 8);
    for ch in v.chars() {
        match ch {
            ';' => o.push_str("\\:"),
            ' ' => o.push_str("\\s"),
            '\\' => o.push_str("\\\\"),
            '\r' => o.push_str("\\r"),
            '\n' => o.push_str("\\n"),
            c => o.push(c),
        }
    }
    o
}

/// `line` with our announce tag added (merged into an existing tag section). None when the
/// tag data would exceed the client limit — the caller then sends the line without it.
pub fn with_tag(line: &str, url: &str) -> Option<String> {
    let tag = format!("{}={}", TAG_KEY, escape_tag_value(url));
    if let Some(rest) = line.strip_prefix('@') {
        let (tags, msg) = rest.split_once(' ')?;
        if tags.split(';').any(|t| t.split('=').next() == Some(TAG_KEY)) {
            return Some(line.to_string());
        }
        if tags.len() + 1 + tag.len() > CLIENT_TAG_DATA_MAX {
            return None;
        }
        Some(format!("@{};{} {}", tags, tag, msg))
    } else {
        if tag.len() > CLIENT_TAG_DATA_MAX {
            return None;
        }
        Some(format!("@{} {}", tag, line))
    }
}

/// May our tag be sent, given the server's ISUPPORT CLIENTTAGDENY (None = not announced)?
pub fn client_tag_allowed(deny: Option<&str>) -> bool {
    let Some(d) = deny else { return true };
    let (mut all, mut exempt, mut listed) = (false, false, false);
    for t in d.split(',').map(str::trim) {
        if t == "*" {
            all = true;
        } else if t.strip_prefix('-') == Some(TAG_NAME) {
            exempt = true;
        } else if t == TAG_NAME {
            listed = true;
        }
    }
    !(listed || (all && !exempt))
}

/// The CLIENTTAGDENY value of one ISUPPORT line: Some(Some(v)) set, Some(None) withdrawn
/// (`-CLIENTTAGDENY`), None not mentioned.
pub fn clienttagdeny_from_isupport(params: &[String]) -> Option<Option<String>> {
    let mut out = None;
    for t in params.iter().skip(1) {
        if t.eq_ignore_ascii_case("-CLIENTTAGDENY") {
            out = Some(None);
        } else if let Some((k, v)) = t.split_once('=') {
            if k.eq_ignore_ascii_case("CLIENTTAGDENY") {
                out = Some(Some(v.chars().take(1024).collect()));
            }
        }
    }
    out
}

/// Does a CAP LS / NEW / ACK / DEL list name `cap` (exact name; `=value` ignored)?
pub fn cap_list_has(caps: &str, cap: &str) -> bool {
    caps.split_whitespace().any(|c| c.split('=').next() == Some(cap))
}

/// Is this a URL host that could be a public server? (names: not localhost / .local /
/// .internal; IP literals: public, or loopback in the debug-build test mode).
fn plausible_public_host(host: &str, test_loopback: bool) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(&h).to_string();
    if h.is_empty() {
        return false;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return !crate::preview::is_private_ip(ip) || (test_loopback && ip.is_loopback());
    }
    !(h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") || h.ends_with(".internal") || !h.contains('.'))
        || (test_loopback && h == "localhost")
}

/// The public base of this instance (CRYPTIRC_BASE_URL) when other servers could reach it:
/// https (http only in the debug-build test mode) and a plausible public host. None → this
/// server announces nothing (sharing is unavailable).
pub fn announce_base(base_url: &str, test_loopback: bool) -> Option<String> {
    let base = base_url.trim().trim_end_matches('/');
    let u = reqwest::Url::parse(base).ok()?;
    let scheme_ok = u.scheme() == "https" || (test_loopback && u.scheme() == "http");
    if !scheme_ok || !u.username().is_empty() || u.password().is_some() || u.query().is_some() || u.fragment().is_some() {
        return None;
    }
    plausible_public_host(u.host_str()?, test_loopback).then(|| base.to_string())
}

/// Host and port of CRYPTIRC_BASE_URL (to recognise announces that point at this instance).
fn own_origin(base_url: &str) -> Option<(String, u16)> {
    let u = reqwest::Url::parse(base_url.trim()).ok()?;
    let host = u.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    Some((host, u.port_or_known_default()?))
}

/// Debug builds only: CRYPTIRC_AVATAR_TEST_LOOPBACK=1 lets the two-instance test run on one
/// machine (http, loopback addresses, any port). Release builds never read it.
fn test_loopback_from_env() -> bool {
    #[cfg(debug_assertions)]
    {
        let on = std::env::var("CRYPTIRC_AVATAR_TEST_LOOPBACK").map_or(false, |v| v == "1");
        if on {
            tracing::warn!("avatars: CRYPTIRC_AVATAR_TEST_LOOPBACK is on (debug build) — remote avatars may be fetched over http from loopback");
        }
        on
    }
    #[cfg(not(debug_assertions))]
    {
        false
    }
}

/// An announced URL, normalised, if acceptable: https on port 443 (debug test mode: http and
/// any port too), no credentials, a host that is not this instance (a URL pointing here never
/// bypasses v1's checks: v1 alone decides about this instance's accounts), at most URL_MAX.
pub fn checked_url(raw: &str, own: Option<&(String, u16)>, test_loopback: bool) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > URL_MAX || raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return None;
    }
    let mut u = reqwest::Url::parse(raw).ok()?;
    let scheme_ok = u.scheme() == "https" || (test_loopback && u.scheme() == "http");
    if !scheme_ok || !u.username().is_empty() || u.password().is_some() {
        return None;
    }
    crate::preview::canonicalize_url_host(&mut u).ok()?;
    let host = u.host_str()?.to_ascii_lowercase();
    let port = u.port_or_known_default()?;
    if host.is_empty() || (!test_loopback && port != 443) || !plausible_public_host(&host, test_loopback) {
        return None;
    }
    if let Some((oh, op)) = own {
        if *oh == host && (!test_loopback || *op == port) {
            return None;
        }
    }
    u.set_fragment(None);
    Some(u.to_string())
}

fn lower(n: &str) -> String {
    n.to_ascii_lowercase()
}

fn strip_pfx(n: &str) -> &str {
    cryptirc::ircproto::strip_pfx(n)
}

// ─── Per-connection state ─────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Ctcp,
    Tag,
    Meta,
}

/// What the current holder of a nick announced on this connection.
#[derive(Clone, Debug)]
pub struct Binding {
    pub url: String,
    /// The sender's user@host when the announce arrived ("" for metadata without one).
    pub userhost: String,
    pub source: Source,
    pub at: Instant,
}

/// Per IrcConnection (`IrcConnection::avx`): announces learned on it, and what it
/// negotiated for this feature. Reset with the IRC session.
#[derive(Debug, Default, Clone)]
pub struct ConnState {
    bindings: HashMap<String, Binding>,
    joined_at: HashMap<String, Instant>,
    /// Open BATCHes: reference → type ("" when it is nested in a batch that is not a
    /// metadata one, so it never counts as metadata).
    batches: HashMap<String, String>,
    /// Metadata values waiting for the nick's user@host (`metadata_line`, `promote_held`).
    meta_held: HashMap<String, (String, Instant)>,
    /// The server offers draft/metadata-2 (live CAP LS / NEW), we asked, it is on (ACK).
    pub meta2_offered: bool,
    pub meta2_requested: bool,
    pub meta2_on: bool,
    /// ISUPPORT CLIENTTAGDENY (None: not announced).
    pub client_tag_deny: Option<String>,
}

impl ConnState {
    pub fn reset(&mut self) {
        *self = ConnState::default();
    }
    /// After an Attach whose replay does not prove the same irc-core session (the IRC
    /// connection may have restarted meanwhile, its lifecycle events unseen): forget every
    /// announce, open batch and negotiated metadata state. CLIENTTAGDENY stays (the replay's
    /// own 005 lines set it, in order).
    pub fn drop_unproven(&mut self) {
        let deny = self.client_tag_deny.take();
        *self = ConnState::default();
        self.client_tag_deny = deny;
    }
    pub fn tags_allowed(&self) -> bool {
        client_tag_allowed(self.client_tag_deny.as_deref())
    }
    pub fn binding(&self, nick: &str) -> Option<&Binding> {
        self.bindings.get(&lower(nick))
    }
    pub fn bindings_len(&self) -> usize {
        self.bindings.len()
    }
    /// Keep an announce for `nick`. True when it is new or changed.
    pub fn learn(&mut self, nick: &str, b: Binding) -> bool {
        let k = lower(nick);
        if let Some(old) = self.bindings.get_mut(&k) {
            let same = old.url == b.url && old.userhost == b.userhost;
            *old = b;
            return !same;
        }
        if self.bindings.len() >= BINDINGS_MAX {
            if let Some(oldest) = self.bindings.iter().min_by_key(|(_, v)| v.at).map(|(k, _)| k.clone()) {
                self.bindings.remove(&oldest);
            }
        }
        self.bindings.insert(k, b);
        true
    }
    pub fn forget(&mut self, nick: &str) -> bool {
        self.held_forget(nick);
        self.bindings.remove(&lower(nick)).is_some()
    }
    fn hold_meta(&mut self, nick: &str, url: String) {
        let now = Instant::now();
        self.meta_held.retain(|_, (_, t)| now.duration_since(*t) < META_HELD_TTL);
        if self.meta_held.len() >= META_HELD_MAX && !self.meta_held.contains_key(&lower(nick)) {
            return;
        }
        self.meta_held.insert(lower(nick), (url, now));
    }
    fn held_forget(&mut self, nick: &str) {
        self.meta_held.remove(&lower(nick));
    }
    pub fn held_len(&self) -> usize {
        self.meta_held.len()
    }
    /// A metadata "key not set / deleted" for `nick`: only a metadata binding goes.
    pub fn forget_meta(&mut self, nick: &str) -> bool {
        let k = lower(nick);
        if self.bindings.get(&k).map_or(false, |b| b.source == Source::Meta) {
            self.bindings.remove(&k);
            return true;
        }
        false
    }
    /// NICK old → new: the old nick's announce is dropped (someone else may take it) and so
    /// is anything kept for the new nick (an earlier holder's). A metadata binding — the
    /// server's per-user data, which follows the user — moves to the new nick.
    pub fn renamed(&mut self, old: &str, new: &str) -> bool {
        self.held_forget(old);
        self.held_forget(new);
        let gone_new = self.bindings.remove(&lower(new)).is_some();
        match self.bindings.remove(&lower(old)) {
            Some(b) => {
                if b.source == Source::Meta && !new.is_empty() {
                    self.bindings.insert(lower(new), b);
                }
                true
            }
            None => gone_new,
        }
    }
    /// Drop announces of nicks the connection no longer sees (`visible`: ASCII-lowercased).
    pub fn retain_visible(&mut self, visible: &HashSet<String>) -> Vec<String> {
        self.meta_held.retain(|k, _| visible.contains(k));
        let gone: Vec<String> = self.bindings.keys().filter(|k| !visible.contains(*k)).cloned().collect();
        for k in &gone {
            self.bindings.remove(k);
        }
        gone
    }
    /// `BATCH +ref type` (`parent`: the `batch` tag on that line, if nested).
    pub fn batch_open(&mut self, reference: &str, kind: &str, parent: Option<&str>) {
        if reference.is_empty() || reference.len() > 64 {
            return;
        }
        if self.batches.len() >= BATCHES_MAX {
            self.batches.clear();
        }
        let inherited_ok = parent.map_or(true, |p| self.batch_is_metadata(p));
        let kind = if inherited_ok { kind.chars().take(64).collect() } else { String::new() };
        self.batches.insert(reference.to_string(), kind);
    }
    pub fn batch_close(&mut self, reference: &str) {
        self.batches.remove(reference);
    }
    /// Is `reference` an open metadata batch (sync or the answer to our GET), not nested in
    /// a playback / history batch?
    pub fn batch_is_metadata(&self, reference: &str) -> bool {
        self.batches.get(reference).map_or(false, |k| META_BATCH_TYPES.iter().any(|t| k.eq_ignore_ascii_case(t)))
    }
    pub fn note_joined(&mut self, channel: &str) {
        if self.joined_at.len() >= JOINED_MAX {
            self.joined_at.clear();
        }
        self.joined_at.insert(lower(channel), Instant::now());
    }
    fn recently_joined(&self, channel: &str, within: Duration) -> bool {
        self.joined_at.get(&lower(channel)).map_or(false, |t| t.elapsed() < within)
    }
}

/// The nicks a connection sees (channel members, fresh WHOIS replies), ASCII-lowercased.
pub fn visible_nicks(c: &IrcConnection) -> HashSet<String> {
    let mut v: HashSet<String> = c.channels.values().flat_map(|ch| ch.names.iter().map(|n| lower(strip_pfx(n)))).collect();
    v.extend(c.whois_seen.fresh().map(lower));
    v
}

/// Is a line's server-time recent: at most ANNOUNCE_MAX_AGE_SECS before `received` (when
/// this process — or irc-core, for a replayed line — read it) and not more than
/// ANNOUNCE_MAX_AHEAD_SECS after it? A missing or unreadable stamp counts only on a live line
/// of a connection not behind a bouncer (`strict` false): it is happening now. For a replayed
/// line or a bouncer connection (playback may come without a usable stamp) it does not.
pub fn time_is_fresh(tags: &HashMap<String, String>, received: i64, strict: bool) -> bool {
    time_within(tags, received, strict, ANNOUNCE_MAX_AGE_SECS)
}
fn time_within(tags: &HashMap<String, String>, received: i64, strict: bool, max_age: i64) -> bool {
    match tags.get("time").map(|t| chrono::DateTime::parse_from_rfc3339(t)) {
        Some(Ok(t)) => (received - max_age..=received + ANNOUNCE_MAX_AHEAD_SECS).contains(&t.timestamp()),
        Some(Err(_)) | None => !strict,
    }
}

/// How a line arrived, for `announce_is_fresh` / `metadata_line`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    /// From irc-core's Attach replay ring.
    pub replayed: bool,
    /// The connection is behind a bouncer OR not classified (no CAP negotiation seen —
    /// e.g. after a web restart whose replay could not prove the session): a bouncer may
    /// play back old lines unbatched and freshly stamped, indistinguishable from live ones.
    pub restricted: bool,
}

/// Is a connection restricted (`Arrival::restricted`)? Unknown counts as a bouncer.
pub fn restricted(c: &IrcConnection) -> bool {
    !c.cap_ls_done || c.behind_bouncer
}

/// May an announce (message tag, TAGMSG) carried by a line with these tags count? Never on a
/// restricted connection: like v1's bouncer exclusion, a connection through a bouncer (or
/// not classified) learns NO remote avatar at all, solicited or not — no freshness window
/// or query correlation tells a bouncer's playback from a live line (codex astra re-checks).
/// Never inside a batch. A plain
/// connection's live line: a server-time, if any, within the last 2 minutes (none = now);
/// a replayed one: a readable server-time within the last 2 minutes. The viewer's own
/// settings play no part: receiving never depends on whether the viewer shares.
pub fn announce_is_fresh(tags: &HashMap<String, String>, received: i64, arrival: Arrival) -> bool {
    if arrival.restricted || tags.contains_key("batch") {
        return false;
    }
    time_is_fresh(tags, received, arrival.replayed)
}

/// Does an answer to our own CTCP query come from the user we asked? `asked`: the user@host
/// this connection showed for the nick when we asked (equal when it was known).
pub fn answer_matches(asked: Option<&str>, answer_userhost: &str) -> bool {
    asked.map_or(true, |a| super::same_userhost(a, answer_userhost))
}

/// Does this connection see `nick` right now (a member of one of its channels, or a fresh
/// WHOIS reply)? An announce from a nick it does not see is not learned: while out of sight
/// the nick may change hands unseen (v1's rule), and a late private announce could otherwise
/// outlive the PART that should have dropped it.
pub fn sees(c: &IrcConnection, nick: &str) -> bool {
    c.channels.values().any(|ch| ch.names.iter().any(|n| strip_pfx(n).eq_ignore_ascii_case(nick)))
        || c.whois_seen.fresh().any(|n| n.eq_ignore_ascii_case(nick))
}

/// Learn an announce carried by a line from `prefix` (`nick!user@host` — never a server
/// source), unless it is our own (`own_nick`, the nick we had when the line arrived), from a
/// nick this connection does not see, or on a restricted connection (`restricted`).
pub fn learn_from_prefix(c: &mut IrcConnection, remote: &RemoteAvatars, prefix: Option<&str>, raw_url: &str, source: Source, own_nick: &str) -> Option<String> {
    let (nick, userhost) = prefix?.split_once('!')?;
    if restricted(c) || !super::plausible_nick(nick) || !userhost.contains('@') || crate::irc::same_nick(nick, own_nick) || !sees(c, nick) {
        return None;
    }
    let url = remote.check_url(raw_url)?;
    c.avx
        .learn(nick, Binding { url, userhost: userhost.to_string(), source, at: Instant::now() })
        .then(|| nick.to_string())
}

/// A nick left (PART / KICK of someone else) or — `None` — we left a channel: its held
/// metadata value is dropped whatever else it still shares (the holder may change while
/// unseen — codex astra re-check 3 M irc.rs:1125), and announces of nicks no longer seen go.
/// QUIT / NICK / CHGHOST forget through ConnState::forget / renamed, which drop held values
/// too. Returns the nicks whose announce went.
pub fn on_departure(c: &mut IrcConnection, left: Option<&str>) -> Vec<String> {
    if let Some(nick) = left {
        c.avx.held_forget(nick);
    }
    if c.avx.bindings_len() == 0 && c.avx.held_len() == 0 {
        return Vec::new();
    }
    match left {
        Some(nick) => {
            if !sees(c, nick) && c.avx.forget(nick) {
                vec![nick.to_string()]
            } else {
                Vec::new()
            }
        }
        None => {
            let visible = visible_nicks(c);
            c.avx.retain_visible(&visible)
        }
    }
}

/// Bind held metadata values whose nick now has a known user@host (NAMES with
/// userhost-in-names, WHO, a JOIN prefix, WHOIS) and is still seen; expired ones go. Called
/// after each line's observations (irc.rs). Returns the nicks that changed.
pub fn promote_held(c: &mut IrcConnection) -> Vec<String> {
    if c.avx.meta_held.is_empty() {
        return Vec::new();
    }
    let now = Instant::now();
    c.avx.meta_held.retain(|_, (_, t)| now.duration_since(*t) < META_HELD_TTL);
    if restricted(c) {
        c.avx.meta_held.clear();
        return Vec::new();
    }
    let ready: Vec<(String, String, String)> = c
        .avx
        .meta_held
        .iter()
        .filter_map(|(k, (url, _))| c.seen_userhosts.get(k).filter(|_| sees(c, k)).map(|uh| (k.clone(), url.clone(), uh.to_string())))
        .collect();
    let mut changed = Vec::new();
    for (k, url, userhost) in ready {
        c.avx.meta_held.remove(&k);
        if c.avx.learn(&k, Binding { url, userhost, source: Source::Meta, at: now }) {
            changed.push(k);
        }
    }
    changed
}

/// Metadata lines (761 / 760 / 766 / 770–774 / METADATA / FAIL METADATA) that concern the
/// `avatar` key or our subscription: consumed here (never shown). Returns None when the line
/// is not one of them; Some(changed nick or None) otherwise. A value is learned only from a
/// line with a fresh server-time (as for announces) that is either outside any batch, for a nick this connection sees, or inside a
/// metadata batch (the server's sync for a channel being joined — its NAMES follow — or the
/// answer to our GET; never a playback / history batch, nor one nested in it). Nothing is
/// learned on a restricted connection. A value for a nick whose user@host is not known yet is
/// held (bounded, short-lived) and bound when one is first observed (`promote_held`). A
/// deletion is always applied (forgetting is safe).
pub fn metadata_line(c: &mut IrcConnection, remote: &RemoteAvatars, command: &str, tags: &HashMap<String, String>, params: &[String], own_nick: &str, received: i64, arrival: Arrival) -> Option<Option<String>> {
    let p = |i: usize| params.get(i).map(String::as_str);
    // (target, key, value) of a key/value line.
    let kv = match command {
        // RPL_WHOISKEYVALUE / RPL_KEYVALUE: <client> <target> <key> <visibility> [:<value>]
        "760" | "761" => Some((p(1)?, p(2)?, p(4))),
        // METADATA <target> <key> <visibility> [:<value>]
        "METADATA" => Some((p(0)?, p(1)?, p(3))),
        // RPL_KEYNOTSET: <client> <target> <key> :key not set / deleted
        "766" => Some((p(1)?, p(2)?, None)),
        "770" | "771" | "772" => return params.iter().skip(1).any(|k| k.eq_ignore_ascii_case(META_KEY)).then_some(None),
        "774" => return Some(None),
        "FAIL" | "WARN" | "NOTE" => return (p(0)? == "METADATA").then_some(None),
        _ => None,
    };
    let (target, key, value) = kv?;
    if !key.eq_ignore_ascii_case(META_KEY) {
        return None;
    }
    if target == "*" || target.starts_with(['#', '&', '+', '!']) || !super::plausible_nick(target) || crate::irc::same_nick(target, own_nick) {
        return Some(None);
    }
    let batch = tags.get("batch").map(String::as_str);
    let meta_batch = batch.map_or(false, |b| c.avx.batch_is_metadata(b));
    let learn_url = value.filter(|v| !v.is_empty() && command != "766").and_then(|v| remote.check_url(v));
    let usable = if learn_url.is_none() {
        true // a deletion / an unusable value only ever forgets
    } else {
        !arrival.restricted && time_is_fresh(tags, received, arrival.replayed) && (meta_batch || (batch.is_none() && sees(c, target)))
    };
    if !usable {
        return Some(None);
    }
    let changed = match learn_url {
        Some(url) => match c.seen_userhosts.get(target).map(str::to_string) {
            // Never bound without a known user@host (codex astra re-check 2 M remote.rs:583).
            Some(userhost) => {
                c.avx.held_forget(target);
                c.avx.learn(target, Binding { url, userhost, source: Source::Meta, at: Instant::now() })
            }
            None => {
                c.avx.hold_meta(target, url);
                false
            }
        },
        _ => {
            c.avx.held_forget(target);
            c.avx.forget_meta(target)
        }
    };
    Some(changed.then(|| target.to_string()))
}

// ─── The service ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Waiter {
    owner: String,
    conn_id: String,
    nick: String,
}

#[derive(Clone, Debug)]
struct Entry {
    rid: String,
    host: String,
    /// The version of the re-encoded picture on disk, if any.
    ready_v: Option<String>,
    etag: Option<String>,
    fetching: bool,
    failed: bool,
    /// Last successful fetch / revalidation (ready), failure, or fetch start.
    at: Instant,
    fetch_started: Instant,
}

/// What the cache has for a URL.
#[derive(Debug, PartialEq, Eq)]
pub enum Status {
    /// rid, version, host; `refresh`: older than OK_TTL (shown, revalidated now).
    Ready { rid: String, v: String, host: String, refresh: bool },
    Pending,
    Failed,
    Missing,
}

#[derive(Debug, Clone, Copy)]
struct Window {
    start: Instant,
    n: u32,
}

pub struct RemoteAvatars {
    dir: PathBuf,
    secret: [u8; 32],
    entries: DashMap<String, Entry>,
    by_rid: DashMap<String, String>,
    waiters: DashMap<String, Vec<Waiter>>,
    decode_slot: Arc<Semaphore>,
    fetch_slots: Arc<Semaphore>,
    /// The process-wide outbound fetch permits shared with link previews (#33).
    outbound: Arc<Semaphore>,
    rates: DashMap<String, Window>,
    cooldowns: DashMap<String, Instant>,
    announced: DashMap<String, (String, Instant)>,
    /// Our own on-demand queries (CTCP AVATAR, METADATA GET) awaiting an answer: when sent,
    /// and the user@host the connection showed for the nick then.
    ctcp_pending: DashMap<String, (Instant, Option<String>)>,
    own: Option<(String, u16)>,
    events: crate::UserEventMap,
    test_loopback: bool,
    fetch_timeout: Duration,
}

impl RemoteAvatars {
    /// The cache directory (`<data>/avatar_remote`) is emptied at startup: the index lives in
    /// memory only and is rebuilt on demand.
    pub fn new(data_dir: &str, outbound: Arc<Semaphore>, events: crate::UserEventMap, base_url: &str) -> Self {
        let dir = PathBuf::from(data_dir).join("avatar_remote");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::create_dir_all(&dir);
        Self::with(dir, outbound, events, base_url, test_loopback_from_env(), FETCH_TIMEOUT)
    }

    pub fn with(dir: PathBuf, outbound: Arc<Semaphore>, events: crate::UserEventMap, base_url: &str, test_loopback: bool, fetch_timeout: Duration) -> Self {
        RemoteAvatars {
            dir,
            secret: rand::random::<[u8; 32]>(),
            entries: DashMap::new(),
            by_rid: DashMap::new(),
            waiters: DashMap::new(),
            decode_slot: Arc::new(Semaphore::new(1)),
            fetch_slots: Arc::new(Semaphore::new(FETCH_CONCURRENT)),
            outbound,
            rates: DashMap::new(),
            cooldowns: DashMap::new(),
            announced: DashMap::new(),
            ctcp_pending: DashMap::new(),
            own: own_origin(base_url),
            events,
            test_loopback,
            fetch_timeout,
        }
    }

    pub fn test_loopback(&self) -> bool {
        self.test_loopback
    }

    pub fn check_url(&self, raw: &str) -> Option<String> {
        checked_url(raw, self.own.as_ref(), self.test_loopback)
    }

    fn rid(&self, url: &str) -> String {
        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<sha2::Sha256> as Mac>::new_from_slice(&self.secret).expect("hmac key");
        mac.update(url.as_bytes());
        mac.finalize().into_bytes().iter().take(16).map(|b| format!("{:02x}", b)).collect()
    }

    // ── limits ──

    /// Fixed-window counter `key`: may one more happen (and count it)?
    fn take(&self, key: &str, max: u32, per: Duration) -> bool {
        let now = Instant::now();
        if self.rates.len() > RATES_MAX {
            self.rates.retain(|_, w| now.duration_since(w.start) < Duration::from_secs(3600));
        }
        let mut e = self.rates.entry(key.to_string()).or_insert(Window { start: now, n: 0 });
        if now.duration_since(e.start) >= per {
            *e = Window { start: now, n: 0 };
        }
        if e.n >= max {
            return false;
        }
        e.n += 1;
        true
    }
    fn would_take(&self, key: &str, max: u32, per: Duration) -> bool {
        self.rates.get(key).map_or(true, |w| w.start.elapsed() >= per || w.n < max)
    }
    /// At most once per `every` for `key` (recorded when allowed).
    fn cooldown(&self, key: &str, every: Duration) -> bool {
        let now = Instant::now();
        if self.cooldowns.len() > RATES_MAX {
            self.cooldowns.retain(|_, t| now.duration_since(*t) < Duration::from_secs(3600));
        }
        if self.cooldowns.get(key).map_or(false, |t| now.duration_since(*t) < every) {
            return false;
        }
        self.cooldowns.insert(key.to_string(), now);
        true
    }
    fn cooling(&self, key: &str, every: Duration) -> bool {
        self.cooldowns.get(key).map_or(false, |t| t.elapsed() < every)
    }

    /// An on-demand query (CTCP / METADATA GET) for `nick` on `conn` by `viewer`.
    pub fn probe_allowed(&self, viewer: &str, conn: &str, nick: &str) -> bool {
        let k = format!("p:{}\n{}", conn, lower(nick));
        if self.cooling(&k, PROBE_EVERY)
            || !self.would_take(&format!("pv:{}", viewer), PROBE_VIEWER_10MIN, TEN_MINUTES)
            || !self.would_take("pg", PROBE_GLOBAL_MIN, MINUTE)
        {
            return false;
        }
        self.cooldown(&k, PROBE_EVERY) && self.take(&format!("pv:{}", viewer), PROBE_VIEWER_10MIN, TEN_MINUTES) && self.take("pg", PROBE_GLOBAL_MIN, MINUTE)
    }
    fn note_pending(map: &DashMap<String, (Instant, Option<String>)>, conn: &str, nick: &str, userhost: Option<String>) {
        let now = Instant::now();
        if map.len() > 4096 {
            map.retain(|_, (t, _)| now.duration_since(*t) < ANSWER_WINDOW);
        }
        map.insert(format!("{}\n{}", conn, lower(nick)), (now, userhost));
    }
    fn take_pending(map: &DashMap<String, (Instant, Option<String>)>, conn: &str, nick: &str) -> Option<Option<String>> {
        map.remove(&format!("{}\n{}", conn, lower(nick))).and_then(|(_, (t, uh))| (t.elapsed() < ANSWER_WINDOW).then_some(uh))
    }
    pub fn note_ctcp_sent(&self, conn: &str, nick: &str, userhost: Option<String>) {
        Self::note_pending(&self.ctcp_pending, conn, nick, userhost);
    }
    /// A CTCP AVATAR answer from `nick` on `conn` counts only within ANSWER_WINDOW of our own
    /// query, once: Some(the user@host shown when we asked).
    pub fn take_ctcp_answer(&self, conn: &str, nick: &str) -> Option<Option<String>> {
        Self::take_pending(&self.ctcp_pending, conn, nick)
    }
    /// Our query to `nick` on `conn` is void: that nick changed (NICK / QUIT / PART / KICK) or
    /// answered — even negatively (codex astra re-check 2).
    pub fn forget_query(&self, conn: &str, nick: &str) {
        self.ctcp_pending.remove(&format!("{}\n{}", conn, lower(nick)));
    }
    /// Answer a CTCP AVATAR from `asker` (nick!user@host, lowercased) on `conn`?
    pub fn reply_allowed(&self, conn: &str, asker: &str) -> bool {
        let k = format!("r:{}\n{}", conn, asker);
        if self.cooling(&k, REPLY_EVERY)
            || !self.would_take(&format!("rc:{}", conn), REPLY_PER_CONN_MIN, MINUTE)
            || !self.would_take("rg", REPLY_GLOBAL_MIN, MINUTE)
        {
            return false;
        }
        self.cooldown(&k, REPLY_EVERY) && self.take(&format!("rc:{}", conn), REPLY_PER_CONN_MIN, MINUTE) && self.take("rg", REPLY_GLOBAL_MIN, MINUTE)
    }
    /// Is an announce of `url` to `target` on `conn` due (first time, URL changed, or older
    /// than ANNOUNCE_EVERY)? Recorded when it is.
    pub fn announce_due(&self, conn: &str, target: &str, url: &str) -> bool {
        let k = format!("{}\n{}", conn, lower(target));
        let now = Instant::now();
        if let Some(e) = self.announced.get(&k) {
            if e.0 == url && now.duration_since(e.1) < ANNOUNCE_EVERY {
                return false;
            }
        }
        if self.announced.len() >= ANNOUNCED_MAX {
            self.announced.retain(|_, (_, t)| now.duration_since(*t) < ANNOUNCE_EVERY);
            if self.announced.len() >= ANNOUNCED_MAX {
                self.announced.clear();
            }
        }
        self.announced.insert(k, (url.to_string(), now));
        true
    }
    /// A welcome TAGMSG to `joiner` of `channel` on `conn`?
    pub fn welcome_allowed(&self, conn: &str, channel: &str, joiner: &str) -> bool {
        let k = format!("w:{}\n{}", conn, lower(joiner));
        let ch = format!("wch:{}\n{}", conn, lower(channel));
        let wc = format!("wc:{}", conn);
        if self.cooling(&k, WELCOME_EVERY)
            || !self.would_take(&ch, WELCOME_PER_CHANNEL_MIN, MINUTE)
            || !self.would_take(&wc, WELCOME_PER_CONN_MIN, MINUTE)
            || !self.would_take("wg", WELCOME_GLOBAL_MIN, MINUTE)
        {
            return false;
        }
        self.cooldown(&k, WELCOME_EVERY)
            && self.take(&ch, WELCOME_PER_CHANNEL_MIN, MINUTE)
            && self.take(&wc, WELCOME_PER_CONN_MIN, MINUTE)
            && self.take("wg", WELCOME_GLOBAL_MIN, MINUTE)
    }
    /// Answer a peer's channel announce from `peer` on `conn`?
    pub fn peer_reply_allowed(&self, conn: &str, peer: &str) -> bool {
        let k = format!("pa:{}\n{}", conn, lower(peer));
        let pc = format!("pac:{}", conn);
        if self.cooling(&format!("w:{}\n{}", conn, lower(peer)), PEER_REPLY_AFTER_WELCOME)
            || self.cooling(&k, PEER_REPLY_EVERY) || !self.would_take(&pc, PEER_REPLY_PER_CONN_MIN, MINUTE) || !self.would_take("pag", PEER_REPLY_GLOBAL_MIN, MINUTE) {
            return false;
        }
        self.cooldown(&k, PEER_REPLY_EVERY) && self.take(&pc, PEER_REPLY_PER_CONN_MIN, MINUTE) && self.take("pag", PEER_REPLY_GLOBAL_MIN, MINUTE)
    }
    /// `nick` left (PART / KICK / QUIT, live): its next join may be welcomed again (the
    /// per-channel / connection / process caps still bound join-part floods).
    pub fn forget_welcome(&self, conn: &str, nick: &str) {
        self.cooldowns.remove(&format!("w:{}\n{}", conn, lower(nick)));
    }
    /// We left `target` (PART / KICK): the next join there announces again.
    pub fn forget_target(&self, conn: &str, target: &str) {
        self.announced.remove(&format!("{}\n{}", conn, lower(target)));
    }
    /// A new IRC session (or our own nick / host changed): announce again from scratch.
    pub fn forget_conn(&self, conn: &str) {
        let pre = format!("{}\n", conn);
        self.announced.retain(|k, _| !k.starts_with(&pre));
        self.ctcp_pending.retain(|k, _| !k.starts_with(&pre));
        let w = format!("w:{}\n", conn);
        self.cooldowns.retain(|k, _| !k.starts_with(&w));
    }

    // ── cache ──

    pub fn status(&self, url: &str) -> Status {
        let Some(e) = self.entries.get(url) else { return Status::Missing };
        let now = Instant::now();
        if let Some(v) = &e.ready_v {
            let age = now.duration_since(e.at);
            if age < STALE_MAX {
                return Status::Ready { rid: e.rid.clone(), v: v.clone(), host: e.host.clone(), refresh: age >= OK_TTL && !e.fetching };
            }
        }
        if e.fetching && now.duration_since(e.fetch_started) < FETCH_STUCK {
            return Status::Pending;
        }
        if e.failed && now.duration_since(e.at) < FAIL_TTL {
            return Status::Failed;
        }
        Status::Missing
    }

    /// Tell `w` (when the fetch of `url` ends) — bounded per URL.
    fn add_waiter(&self, url: &str, w: Waiter) {
        let mut ws = self.waiters.entry(url.to_string()).or_default();
        if ws.len() < WAITERS_MAX && !ws.iter().any(|x| x.owner == w.owner && x.conn_id == w.conn_id && x.nick.eq_ignore_ascii_case(&w.nick)) {
            ws.push(w);
        }
    }

    fn notify(&self, owner: &str, conn_id: &str, nicks: Vec<String>) {
        if let Some(tx) = self.events.get(owner) {
            let _ = tx.send(crate::ServerEvent::AvatarHint { conn_id: conn_id.to_string(), nicks });
        }
    }

    /// Start fetching `url` for `viewer` (or join the fetch in flight). False when a limit
    /// says no (nothing is recorded, so a later view may try again).
    fn start_fetch(self: &Arc<Self>, url: &str, viewer: &str, w: Waiter) -> bool {
        if let Some(e) = self.entries.get(url) {
            if e.fetching && e.fetch_started.elapsed() < FETCH_STUCK {
                drop(e);
                self.add_waiter(url, w);
                return true;
            }
        }
        let host = reqwest::Url::parse(url).ok().and_then(|u| u.host_str().map(lower)).unwrap_or_default();
        let hk = format!("fh:{}", host);
        let vk = format!("fv:{}", viewer);
        if host.is_empty()
            || !self.would_take("fg", FETCH_GLOBAL_MIN, MINUTE)
            || !self.would_take(&hk, FETCH_HOST_10MIN, TEN_MINUTES)
            || !self.would_take(&vk, FETCH_VIEWER_10MIN, TEN_MINUTES)
        {
            return false;
        }
        if !(self.take("fg", FETCH_GLOBAL_MIN, MINUTE) && self.take(&hk, FETCH_HOST_10MIN, TEN_MINUTES) && self.take(&vk, FETCH_VIEWER_10MIN, TEN_MINUTES)) {
            return false;
        }
        tracing::debug!("avatars: fetching {} for {}", url, viewer);
        let now = Instant::now();
        let rid = self.rid(url);
        let (etag, prev_v) = {
            let mut e = self.entries.entry(url.to_string()).or_insert_with(|| Entry {
                rid: rid.clone(),
                host: host.clone(),
                ready_v: None,
                etag: None,
                fetching: false,
                failed: false,
                at: now,
                fetch_started: now,
            });
            e.fetching = true;
            e.fetch_started = now;
            (e.etag.clone(), e.ready_v.clone())
        };
        self.by_rid.insert(rid.clone(), url.to_string());
        self.add_waiter(url, w);
        self.evict();
        let this = self.clone();
        let url = url.to_string();
        tokio::spawn(async move {
            let res = tokio::time::timeout(this.fetch_timeout + Duration::from_secs(30), this.fetch(&url, etag.as_deref().filter(|_| prev_v.is_some()))).await;
            let outcome = match res {
                Ok(Ok(Fetched::NotModified)) => Ok(None),
                Ok(Ok(Fetched::Picture(p, etag))) => this.store_files(&rid, &p).await.map(|_| Some((p.version, etag))),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("timed out".to_string()),
            };
            let now = Instant::now();
            let mut drop_files = false;
            if let Some(mut e) = this.entries.get_mut(&url) {
                e.fetching = false;
                match outcome {
                    Ok(None) => {
                        e.at = now;
                        e.failed = false;
                    }
                    Ok(Some((v, etag))) => {
                        e.ready_v = Some(v);
                        e.etag = etag;
                        e.at = now;
                        e.failed = false;
                    }
                    Err(why) => {
                        tracing::debug!("avatars: remote fetch failed for {}: {}", e.host, why);
                        // A gone / refused picture is not shown any longer (opt-out, removal).
                        e.ready_v = None;
                        e.etag = None;
                        e.failed = true;
                        e.at = now;
                        drop_files = true;
                    }
                }
            }
            if drop_files {
                this.remove_files(&rid).await;
            }
            tracing::debug!("avatars: fetch of {} done (ok: {})", url, !drop_files);
            if let Some((_, ws)) = this.waiters.remove(&url) {
                for w in ws {
                    this.notify(&w.owner, &w.conn_id, vec![w.nick]);
                }
            }
        });
        true
    }

    /// Keep at most CACHE_MAX_ENTRIES (oldest, not being fetched, go first).
    fn evict(&self) {
        if self.entries.len() <= CACHE_MAX_ENTRIES {
            return;
        }
        let mut all: Vec<(String, String, Instant)> =
            self.entries.iter().filter(|e| !e.fetching).map(|e| (e.key().clone(), e.rid.clone(), e.at)).collect();
        all.sort_by_key(|x| x.2);
        let excess = self.entries.len().saturating_sub(CACHE_MAX_ENTRIES);
        for (url, rid, _) in all.into_iter().take(excess) {
            self.entries.remove(&url);
            self.by_rid.remove(&rid);
            let dir = self.dir.clone();
            tokio::spawn(async move {
                for s in [super::SIZE_LARGE, super::SIZE_SMALL] {
                    let _ = tokio::fs::remove_file(dir.join(format!("{}-{}.png", rid, s))).await;
                }
            });
        }
    }

    async fn store_files(&self, rid: &str, p: &Processed) -> Result<(), String> {
        for (bytes, size) in [(&p.large, super::SIZE_LARGE), (&p.small, super::SIZE_SMALL)] {
            crate::write_user_file_atomic(&self.dir.join(format!("{}-{}.png", rid, size)), bytes)
                .await
                .map_err(|_| "could not store".to_string())?;
        }
        Ok(())
    }
    async fn remove_files(&self, rid: &str) {
        for s in [super::SIZE_LARGE, super::SIZE_SMALL] {
            let _ = tokio::fs::remove_file(self.dir.join(format!("{}-{}.png", rid, s))).await;
        }
    }

    /// Resolve `host` (port) to addresses the fetch may use: public only (pinned); in the
    /// debug test mode loopback too.
    async fn addresses(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
        if !self.test_loopback {
            return crate::preview::resolve_and_validate_host(host, Some(port)).await.map_err(|e| e.to_string());
        }
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.map_err(|_| "DNS failed".to_string())?.collect();
        if addrs.is_empty() || addrs.iter().any(|a| crate::preview::is_private_ip(a.ip()) && !a.ip().is_loopback()) {
            return Err("private address".into());
        }
        Ok(addrs)
    }

    /// One fetch: no redirects, a capped body, a picture by its signature, decoded and
    /// re-encoded with the v1 pipeline (smaller dimension cap, own slot).
    async fn fetch(&self, url: &str, etag: Option<&str>) -> Result<Fetched, String> {
        let _slot = tokio::time::timeout(Duration::from_secs(20), self.fetch_slots.clone().acquire_owned())
            .await
            .map_err(|_| "busy".to_string())?
            .map_err(|_| "closed".to_string())?;
        let _permit = tokio::time::timeout(PERMIT_WAIT, self.outbound.clone().acquire_owned())
            .await
            .map_err(|_| "busy".to_string())?
            .map_err(|_| "closed".to_string())?;
        let mut u = reqwest::Url::parse(url).map_err(|_| "bad url".to_string())?;
        crate::preview::canonicalize_url_host(&mut u).map_err(|e| e.to_string())?;
        let host = u.host_str().ok_or("no host")?.to_string();
        let port = u.port_or_known_default().ok_or("no port")?;
        let addrs = self.addresses(&host, port).await?;
        let client = reqwest::Client::builder()
            .connect_timeout(FETCH_CONNECT_TIMEOUT)
            .timeout(self.fetch_timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("CryptIRC (avatar)")
            .no_proxy()
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| e.to_string())?;
        let mut req = client.get(u.as_str()).header(header::ACCEPT, "image/png, image/jpeg, image/webp");
        if let Some(t) = etag {
            req = req.header(header::IF_NONE_MATCH, t);
        }
        let resp = req.send().await.map_err(|e| format!("request: {}", e))?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED && etag.is_some() {
            return Ok(Fetched::NotModified);
        }
        if resp.status() != reqwest::StatusCode::OK {
            return Err(format!("status {}", resp.status().as_u16()));
        }
        if resp.content_length().map_or(false, |n| n > REMOTE_MAX_BYTES as u64) {
            return Err("too large".into());
        }
        let new_etag = resp
            .headers()
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .filter(|v| v.len() <= 128 && v.is_ascii())
            .map(str::to_string);
        let body = crate::preview::read_capped_body(resp, REMOTE_MAX_BYTES + 1).await.map_err(|e| e.to_string())?;
        if body.len() > REMOTE_MAX_BYTES {
            return Err("too large".into());
        }
        if super::sniff_format(&body).is_none() {
            return Err("not a PNG / JPEG / WebP picture".into());
        }
        let permit = tokio::time::timeout(Duration::from_secs(10), self.decode_slot.clone().acquire_owned())
            .await
            .map_err(|_| "busy".to_string())?
            .map_err(|_| "closed".to_string())?;
        let task = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            super::process_image_with(&body, REMOTE_MAX_DIMENSION, REMOTE_DECODE_ALLOC)
        });
        match tokio::time::timeout(Duration::from_secs(20), task).await {
            Ok(Ok(Ok(p))) => Ok(Fetched::Picture(p, new_etag)),
            Ok(Ok(Err(e))) => Err(e.message().to_string()),
            _ => Err("decode failed".into()),
        }
    }

    pub async fn read_picture(&self, rid: &str, v: &str, size: u32) -> Option<Vec<u8>> {
        let url = self.by_rid.get(rid).map(|u| u.clone())?;
        let ok = self.entries.get(&url).map_or(false, |e| e.rid == rid && e.ready_v.as_deref() == Some(v) && e.at.elapsed() < STALE_MAX);
        if !ok {
            return None;
        }
        let path = self.dir.join(format!("{}-{}.png", rid, size));
        let md = tokio::fs::symlink_metadata(&path).await.ok()?;
        if !md.is_file() || md.len() > super::STORED_IMAGE_MAX {
            return None;
        }
        tokio::fs::read(&path).await.ok()
    }

    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.entries.len()
    }
    /// Tests: `url` as if fetched (a small picture on disk, ready).
    #[cfg(test)]
    pub(crate) async fn test_ready(&self, url: &str) -> (String, String) {
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(40, 40, image::Rgb([1, 99, 200])));
        let mut c = std::io::Cursor::new(Vec::new());
        img.write_to(&mut c, image::ImageFormat::Png).unwrap();
        let p = super::process_image(&c.into_inner()).unwrap();
        let rid = self.rid(url);
        self.store_files(&rid, &p).await.unwrap();
        let now = Instant::now();
        self.entries.insert(url.to_string(), Entry { rid: rid.clone(), host: "remote.example".into(), ready_v: Some(p.version.clone()), etag: None, fetching: false, failed: false, at: now, fetch_started: now });
        self.by_rid.insert(rid.clone(), url.to_string());
        (rid, p.version)
    }
}

enum Fetched {
    Picture(Processed, Option<String>),
    NotModified,
}

// ─── Wiring (irc.rs, main.rs, routes) ─────────────────────────────────────────

/// The URL `owner` announces right now, if sharing is effective (avatar, visible, opted in,
/// avatars on, a public base URL) and the account is not disabled or being deleted.
pub fn share_url(state: &crate::AppState, owner: &str) -> Option<String> {
    if state.auth.is_being_deleted(owner) || state.auth.is_disabled_cached(owner) {
        return None;
    }
    state.avatars.public_url(owner)
}

/// The owner's account, read from disk: exists, not disabled, not being deleted. Checked
/// before every announce or answer (the in-memory disabled set is not loaded at startup).
pub async fn owner_active(auth: &crate::auth::AuthManager, owner: &str) -> bool {
    !auth.is_being_deleted(owner) && auth.account_exists(owner).await && !auth.get_user(owner).await.map_or(false, |u| u.disabled)
}

/// The URL `owner` announces right now, if sharing is effective and the account is active
/// (`share_url` + `owner_active`).
pub async fn announce_url(state: &crate::AppState, owner: &str) -> Option<String> {
    let url = share_url(state, owner)?;
    owner_active(&state.auth, owner).await.then_some(url)
}

/// Answer a CTCP AVATAR addressed to our user (live lines only; irc.rs). Nothing at all for
/// an owner who does not share; rate-limited per asker, connection and process.
pub async fn answer_ctcp(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, conn_id: &str, prefix: Option<&str>) {
    let Some((nick, userhost)) = prefix.and_then(|p| p.split_once('!')) else { return };
    if !super::plausible_nick(nick) {
        return;
    }
    let Some(url) = share_url(state, owner) else { return };
    if !state.avatar_remote.reply_allowed(conn_id, &lower(&format!("{}!{}", nick, userhost))) {
        return;
    }
    if !owner_active(&state.auth, owner).await {
        return;
    }
    let line = format!("NOTICE {} :\u{1}AVATAR {}\u{1}\r\n", cryptirc::ircproto::strip_crlf(nick), url);
    let _ = conn.lock().await.send_raw(&line).await;
}

/// Our user joined `channel` (live self-JOIN): an invisible `TAGMSG #chan` announce, when due.
pub async fn on_self_join(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, conn_id: &str, channel: &str) {
    let url = announce_url(state, owner).await;
    let mut c = conn.lock().await;
    c.avx.note_joined(channel);
    let Some(url) = url else { return };
    if channel.is_empty() || channel.contains([' ', '\r', '\n', ',']) || !(c.message_tags && c.avx.tags_allowed() && c.connected && c.registered) {
        return;
    }
    if !state.avatar_remote.announce_due(conn_id, channel, &url) {
        return;
    }
    if let Some(line) = with_tag(&format!("TAGMSG {}", channel), &url) {
        let _ = c.send_raw(&format!("{}\r\n", line)).await;
    }
}

/// Someone else joined `channel` (live): one private invisible `TAGMSG <joiner>` after a
/// short random delay — not in our own join burst, not to a nick of this instance (v1 covers
/// those), at most once per joiner per 30 min, and only a few per channel / connection /
/// process each minute (the extras of a mass join are dropped).
pub async fn on_other_join(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, conn_id: &str, channel: &str, joiner: &str) {
    if !super::plausible_nick(joiner) || channel.contains([' ', '\r', '\n']) {
        return;
    }
    let Some(url) = share_url(state, owner) else { return };
    let host = {
        let c = conn.lock().await;
        if !(c.message_tags && c.avx.tags_allowed() && c.connected && c.registered) || crate::irc::same_nick(joiner, &c.nick) || c.avx.recently_joined(channel, WELCOME_BURST) {
            return;
        }
        super::conn_host(&c)
    };
    if !state.avatar_remote.welcome_allowed(conn_id, channel, joiner) {
        return;
    }
    if held_here(state, &host, joiner).await {
        return;
    }
    let _ = url;
    let delay = {
        use rand::Rng;
        Duration::from_millis(rand::thread_rng().gen_range(0..WELCOME_DELAY_MS))
    };
    let (gen, joiner_uh) = {
        let c = conn.lock().await;
        (c.resync_gen, c.seen_userhosts.get(joiner).map(str::to_string))
    };
    let (state, owner, conn, channel, joiner) = (state.clone(), owner.to_string(), conn.clone(), channel.to_string(), joiner.to_string());
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        send_delayed(&state, &owner, &conn, gen, &joiner, joiner_uh.as_deref(), Some(&channel)).await;
    });
}

/// A delayed private announce (welcome, answer to a peer): everything is checked again at
/// send time (codex astra L remote.rs:1123) — the owner still shares and is active (opt-out,
/// admin switch, disable), tags are still allowed (message-tags, CLIENTTAGDENY), the same IRC
/// session (no reconnect meanwhile), and the recipient is still the same user (in the channel
/// / seen, with the user@host it had).
async fn send_delayed(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, gen: u64, to: &str, to_userhost: Option<&str>, channel: Option<&str>) {
    let Some(url) = announce_url(state, owner).await else { return };
    let mut c = conn.lock().await;
    if !delayed_send_ok(&c, gen, to, to_userhost, channel) {
        return;
    }
    if let Some(line) = with_tag(&format!("TAGMSG {}", to), &url) {
        let _ = c.send_raw(&format!("{}\r\n", line)).await;
    }
}

/// A CryptIRC peer announced itself to a channel we are in (live): it may not know us yet
/// (it joined, changed nick, or we were out of sight) — one private invisible TAGMSG back,
/// after a short delay; once per peer per 10 min, capped. Only peers that announce (CryptIRC
/// users who share) ever get one.
pub async fn on_peer_announce(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, conn_id: &str, peer: &str) {
    if !super::plausible_nick(peer) {
        return;
    }
    let Some(url) = share_url(state, owner) else { return };
    {
        let c = conn.lock().await;
        if !(c.message_tags && c.avx.tags_allowed() && c.connected && c.registered) || crate::irc::same_nick(peer, &c.nick) {
            return;
        }
    }
    if !state.avatar_remote.peer_reply_allowed(conn_id, peer) {
        tracing::debug!("avatars: no answer to {}'s announce on {} (limits)", peer, conn_id);
        return;
    }
    tracing::debug!("avatars: answering {}'s announce on {}", peer, conn_id);
    let _ = url;
    let delay = {
        use rand::Rng;
        Duration::from_millis(rand::thread_rng().gen_range(0..PEER_REPLY_DELAY_MS))
    };
    let (gen, peer_uh) = {
        let c = conn.lock().await;
        (c.resync_gen, c.seen_userhosts.get(peer).map(str::to_string))
    };
    let (state, owner, conn, peer) = (state.clone(), owner.to_string(), conn.clone(), peer.to_string());
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        send_delayed(&state, &owner, &conn, gen, &peer, peer_uh.as_deref(), None).await;
    });
}

/// Our own nick or host changed (live): other servers dropped our announce, so the channels
/// we are in hear it again now (invisible TAGMSGs, at most REANNOUNCE_MAX_CHANNELS).
pub async fn reannounce(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>, conn_id: &str) {
    let Some(url) = announce_url(state, owner).await else { return };
    let mut c = conn.lock().await;
    if !(c.message_tags && c.avx.tags_allowed() && c.connected && c.registered) {
        return;
    }
    let chans: Vec<String> = c.channels.values().map(|ch| ch.name.clone()).filter(|n| !n.is_empty() && !n.contains([' ', '\r', '\n', ','])).take(REANNOUNCE_MAX_CHANNELS).collect();
    for ch in chans {
        if !state.avatar_remote.announce_due(conn_id, &ch, &url) {
            continue;
        }
        if let Some(line) = with_tag(&format!("TAGMSG {}", ch), &url) {
            let _ = c.send_raw(&format!("{}\r\n", line)).await;
        }
    }
}

/// The connection-side checks of `send_delayed`: same session (`gen`), tags still allowed,
/// the recipient still there (in `channel`, or seen) with the user@host it had.
pub fn delayed_send_ok(c: &IrcConnection, gen: u64, to: &str, to_userhost: Option<&str>, channel: Option<&str>) -> bool {
    if !(c.connected && c.registered && c.message_tags && c.avx.tags_allowed()) || c.resync_gen != gen {
        return false;
    }
    let present = match channel {
        Some(ch) => {
            let key = c.casemapping.fold(ch);
            c.channels.get(&key).map_or(false, |chan| chan.names.iter().any(|n| strip_pfx(n).eq_ignore_ascii_case(to)))
        }
        None => sees(c, to),
    };
    present && c.seen_userhosts.get(to) == to_userhost
}

/// Answer a CTCP AVATAR request? Never on a restricted connection (a bouncer's playback of an
/// old request looks live — codex astra re-check L irc.rs:1487); otherwise only a direct
/// one, not from ourselves, on a live line that is not playback (`fresh`: announce_is_fresh).
pub fn may_answer_ctcp(replayed: bool, fresh: bool, direct: bool, from_self: bool, restricted: bool) -> bool {
    !restricted && !replayed && fresh && direct && !from_self
}

/// After an Attach that dropped unproven state: re-establish draft/metadata-2 when this
/// connection had it (or its session record says so), it is live and the network config
/// does not disable it — so publication and opt-out deletion keep working (codex astra
/// re-check L avatar.rs:425). The CAP REQ is answered with ACK (→ SUB / SET / SYNC again)
/// or NAK (the new session does not offer it).
pub fn meta_recheck(had_meta: bool, dropped: bool, live: bool, disabled_by_config: bool) -> bool {
    had_meta && dropped && live && !disabled_by_config
}

/// Is `nick` held on `host` by a live connection of this instance?
async fn held_here(state: &crate::AppState, host: &str, nick: &str) -> bool {
    let conns: Vec<Arc<Mutex<IrcConnection>>> = state.connections.iter().map(|e| e.value().clone()).collect();
    for conn in conns {
        let c = conn.lock().await;
        if c.connected && c.registered && c.nick.eq_ignore_ascii_case(nick) && super::conn_host(&c) == host {
            return true;
        }
    }
    false
}

/// The connection negotiated draft/metadata-2 (live ACK): subscribe to the key and publish
/// (or clear) our own value.
pub async fn on_meta2_ack(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>) {
    let url = announce_url(state, owner).await;
    let mut c = conn.lock().await;
    c.avx.meta2_on = true;
    let _ = c.send_raw(&format!("METADATA * SUB {}\r\n", META_KEY)).await;
    // Idempotent sync of the current state (codex astra re-check 2): our URL if sharing, an
    // explicit deletion otherwise — a withdrawal that could not reach IRC is applied now.
    let _ = c.send_raw(&meta_sync_line(url.as_deref())).await;
    // Channels joined before the subscription: ask for their members' values now (a JOIN
    // after it is synced by the server by itself).
    let chans: Vec<String> = c.channels.values().map(|ch| ch.name.clone()).filter(|n| !n.is_empty() && !n.contains([' ', '\r', '\n', ','])).take(REANNOUNCE_MAX_CHANNELS).collect();
    for ch in chans {
        let _ = c.send_raw(&format!("METADATA {} SYNC\r\n", ch)).await;
    }
}

/// The line that makes the server's `avatar` value for us match `url` (None: delete it).
pub fn meta_sync_line(url: Option<&str>) -> String {
    match url {
        Some(u) => format!("METADATA * SET {} :{}\r\n", META_KEY, u),
        None => format!("METADATA * SET {}\r\n", META_KEY),
    }
}

/// Metadata-2 became active again without an ACK (state restored after a web restart): sync
/// our value the same way (`meta_sync_line`).
pub async fn meta_sync(state: &crate::AppState, owner: &str, conn: &Arc<Mutex<IrcConnection>>) {
    let url = announce_url(state, owner).await;
    let mut c = conn.lock().await;
    if c.avx.meta2_on && c.connected && c.registered {
        let _ = c.send_raw(&meta_sync_line(url.as_deref())).await;
    }
}

/// `owner`'s sharing changed: publish or clear the metadata value on each of their live
/// connections that negotiated draft/metadata-2. (Announces by tag follow the new URL by
/// themselves; an opted-out owner sends none.)
pub async fn republish(state_auth: &crate::auth::AuthManager, store: &AvatarStore, connections: &DashMap<String, Arc<Mutex<IrcConnection>>>, conn_owners: &DashMap<String, String>, owner: &str) {
    let url = if state_auth.is_disabled_cached(owner) || !owner_active(state_auth, owner).await { None } else { store.public_url(owner) };
    let ids: Vec<String> = conn_owners.iter().filter(|e| e.value() == owner).map(|e| e.key().clone()).collect();
    for id in ids {
        let Some(conn) = connections.get(&id).map(|c| c.clone()) else { continue };
        let mut c = conn.lock().await;
        if !(c.avx.meta2_on && c.connected && c.registered) {
            continue;
        }
        let _ = c.send_raw(&meta_sync_line(url.as_deref())).await;
    }
}

/// Every owner with a connection (the admin switch changed).
pub async fn republish_all(auth: &crate::auth::AuthManager, store: &AvatarStore, connections: &DashMap<String, Arc<Mutex<IrcConnection>>>, conn_owners: &DashMap<String, String>) {
    let owners: HashSet<String> = conn_owners.iter().map(|e| e.value().clone()).collect();
    for o in owners {
        republish(auth, store, connections, conn_owners, &o).await;
    }
}

/// Lookup results from other servers' announces (see `resolve`).
#[derive(Default, Debug)]
pub struct Resolved {
    /// spelling → (rid, version, host of the announced URL)
    pub found: HashMap<String, (String, String, String)>,
    pub pending: Vec<String>,
}

/// The remote part of a lookup (POST /api/avatar/lookup), for nicks v1 did not vouch for
/// (`local`, ASCII-lowercased): the viewer's connection is live on the current link, the nick
/// is one it sees (channel member or fresh WHOIS) and not its own, and its current holder
/// announced a URL on this connection whose sender user@host still matches what the
/// connection shows for the nick. Ready pictures are returned; missing ones are fetched (for
/// this viewer, within the limits) and reported pending; the app is told when they arrive
/// (`avatar_hint`). `probe`: nicks the user explicitly opened (nick menu / WHOIS) — for one
/// with nothing known, one query (METADATA GET where negotiated, else CTCP AVATAR).
pub async fn resolve(state: &AvatarRouteState, viewer: &str, viewer_conn: &str, nicks: &[String], probe: &[String], local: &HashSet<String>) -> Resolved {
    let mut out = Resolved::default();
    let link = (state.link)();
    if !state.store.enabled() || link == 0 || nicks.is_empty() {
        return out;
    }
    let Some(vconn) = state.connections.get(viewer_conn).map(|c| c.clone()) else { return out };
    let probe_set: HashSet<String> = probe.iter().take(super::LOOKUP_MAX_NICKS).map(|n| lower(strip_pfx(n.trim()))).collect();
    let mut with_url: Vec<(String, String)> = Vec::new();
    let mut to_probe: Vec<String> = Vec::new();
    let meta2;
    {
        let mut c = vconn.lock().await;
        if !(c.connected && c.registered) || c.synced_link != link {
            return out;
        }
        // A connection through a bouncer (or not classified) gets no remote avatars at all —
        // nothing is learned there, and nothing is asked.
        if restricted(&c) {
            return out;
        }
        meta2 = c.avx.meta2_on;
        let own = lower(&c.nick);
        let visible = visible_nicks(&c);
        let mut stale = Vec::new();
        let mut done = HashSet::new();
        for n in nicks.iter().take(super::LOOKUP_MAX_NICKS) {
            let n = strip_pfx(n.trim());
            if !super::plausible_nick(n) {
                continue;
            }
            let k = lower(n);
            if k == own || local.contains(&k) || !visible.contains(&k) || !done.insert(k.clone()) {
                continue;
            }
            match c.avx.binding(&k) {
                Some(b) => {
                    // Only with a known user@host that the connection still shows for the nick
                    // (codex astra re-check 2 M remote.rs:583).
                    let moved = b.userhost.is_empty() || c.seen_userhosts.get(&k).map_or(true, |o| !super::same_userhost(o, &b.userhost));
                    if moved {
                        stale.push(k);
                    } else {
                        with_url.push((n.to_string(), b.url.clone()));
                    }
                }
                None => {
                    if probe_set.contains(&k) && to_probe.len() < PROBES_PER_LOOKUP {
                        to_probe.push(n.to_string());
                    }
                }
            }
        }
        for k in stale {
            c.avx.forget(&k);
        }
    }
    for (n, url) in with_url {
        let w = Waiter { owner: viewer.to_string(), conn_id: viewer_conn.to_string(), nick: n.clone() };
        match state.remote.status(&url) {
            Status::Ready { rid, v, host, refresh } => {
                if refresh {
                    state.remote.start_fetch(&url, viewer, w);
                }
                out.found.insert(n, (rid, v, host));
            }
            Status::Pending => {
                state.remote.add_waiter(&url, w);
                out.pending.push(n);
            }
            Status::Failed => {}
            Status::Missing => {
                if state.remote.start_fetch(&url, viewer, w) {
                    out.pending.push(n);
                }
            }
        }
    }
    for n in to_probe {
        if !state.remote.probe_allowed(viewer, viewer_conn, &n) {
            continue;
        }
        let mut c = vconn.lock().await;
        let asked = c.seen_userhosts.get(&n).map(str::to_string);
        let line = if meta2 {
            let _ = asked;
            format!("METADATA {} GET {}\r\n", n, META_KEY)
        } else {
            state.remote.note_ctcp_sent(viewer_conn, &n, asked);
            format!("PRIVMSG {} :\u{1}AVATAR\u{1}\r\n", n)
        };
        let sent = c.send_raw(&line).await.is_ok();
        drop(c);
        if sent {
            out.pending.push(n);
        }
    }
    out
}

/// GET /avatar/remote/<rid>?v=<version>[&s=48] — a picture fetched from another server, for
/// sessions of this instance (Authorization header), `private, no-store`, same-origin.
pub async fn route_remote_image(
    State(state): State<AvatarRouteState>,
    UrlPath(rid): UrlPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(_user) = super::api_user(&state, &headers) else { return super::unauthorized() };
    if !state.store.enabled() || !super::is_lower_hex(&rid, 32) {
        return super::not_found();
    }
    let Some(v) = params.get("v").filter(|v| super::valid_version(v)) else { return super::not_found() };
    let size = match params.get("s").map(String::as_str) {
        None | Some("128") => super::SIZE_LARGE,
        Some("48") => super::SIZE_SMALL,
        Some(_) => return super::not_found(),
    };
    let etag = format!("\"r{}-{}\"", v, size);
    let revalidated = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        .map_or(false, |h| h.split(',').any(|t| t.trim() == etag));
    let Some(bytes) = state.remote.read_picture(&rid, v, size).await else { return super::not_found() };
    let mut r = if revalidated {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let mut r = Response::new(Body::from(bytes));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        r
    };
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(super::PRIVATE_NO_STORE));
    h.insert(header::HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    h.insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    r.into_response()
}

#[cfg(test)]
mod tests;
