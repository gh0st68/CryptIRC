//! bots.rs — server-side channel bots (Weather via wttr.in, Urban Dictionary)
//! that run in the WEB process 24/7, independent of the vault or any open browser,
//! and reply through the owner's existing IRC connection (as the owner's own nick).
//!
//! Config is stored server-readable at {data}/bots/{user}.json — like network
//! configs, NOT the vault-encrypted prefs — so the bots keep working while the
//! vault is locked. wttr.in and urbandictionary are free keyless APIs, so there
//! are no secrets on disk. Enforcement bots (auto-op/flood/filters) come later.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::OnceLock;
use dashmap::DashMap;
use tokio::sync::Mutex;
use crate::{AppState, ServerEvent};
use crate::irc::IrcConnection;

/// Who may use a bot's public channel trigger.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    /// Anyone in the channel.
    Public,
    /// Only nicks/host-masks on the allow lists.
    List,
    /// No public trigger at all — the owner still has the private /command.
    Private,
}
impl Default for Access { fn default() -> Self { Access::Public } }

/// One bot's settings.
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct BotDef {
    #[serde(default)]
    pub enabled: bool,
    /// Public channel trigger, e.g. "!w". Falls back to a per-bot default if blank.
    #[serde(default)]
    pub trigger: String,
    #[serde(default)]
    pub access: Access,
    /// For access = List: exact nicks (case-insensitive).
    #[serde(default)]
    pub allow_nicks: Vec<String>,
    /// For access = List: wildcard masks matched against nick!user@host.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// Channels the trigger is active in. Empty = every channel the owner is in.
    #[serde(default)]
    pub channels: Vec<String>,
}

impl BotDef {
    fn trigger_or(&self, default: &str) -> String {
        let t = self.trigger.trim();
        if t.is_empty() { default.to_string() } else { t.to_string() }
    }
}

/// A user's full bot configuration (one file per user).
#[derive(Clone, Serialize, Deserialize, Default)]
pub struct BotConfig {
    /// Master switch — off = none of this user's bots run.
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub weather: BotDef,
    #[serde(default)]
    pub ud: BotDef,
}

// ── Storage (server-readable, like network configs) ──────────────────────────

fn bots_dir(data_dir: &str) -> std::path::PathBuf {
    std::path::PathBuf::from(data_dir).join("bots")
}

/// Load every user's bot config into an in-memory map at startup. Read on every
/// relevant channel message, so it must be in memory (not a per-message file read).
pub async fn load_all(data_dir: &str) -> DashMap<String, BotConfig> {
    let map = DashMap::new();
    if let Ok(mut rd) = tokio::fs::read_dir(bots_dir(data_dir)).await {
        while let Ok(Some(e)) = rd.next_entry().await {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("json") { continue; }
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else { continue };
            if let Ok(body) = tokio::fs::read_to_string(&path).await {
                if let Ok(cfg) = serde_json::from_str::<BotConfig>(&body) {
                    map.insert(stem.to_string(), cfg);
                }
            }
        }
    }
    map
}

/// Persist one user's config (atomic write-then-rename). safe_username prevents
/// path traversal via the filename.
pub async fn save(data_dir: &str, username: &str, cfg: &BotConfig) -> anyhow::Result<()> {
    let dir = bots_dir(data_dir);
    tokio::fs::create_dir_all(&dir).await?;
    let safe = crate::safe_username(username);
    let path = dir.join(format!("{}.json", safe));
    let tmp = dir.join(format!("{}.json.tmp", safe));
    let body = serde_json::to_string_pretty(cfg)?;
    tokio::fs::write(&tmp, body.as_bytes()).await?;
    tokio::fs::rename(&tmp, &path).await?;
    Ok(())
}

// ── Access control ───────────────────────────────────────────────────────────

/// Case-insensitive glob supporting `*` (any run) and `?` (one char) — enough for
/// IRC host masks like `*!*@*.trusted.host`.
pub fn wildmatch(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let t: Vec<char> = text.to_lowercase().chars().collect();
    // Classic two-pointer glob with backtracking on '*'.
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star, mut mark) = (usize::MAX, 0usize);
    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1; ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = pi; mark = ti; pi += 1;
        } else if star != usize::MAX {
            pi = star + 1; mark += 1; ti = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' { pi += 1; }
    pi == p.len()
}

/// Is `from_nick` (full mask `nick!user@host`) allowed to use this bot's trigger?
fn access_ok(def: &BotDef, from_nick: &str, full_mask: &str) -> bool {
    match def.access {
        Access::Public => true,
        Access::Private => false,
        Access::List => {
            def.allow_nicks.iter().any(|n| n.trim().eq_ignore_ascii_case(from_nick))
                || def.allow_hosts.iter().any(|h| { let h = h.trim(); !h.is_empty() && wildmatch(h, full_mask) })
        }
    }
}

// ── Per-(user,bot) cooldown so a busy channel can't make us Excess-Flood ─────

fn cooldowns() -> &'static DashMap<String, i64> {
    static C: OnceLock<DashMap<String, i64>> = OnceLock::new();
    C.get_or_init(DashMap::new)
}
const COOLDOWN_SECS: i64 = 3;
/// Atomic check-and-set: this cooldown is the ONLY outbound-flood defense (the
/// irc-core daemon does no outbound rate limiting), so a non-atomic get-then-insert
/// could let two concurrent trigger messages both fire within the window. The
/// DashMap `entry` API holds the shard lock across the compare-and-update.
fn cooldown_ok(username: &str, bot: &str) -> bool {
    use dashmap::mapref::entry::Entry;
    let key = format!("{}:{}", username, bot);
    let now = chrono::Utc::now().timestamp();
    match cooldowns().entry(key) {
        Entry::Occupied(mut e) => {
            if now - *e.get() < COOLDOWN_SECS { false }
            else { *e.get_mut() = now; true }
        }
        Entry::Vacant(e) => { e.insert(now); true }
    }
}

// ── External fetchers (keyless public APIs) ──────────────────────────────────

fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("curl/8.0 (CryptIRC bot)")   // wttr.in returns its plain-text one-liner to curl-like UAs
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Percent-encode a path segment (keep unreserved chars; everything else → %XX).
fn enc_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// One-line weather for `loc` (zip or "city, ST") via wttr.in's plain-text format.
async fn fetch_weather(loc: &str) -> String {
    let url = format!(
        "https://wttr.in/{}?format=%l:+%c+%t+(feels+%f)+%h+humidity,+wind+%w",
        enc_segment(loc)
    );
    match http().get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let line = body.lines().next().unwrap_or("").trim().to_string();
            if line.is_empty() || line.to_lowercase().contains("unknown location") || line.contains("Sorry") {
                format!("weather: couldn't find \"{}\"", loc)
            } else {
                // Guard against wttr.in occasionally echoing a giant error page.
                truncate_line(&line, 300)
            }
        }
        Err(_) => "weather: service unavailable, try again".to_string(),
    }
}

/// Top Urban Dictionary definition for `term`, cleaned + truncated for one IRC line.
async fn fetch_ud(term: &str) -> String {
    let url = "https://api.urbandictionary.com/v0/define";
    // reqwest is built without the "json" feature here, so parse the text body.
    match http().get(url).query(&[("term", term)]).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(json) => {
                    let def = json.get("list").and_then(|l| l.get(0));
                    match def.and_then(|d| d.get("definition")).and_then(|d| d.as_str()) {
                        Some(text) => {
                            // UD wraps cross-referenced words in [brackets]; strip the brackets,
                            // collapse newlines/whitespace, and truncate for IRC.
                            let cleaned: String = text.replace(['[', ']'], "");
                            let flat = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
                            format!("{}: {}", term, truncate_line(&flat, 350))
                        }
                        None => format!("ud: no definition for \"{}\"", term),
                    }
                }
                Err(_) => "ud: bad response, try again".to_string(),
            }
        }
        Err(_) => "ud: service unavailable, try again".to_string(),
    }
}

/// Truncate on a char boundary, appending … if cut. Strips CR/LF/NUL FIRST (via
/// the canonical strip_crlf every other outbound sender uses) so a reply can never
/// smuggle extra IRC lines, and so the bot path can't drift from the rest of the code.
fn truncate_line(s: &str, max: usize) -> String {
    let clean = cryptirc::ircproto::strip_crlf(s);
    if clean.chars().count() <= max { return clean; }
    let mut out: String = clean.chars().take(max).collect();
    out.push('…');
    out
}

/// Run `bot` with `query` and return the reply text (used by both the public
/// trigger path and the owner's private /command path).
pub async fn run_bot(bot: &str, query: &str) -> String {
    match bot {
        "weather" => fetch_weather(query).await,
        "ud" => fetch_ud(query).await,
        _ => "unknown bot".to_string(),
    }
}

// ── Public trigger dispatch (called from irc.rs on every channel PRIVMSG) ────

/// If this channel message matches an enabled bot trigger the sender is allowed
/// to use, spawn the fetch and reply to the channel. Non-blocking: never holds a
/// lock across the network fetch. Owners never reach here for their OWN messages
/// (the server either echoes-and-skips them or never echoes them), which is why
/// the private /command exists for the owner.
pub fn maybe_trigger(
    state: &AppState,
    username: &str,
    conn: &Arc<Mutex<IrcConnection>>,
    channel: &str,
    from_nick: &str,
    full_mask: &str,
    text: &str,
) {
    let Some(cfg) = state.bots.get(username).map(|c| c.clone()) else { return };
    if !cfg.enabled { return; }

    for (bot, def, default_trig) in [
        ("weather", &cfg.weather, "!w"),
        ("ud", &cfg.ud, "!ud"),
    ] {
        if !def.enabled { continue; }
        let trig = def.trigger_or(default_trig);
        // Require a word boundary: "!w" alone or "!w <arg>", not "!working".
        let arg = if text == trig {
            ""
        } else if let Some(rest) = text.strip_prefix(&trig) {
            if rest.starts_with(' ') { rest.trim() } else { continue; }
        } else {
            continue;
        };
        // Channel scope (empty = all channels).
        if !def.channels.is_empty()
            && !def.channels.iter().any(|c| c.trim().eq_ignore_ascii_case(channel)) {
            continue;
        }
        if !access_ok(def, from_nick, full_mask) { continue; }
        if arg.is_empty() { continue; }               // no query → stay silent
        if !cooldown_ok(username, bot) { continue; }  // anti-flood self-guard

        let conn = conn.clone();
        let (bot, query, channel) = (bot.to_string(), arg.to_string(), channel.to_string());
        tokio::spawn(async move {
            let reply = run_bot(&bot, &query).await;
            let line = format!("PRIVMSG {} :{}\r\n", channel, reply);
            let _ = conn.lock().await.send_raw(&line).await;
        });
        // One message fires at most one bot — if the owner misconfigured two bots
        // with the same trigger, don't double-reply (and double the flood surface).
        break;
    }
}

/// Owner's private /command (e.g. /w, /ud): fetch and hand the text back to the
/// owner's UI only (never posted to a channel). Available regardless of the
/// bots' enabled state — it's the owner's personal lookup.
pub fn run_private_query(state: &AppState, username: &str, bot: &str, query: &str) {
    let state = state.clone();
    let (username, bot, query) = (username.to_string(), bot.to_string(), query.to_string());
    tokio::spawn(async move {
        let text = run_bot(&bot, &query).await;
        state.send_to_user(&username, ServerEvent::BotResult { bot, text });
    });
}
