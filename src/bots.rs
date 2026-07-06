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
use rand::Rng;
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
    #[serde(default)]
    pub wiki: BotDef,
    #[serde(default)]
    pub define: BotDef,
    #[serde(default)]
    pub crypto: BotDef,
    #[serde(default)]
    pub time: BotDef,
    #[serde(default)]
    pub cc: BotDef,
    #[serde(default)]
    pub joke: BotDef,
    #[serde(default)]
    pub quote: BotDef,
    #[serde(default)]
    pub fact: BotDef,
    #[serde(default)]
    pub eightball: BotDef,
    #[serde(default)]
    pub roll: BotDef,
    #[serde(default)]
    pub coin: BotDef,
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
/// Rich single line: condition, temp+feels, humidity, wind, precip, pressure, UV,
/// and sunrise-sunset. Pipe separators are %7C-encoded so reqwest's stricter URL
/// parser accepts them (wttr.in decodes them back to '|').
async fn fetch_weather(loc: &str) -> String {
    let url = format!(
        "https://wttr.in/{}?format=%l:+%C+%c+%t+(feels+%f)+%7C+humidity+%h+%7C+wind+%w+%7C+precip+%p+%7C+pressure+%P+%7C+UV+%u+%7C+sun+%S-%s",
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

/// One-line Wikipedia summary for `topic` via the keyless REST summary API.
async fn fetch_wiki(topic: &str) -> String {
    let title = topic.trim().replace(' ', "_");
    let url = format!("https://en.wikipedia.org/api/rest_v1/page/summary/{}", enc_segment(&title));
    // Wikipedia asks for a descriptive User-Agent — override the client's curl UA.
    match http().get(&url)
        .header("User-Agent", "CryptIRC-bot/1.0 (+https://github.com/gh0st68/CryptIRC)")
        .send().await
    {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => {
                    let extract = j.get("extract").and_then(|x| x.as_str()).unwrap_or("");
                    if extract.is_empty() {
                        return format!("wiki: nothing found for \"{}\"", topic.trim());
                    }
                    let title = j.get("title").and_then(|t| t.as_str()).unwrap_or(topic.trim());
                    let page = j.get("content_urls").and_then(|c| c.get("desktop"))
                        .and_then(|d| d.get("page")).and_then(|p| p.as_str()).unwrap_or("");
                    let line = if page.is_empty() {
                        format!("{}: {}", title, extract)
                    } else {
                        format!("{}: {} — {}", title, extract, page)
                    };
                    truncate_line(&line, 400)
                }
                Err(_) => "wiki: bad response, try again".to_string(),
            }
        }
        Err(_) => "wiki: service unavailable, try again".to_string(),
    }
}

/// One-line dictionary definition via the keyless dictionaryapi.dev.
async fn fetch_define(word: &str) -> String {
    let w = word.trim();
    let url = format!("https://api.dictionaryapi.dev/api/v2/entries/en/{}", enc_segment(w));
    match http().get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                // Success is a JSON array; a 404 is an object → j.get(0) is None → "no definition".
                Ok(j) => {
                    let entry = j.get(0);
                    let phon = entry.and_then(|e| e.get("phonetic")).and_then(|p| p.as_str()).unwrap_or("");
                    let meaning = entry.and_then(|e| e.get("meanings")).and_then(|m| m.get(0));
                    let pos = meaning.and_then(|m| m.get("partOfSpeech")).and_then(|p| p.as_str()).unwrap_or("");
                    let def = meaning.and_then(|m| m.get("definitions")).and_then(|d| d.get(0))
                        .and_then(|d| d.get("definition")).and_then(|d| d.as_str());
                    match def {
                        Some(d) => {
                            let head = if phon.is_empty() { w.to_string() } else { format!("{} {}", w, phon) };
                            let pos = if pos.is_empty() { String::new() } else { format!(" ({})", pos) };
                            truncate_line(&format!("{}{}: {}", head, pos, d), 350)
                        }
                        None => format!("define: no definition found for \"{}\"", w),
                    }
                }
                Err(_) => "define: bad response, try again".to_string(),
            }
        }
        Err(_) => "define: service unavailable, try again".to_string(),
    }
}

/// Map a common ticker to its CoinGecko id; otherwise use the input verbatim
/// (lowercased) so a full id like "solana" also works.
fn crypto_id(sym: &str) -> String {
    let s = sym.trim().to_lowercase();
    match s.as_str() {
        "btc" | "xbt" => "bitcoin",
        "eth"         => "ethereum",
        "doge"        => "dogecoin",
        "sol"         => "solana",
        "xrp"         => "ripple",
        "ada"         => "cardano",
        "bnb"         => "binancecoin",
        "ltc"         => "litecoin",
        "dot"         => "polkadot",
        "matic"       => "matic-network",
        "usdt"        => "tether",
        "usdc"        => "usd-coin",
        "trx"         => "tron",
        "avax"        => "avalanche-2",
        "link"        => "chainlink",
        "bch"         => "bitcoin-cash",
        "xmr"         => "monero",
        "shib"        => "shiba-inu",
        _             => return s,
    }.to_string()
}

fn fmt_price(p: f64) -> String {
    if p >= 1.0 { format!("{:.2}", p) } else { format!("{:.6}", p) }
}

/// Spot USD price + 24h change for a coin via the keyless CoinGecko simple API.
async fn fetch_crypto(sym: &str) -> String {
    let id = crypto_id(sym);
    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies=usd&include_24hr_change=true",
        enc_segment(&id)
    );
    match http().get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => {
                    if let Some(obj) = j.get(&id).and_then(|o| o.as_object()) {
                        let usd = obj.get("usd").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let chg = obj.get("usd_24h_change").and_then(|v| v.as_f64()).unwrap_or(0.0);
                        let arrow = if chg >= 0.0 { "▲" } else { "▼" };
                        format!("{}: ${} ({}{:.2}% 24h)", id, fmt_price(usd), arrow, chg)
                    } else {
                        format!("crypto: unknown coin \"{}\" — try a ticker (btc, eth) or id (bitcoin, solana)", sym.trim())
                    }
                }
                Err(_) => "crypto: bad response, try again".to_string(),
            }
        }
        Err(_) => "crypto: service unavailable, try again".to_string(),
    }
}

/// Local time + timezone for a place via wttr.in.
async fn fetch_time(place: &str) -> String {
    let url = format!("https://wttr.in/{}?format=%l:+%T+%Z", enc_segment(place));
    match http().get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            let line = body.lines().next().unwrap_or("").trim().to_string();
            if line.is_empty() || line.to_lowercase().contains("unknown location") {
                format!("time: couldn't find \"{}\"", place.trim())
            } else {
                truncate_line(&line, 200)
            }
        }
        Err(_) => "time: service unavailable, try again".to_string(),
    }
}

/// Currency conversion: "<amount> <from> <to>" via the keyless open.er-api.com.
async fn fetch_cc(query: &str) -> String {
    let parts: Vec<&str> = query.split_whitespace().collect();
    if parts.len() != 3 {
        return "cc: usage — <amount> <from> <to>, e.g. 100 usd eur".to_string();
    }
    let amt: f64 = match parts[0].parse() {
        Ok(a) if (a as f64).is_finite() => a,   // reject NaN/inf (which parse accepts)
        _ => return "cc: amount must be a number, e.g. 100 usd eur".to_string(),
    };
    let from = parts[1].to_uppercase();
    let to = parts[2].to_uppercase();
    let code_ok = |c: &str| c.len() == 3 && c.chars().all(|ch| ch.is_ascii_alphabetic());
    if !code_ok(&from) || !code_ok(&to) {
        return "cc: use 3-letter currency codes, e.g. 100 usd eur".to_string();
    }
    let url = format!("https://open.er-api.com/v6/latest/{}", enc_segment(&from));
    match http().get(&url).send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => {
                    if j.get("result").and_then(|x| x.as_str()) != Some("success") {
                        return format!("cc: unknown currency \"{}\"", from);
                    }
                    match j.get("rates").and_then(|r| r.get(&to)).and_then(|v| v.as_f64()) {
                        Some(rate) => format!("{} {} = {:.2} {} (1 {} = {:.4} {})", amt, from, amt * rate, to, from, rate, to),
                        None => format!("cc: unknown currency \"{}\"", to),
                    }
                }
                Err(_) => "cc: bad response, try again".to_string(),
            }
        }
        Err(_) => "cc: service unavailable, try again".to_string(),
    }
}

/// Random dad joke via the keyless icanhazdadjoke API (JSON via Accept header).
async fn fetch_joke() -> String {
    match http().get("https://icanhazdadjoke.com/")
        .header("Accept", "application/json")
        .header("User-Agent", "CryptIRC-bot/1.0 (+https://github.com/gh0st68/CryptIRC)")
        .send().await
    {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => match j.get("joke").and_then(|x| x.as_str()) {
                    Some(joke) if !joke.is_empty() => truncate_line(joke, 350),
                    _ => "joke: bad response, try again".to_string(),
                },
                Err(_) => "joke: bad response, try again".to_string(),
            }
        }
        Err(_) => "joke: service unavailable, try again".to_string(),
    }
}

/// Random inspirational quote via the keyless zenquotes.io API.
async fn fetch_quote() -> String {
    match http().get("https://zenquotes.io/api/random").send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => {
                    let item = j.get(0);
                    let q = item.and_then(|i| i.get("q")).and_then(|x| x.as_str()).unwrap_or("");
                    let a = item.and_then(|i| i.get("a")).and_then(|x| x.as_str()).unwrap_or("");
                    if q.is_empty() {
                        "quote: unavailable, try again".to_string()
                    } else {
                        truncate_line(&format!("\u{201C}{}\u{201D} — {}", q.trim(), a.trim()), 350)
                    }
                }
                Err(_) => "quote: bad response, try again".to_string(),
            }
        }
        Err(_) => "quote: service unavailable, try again".to_string(),
    }
}

/// Random useless fact via the keyless uselessfacts API.
async fn fetch_fact() -> String {
    match http().get("https://uselessfacts.jsph.pl/api/v2/facts/random").send().await {
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            match serde_json::from_str::<serde_json::Value>(&body) {
                Ok(j) => match j.get("text").and_then(|x| x.as_str()) {
                    Some(f) if !f.is_empty() => truncate_line(f, 350),
                    _ => "fact: bad response, try again".to_string(),
                },
                Err(_) => "fact: bad response, try again".to_string(),
            }
        }
        Err(_) => "fact: service unavailable, try again".to_string(),
    }
}

/// Magic-8-ball — a local random answer, no network.
fn eight_ball() -> String {
    const A: &[&str] = &[
        "It is certain.", "Without a doubt.", "Yes — definitely.", "You may rely on it.",
        "As I see it, yes.", "Most likely.", "Outlook good.", "Yes.", "Signs point to yes.",
        "Reply hazy, try again.", "Ask again later.", "Better not tell you now.",
        "Cannot predict now.", "Concentrate and ask again.", "Don't count on it.",
        "My reply is no.", "My sources say no.", "Outlook not so good.", "Very doubtful.",
    ];
    let i = rand::thread_rng().gen_range(0..A.len());
    format!("🎱 {}", A[i])
}

/// Dice roll — "NdM" (default 1d6), local random. Bounded to avoid huge output.
fn roll_dice(spec: &str) -> String {
    let spec = spec.trim();
    let spec = if spec.is_empty() { "1d6" } else { spec };
    let (n_str, m_str) = match spec.split_once(['d', 'D']) {
        Some(p) => p,
        None => return "roll: use NdM, e.g. 2d6".to_string(),
    };
    let n: u32 = if n_str.is_empty() { 1 } else { n_str.parse().unwrap_or(0) };
    let m: u32 = m_str.parse().unwrap_or(0);
    if n == 0 || m == 0 || n > 100 || m > 100_000 {
        return "roll: use NdM, e.g. 2d6 (max 100 dice, 100000 sides)".to_string();
    }
    let mut rng = rand::thread_rng();
    let rolls: Vec<u32> = (0..n).map(|_| rng.gen_range(1..=m)).collect();
    let sum: u32 = rolls.iter().sum();
    let out = if n == 1 {
        format!("🎲 {}", sum)
    } else {
        format!("🎲 {}: {} [{}]", spec, sum, rolls.iter().map(|r| r.to_string()).collect::<Vec<_>>().join(", "))
    };
    truncate_line(&out, 300)
}

/// Run `bot` with `query` and return the reply text (used by both the public
/// trigger path and the owner's private /command path).
pub async fn run_bot(bot: &str, query: &str) -> String {
    match bot {
        "weather" => fetch_weather(query).await,
        "ud" => fetch_ud(query).await,
        "wiki" => fetch_wiki(query).await,
        "define" => fetch_define(query).await,
        "crypto" => fetch_crypto(query).await,
        "time" => fetch_time(query).await,
        "cc" => fetch_cc(query).await,
        "joke" => fetch_joke().await,
        "quote" => fetch_quote().await,
        "fact" => fetch_fact().await,
        "coin" => if rand::thread_rng().gen::<bool>() { "🪙 Heads".to_string() } else { "🪙 Tails".to_string() },
        "eightball" => eight_ball(),
        "roll" => roll_dice(query),
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

    // (bot, def, default trigger, requires_arg). requires_arg=false for bots that
    // work with no argument (joke/quote/fact/coin/8ball/roll).
    for (bot, def, default_trig, requires_arg) in [
        ("weather", &cfg.weather, "!w", true),
        ("ud", &cfg.ud, "!ud", true),
        ("wiki", &cfg.wiki, "!wiki", true),
        ("define", &cfg.define, "!define", true),
        ("crypto", &cfg.crypto, "!crypto", true),
        ("time", &cfg.time, "!time", true),
        ("cc", &cfg.cc, "!cc", true),
        ("joke", &cfg.joke, "!joke", false),
        ("quote", &cfg.quote, "!quote", false),
        ("fact", &cfg.fact, "!fact", false),
        ("eightball", &cfg.eightball, "!8ball", false),
        ("roll", &cfg.roll, "!roll", false),
        ("coin", &cfg.coin, "!coin", false),
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
        if requires_arg && arg.is_empty() { continue; }  // needs a query → stay silent
        if !cooldown_ok(username, bot) { continue; }     // anti-flood self-guard

        let conn = conn.clone();
        let (bot, query, channel) = (bot.to_string(), arg.to_string(), channel.to_string());
        tokio::spawn(async move {
            // Sanitize at the boundary: truncate_line (→ strip_crlf) here guarantees
            // NO bot reply — success OR error/not-found branch, current or future —
            // can ever smuggle CR/LF/NUL into the outbound IRC line. Matches the
            // CRLF-injection discipline the rest of the code follows (see irc.rs).
            let reply = truncate_line(&run_bot(&bot, &query).await, 400);
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
