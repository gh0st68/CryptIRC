//! ircproto.rs — pure, dependency-free IRC line parsing/formatting primitives.
//!
//! Shared by the `cryptirc` web binary (via `src/irc.rs`) and the `irc-core` daemon
//! binary. Nothing in this module touches `AppState`/`ServerEvent`/`NetworkConfig`
//! or any vault/filesystem state — it only ever transforms strings/bytes, which is
//! exactly what makes it safe to share across the process boundary between the two
//! binaries introduced by the irc-core daemon split.

use std::collections::HashMap;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// #S7: maximum IRC line length (prevent memory exhaustion from rogue server), CRLF
/// excluded. r4 (agy P2 ircproto.rs:13): the IRCv3 message-tags limit — a tag section of
/// at most 8191 bytes (incl. its `@` and the separating space) plus the classic 512-byte
/// message incl. CRLF. The old 8192 dropped compliant tagged lines (8193..8701 bytes).
/// Worst case over IPC: 8701 control bytes JSON-escape to ~52 KB, under MAX_FRAME_LEN.
pub const MAX_IRC_LINE_LEN: usize = 8191 + 510;

// ─── Safe-truncation / slice helpers ───────────────────────────────────────────

/// #19: char-boundary-safe truncation. Byte-slicing a String (`&s[..n]`) panics
/// when byte `n` lands in the middle of a multibyte UTF-8 sequence; an ordinary
/// IRC peer can trivially trigger this with a unicode NOTICE/nick. Take whole
/// chars instead so truncation can never split a code point.
pub fn truncate_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// #93: replace `token` (an ASCII `$me`/`$nick`) with `val` only when it occurs as a
/// whole token — i.e. bounded by a non-word character (or string edge) on both sides —
/// so a literal `$me`/`$nick` embedded in a larger word (e.g. a NickServ password) is
/// left untouched instead of being silently rewritten to the nick.
pub fn expand_perform_token(s: &str, token: &str, val: &str) -> String {
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
pub fn params_from(params: &[String], n: usize) -> String {
    params.get(n..).map(|s| s.join(" ")).unwrap_or_default()
}

/// RFC1459 case-fold for channel/nick comparison. EFnet (ircd-ratbox) and most
/// legacy IRCds advertise CASEMAPPING=rfc1459, in which `{}|^` are the lowercase
/// forms of `[]\~`. Channel names are case-INSENSITIVE on the wire, but a server
/// — or, very commonly, a ZNC bouncer sitting between us and the network — can
/// echo a channel in a different case than the JOIN we stored. Fold both sides to
/// this canonical key before any HashSet/HashMap match so case never breaks
/// matching.
pub fn irc_lower(s: &str) -> String {
    s.chars().map(|c| match c {
        'A'..='Z' => (c as u8 + 32) as char,
        '['  => '{',
        ']'  => '}',
        '\\' => '|',
        '~'  => '^',
        other => other,
    }).collect()
}

/// The server's ISUPPORT CASEMAPPING (codex P2 irc_daemon.rs:144). Until a 005 says
/// otherwise a connection uses `Rfc1459` (the RFC default, and what irc_lower always
/// did). Any mapping other than the two RFC1459 flavours folds ASCII letters only:
/// `ascii` does exactly that, and the Unicode mappings (rfc7613/precis/utf8 on Ergo &
/// co.) fold a superset of it, so no `[`/`{` style equivalence is ever invented.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CaseMapping {
    #[default]
    Rfc1459,
    StrictRfc1459,
    Ascii,
}

impl CaseMapping {
    /// Map a CASEMAPPING= value (case-insensitive).
    pub fn from_token(v: &str) -> Self {
        match v.to_ascii_lowercase().as_str() {
            "rfc1459" => CaseMapping::Rfc1459,
            "strict-rfc1459" | "rfc1459-strict" => CaseMapping::StrictRfc1459,
            _ => CaseMapping::Ascii,
        }
    }
    /// The CASEMAPPING announced in one 005 line's params, if any.
    pub fn from_isupport(params: &[String]) -> Option<Self> {
        params.iter().find_map(|t| {
            let (k, v) = t.split_once('=')?;
            k.eq_ignore_ascii_case("CASEMAPPING").then(|| Self::from_token(v))
        })
    }
    /// Case-fold a nick or channel name for comparison under this mapping.
    pub fn fold(self, s: &str) -> String {
        match self {
            CaseMapping::Rfc1459 => irc_lower(s),
            CaseMapping::StrictRfc1459 => s.chars().map(|c| match c {
                'A'..='Z' => (c as u8 + 32) as char,
                '['  => '{',
                ']'  => '}',
                '\\' => '|',
                other => other,
            }).collect(),
            CaseMapping::Ascii => s.to_ascii_lowercase(),
        }
    }
    /// The CASEMAPPING= token for this mapping (SessionSync carries it).
    pub fn token(self) -> &'static str {
        match self {
            CaseMapping::Rfc1459 => "rfc1459",
            CaseMapping::StrictRfc1459 => "strict-rfc1459",
            CaseMapping::Ascii => "ascii",
        }
    }
    /// Does this mapping treat RFC1459 specials (`[]\~` vs `{}|^`) as equal?
    pub fn folds_specials(self) -> bool { !matches!(self, CaseMapping::Ascii) }
}

/// Strip CR/LF/NUL from a string headed for an outbound raw IRC line. Applied at
/// every point where server-supplied or user-supplied text is interpolated into a
/// line we send, so an embedded newline can never inject a second command
/// (CRLF injection). Both the web binary (constructing lines via ClientMessage)
/// and the daemon (relaying RawSend lines) share this exact discipline.
pub fn strip_crlf(s: &str) -> String {
    s.chars().filter(|&c| c != '\r' && c != '\n' && c != '\0').collect()
}

// ─── Capped line reader ────────────────────────────────────────────────────────

/// #S7: outcome of a single capped line read. See `read_capped_line`.
pub enum CappedLine {
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
/// NOT cancel-safe: the partial-line buffer lives inside this future, so if it is
/// dropped mid-line (e.g. it lost a `tokio::select!` race) the bytes already pulled
/// off the socket are gone and the next read starts in the middle of that line.
/// Anything that races the read against other branches must use
/// [`CappedLineReader`] instead, which keeps the partial line across calls. Kept for
/// callers that read in a plain loop (and for API stability).
pub async fn read_capped_line<R>(reader: &mut R) -> std::io::Result<CappedLine>
where
    R: AsyncBufRead + Unpin,
{
    CappedLineReader::new(reader).next_line().await
}

/// Ceiling on buffered content bytes (everything before the terminating `\n`).
/// `+2` so a line of exactly MAX_IRC_LINE_LEN content followed by `\r\n` — or a
/// trailing `\r` that trimming would remove — is still accepted, matching the
/// old trim-then-compare check.
const CONTENT_CEIL: usize = MAX_IRC_LINE_LEN + 2;

/// #S7 + cancel-safety: a capped IRC line reader whose partial-line state lives in
/// the struct, not in the read future.
///
/// Pulls from the `BufReader`'s internal buffer via `fill_buf()`/`consume()` and
/// copies at most `MAX_IRC_LINE_LEN + 2` content bytes into its buffer. Once that
/// ceiling is hit it keeps consuming (so the connection stays in sync) but stops
/// growing the buffer, then reports `Oversized`.
///
/// CANCEL-SAFE: `next_line()` can be dropped at any await point (a `select!` timer
/// or command branch winning) without losing input. Its only await is
/// `fill_buf()`, which keeps unread bytes inside the `BufReader`; every byte that
/// is `consume()`d is first copied into `self.buf` (or counted as oversized) in the
/// same synchronous step, so a later call simply resumes the same line. The old
/// free-function form kept that buffer on the future's stack, so a cancelled read
/// dropped the line's head and the tail was parsed as a forged standalone line.
///
/// (e) LENIENT UTF-8: invalid bytes are decoded lossily (→ U+FFFD) so a single
///     non-UTF-8 byte in a server line (common in MOTD/topic/realname) can never
///     drop the connection.
pub struct CappedLineReader<R> {
    reader: R,
    buf: Vec<u8>,
    oversized: bool,
}

impl<R: AsyncBufRead + Unpin> CappedLineReader<R> {
    pub fn new(reader: R) -> Self {
        Self { reader, buf: Vec::new(), oversized: false }
    }

    /// Read the next line. Cancel-safe (see the type docs).
    pub async fn next_line(&mut self) -> std::io::Result<CappedLine> {
        loop {
            // How many bytes to consume from the BufReader after inspecting them, and
            // whether this chunk contained the line-terminating newline. Computed inside
            // a scope so the `&[u8]` borrow from `fill_buf()` ends before `consume()`.
            let (consume_amt, found_nl) = {
                let available = self.reader.fill_buf().await?;
                if available.is_empty() {
                    // EOF. If we have pending content it's a final unterminated line
                    // (parity with `Lines`, which yields a last line without `\n`);
                    // otherwise it's a clean close.
                    if self.buf.is_empty() && !self.oversized {
                        return Ok(CappedLine::Eof);
                    }
                    break;
                }
                match available.iter().position(|&b| b == b'\n') {
                    Some(idx) => {
                        // `idx` bytes are line content; +1 to also consume the `\n`.
                        if !self.oversized {
                            let take = idx.min(CONTENT_CEIL - self.buf.len());
                            self.buf.extend_from_slice(&available[..take]);
                            if take < idx {
                                // The newline is within reach but content already exceeds
                                // the cap — discard this line.
                                self.oversized = true;
                            }
                        }
                        (idx + 1, true)
                    }
                    None => {
                        // No newline yet: copy what fits, then keep draining without
                        // growing the buffer once the ceiling is reached.
                        if !self.oversized {
                            let room = CONTENT_CEIL - self.buf.len();
                            let take = available.len().min(room);
                            self.buf.extend_from_slice(&available[..take]);
                            if take < available.len() {
                                self.oversized = true;
                            }
                        }
                        (available.len(), false)
                    }
                }
            };
            self.reader.consume(consume_amt);
            if found_nl {
                break;
            }
        }

        // A full line (or the final unterminated one) is complete: hand it out and
        // reset the per-line state for the next call.
        let buf = std::mem::take(&mut self.buf);
        if std::mem::replace(&mut self.oversized, false) {
            return Ok(CappedLine::Oversized);
        }

        // `buf` holds the line content only — the terminating `\n` is consumed but
        // never copied in, so there is nothing more to strip here. Any trailing `\r`
        // is left for the caller's existing `trim_end_matches` (parity with the old
        // path, which re-trimmed too).
        //
        // Decode LENIENTLY (lossy): real IRC servers legitimately send non-UTF-8 bytes
        // (Latin-1/CP1252 in MOTD art, topics, realnames). `from_utf8_lossy` maps
        // invalid bytes to U+FFFD so the line still parses and the connection
        // survives; the downstream CR/LF/NUL stripping and IRC tokenizer are
        // unaffected.
        let line = String::from_utf8_lossy(&buf).into_owned();
        Ok(CappedLine::Line(line))
    }
}

// ─── IRC line parser ──────────────────────────────────────────────────────────

pub struct IrcLine {
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
    pub tags: HashMap<String, String>,
}

/// r6 (agy P2 ircproto.rs:323): runs of spaces between the parts are one separator (RFC
/// 1459/2812 `<SPACE> ::= ' ' { ' ' }`): `:srv  001  me :hi` is command 001 with params
/// [me, hi], never an empty command or empty parameters. A trailing parameter (after ` :`)
/// is kept verbatim, spaces included.
pub fn parse_irc(line: &str) -> IrcLine {
    let mut rest = line.trim_start_matches(' ');
    // IRCv3 message tags: @key=value;key2=value2
    let mut tags = HashMap::new();
    if let Some(rest2) = rest.strip_prefix('@') {
        let (tag_str, r) = rest2.split_once(' ').unwrap_or((rest2, ""));
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
        rest = r.trim_start_matches(' ');
    }
    let mut prefix = None;
    if let Some(rest2) = rest.strip_prefix(':') {
        let (p, r) = rest2.split_once(' ').unwrap_or((rest2, ""));
        prefix = Some(p.to_string()); rest = r.trim_start_matches(' ');
    }
    let mut params = Vec::new();
    let (cmd_part, r) = rest.split_once(' ').unwrap_or((rest, ""));
    let mut remaining = r.trim_start_matches(' ');
    while !remaining.is_empty() {
        if let Some(rest2) = remaining.strip_prefix(':') { params.push(rest2.to_string()); break; }
        match remaining.split_once(' ') {
            Some((t, r)) => { params.push(t.to_string()); remaining = r.trim_start_matches(' '); }
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
pub fn unescape_tag_value(v: &str) -> String {
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

pub fn nick_from_prefix(p: &Option<String>) -> String {
    p.as_deref().and_then(|s| s.split('!').next()).unwrap_or("*").to_string()
}

pub fn userhost_from_prefix(p: &Option<String>) -> String {
    p.as_deref().and_then(|s| s.split_once('!')).map(|(_, uh)| uh.to_string()).unwrap_or_default()
}

/// Look up a channel's saved key in a `channel_keys` map, tolerant of how the key was
/// folded when it was stored. Every writer stores under `str::to_lowercase()` (main.rs
/// JOIN-via-Send / JoinChannel, irc.rs persist_channel_key), while channel matching
/// elsewhere uses the RFC1459 `irc_lower` fold (`[]\~` ≡ `{}|^`). Looking up by only one
/// of the two made a keyed channel such as `#Key[X]` rejoin WITHOUT its key. Order: the
/// exact storage form first (so on an ascii-casemapping server `#a[b]` never picks up
/// the key of the distinct channel `#a{b}`), then the `irc_lower` form, then any entry
/// that folds to the same name.
/// channel_key_lookup under a known CASEMAPPING: on an `ascii` server `#a[b]` and
/// `#a{b}` are different channels, so only the exact stored spelling may match there.
/// r4 (codex P2 ircproto.rs:384): only full `rfc1459` takes the rfc1459 path; under
/// `strict-rfc1459` `~` and `^` are different characters, so `#a~` must not get `#a^`'s key.
pub fn channel_key_lookup_cm<'a>(keys: &'a HashMap<String, String>, channel: &str, cm: CaseMapping) -> Option<&'a String> {
    if cm == CaseMapping::Rfc1459 { return channel_key_lookup(keys, channel); }
    if let Some(k) = keys.get(&channel.to_lowercase()) { return Some(k); }
    let folded = cm.fold(channel);
    keys.iter().find(|(k, _)| cm.fold(k) == folded).map(|(_, v)| v)
}

pub fn channel_key_lookup<'a>(keys: &'a HashMap<String, String>, channel: &str) -> Option<&'a String> {
    if let Some(k) = keys.get(&channel.to_lowercase()) { return Some(k); }
    let folded = irc_lower(channel);
    if let Some(k) = keys.get(&folded) { return Some(k); }
    keys.iter().find(|(k, _)| irc_lower(k) == folded).map(|(_, v)| v)
}

/// r7 (codex P2 ircproto.rs:490): which channel modes take a parameter, as the server says in
/// ISUPPORT — `CHANMODES=A,B,C,D` (A list modes and B: a parameter both ways; C: only when
/// set; D: never) and the `PREFIX=(modes)symbols` modes (a parameter both ways). Until a
/// server has said so, the conventional sets apply (prefix `ovhaq`, A `beI`, B `k`, C `lfjLJ`,
/// D the common no-parameter letters below) and any OTHER letter is unknown: the walk stops
/// there, because every parameter after it might belong to it — a key read past it could be
/// another mode's argument (`+Hk 50:10 secret` would have saved `50:10`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ChanModes {
    groups: Option<[String; 4]>,
    prefix: Option<String>,
}

/// Channel modes taken to have no parameter while the server's CHANMODES is unknown.
const CONVENTIONAL_NO_PARAM: &str = "imnpstrcCRSMNOTQzugPD";

impl ChanModes {
    /// Learn CHANMODES= / PREFIX= from one 005 line's params. Returns true if anything changed.
    pub fn learn(&mut self, params: &[String]) -> bool {
        let mut changed = false;
        for t in params {
            let Some((k, v)) = t.split_once('=') else { continue };
            if k.eq_ignore_ascii_case("CHANMODES") {
                let g: Vec<&str> = v.split(',').collect();
                let ok = |x: &str| x.len() <= 64 && x.chars().all(|c| c.is_ascii_alphabetic());
                if g.len() >= 4 && g[..4].iter().all(|x| ok(x)) {
                    let new = Some([g[0].to_string(), g[1].to_string(), g[2].to_string(), g[3].to_string()]);
                    if self.groups != new { self.groups = new; changed = true; }
                }
            } else if k.eq_ignore_ascii_case("PREFIX") {
                if let Some(modes) = v.strip_prefix('(').and_then(|r| r.split_once(')')).map(|(m, _)| m) {
                    if modes.len() <= 16 && modes.chars().all(|c| c.is_ascii_alphabetic()) && self.prefix.as_deref() != Some(modes) {
                        self.prefix = Some(modes.to_string()); changed = true;
                    }
                }
            }
        }
        changed
    }

    /// r8 (codex P1 irc.rs:1845): is `c` a prefix (status) mode — per the server's PREFIX, or
    /// the conventional `ovhaq` until it has said?
    pub fn is_prefix_mode(&self, c: char) -> bool { self.prefix.as_deref().unwrap_or("ovhaq").contains(c) }

    /// r8 (codex P2 ipc_client.rs:1101): what was learned, as ISUPPORT tokens
    /// (`CHANMODES=…`, `PREFIX=(…)`), for the SessionSync; `learn` reads them back. None
    /// while nothing was learned.
    pub fn isupport(&self) -> Option<String> {
        let mut t = Vec::new();
        if let Some([a, b, c, d]) = &self.groups { t.push(format!("CHANMODES={},{},{},{}", a, b, c, d)); }
        if let Some(p) = &self.prefix { t.push(format!("PREFIX=({})", p)); }
        (!t.is_empty()).then(|| t.join(" "))
    }

    /// Does mode letter `c` take a parameter when set (`adding`) / unset? None = unknown.
    pub fn takes_param(&self, c: char, adding: bool) -> Option<bool> {
        if self.prefix.as_deref().unwrap_or("ovhaq").contains(c) { return Some(true); }
        match &self.groups {
            Some([a, b, cc, d]) => {
                if a.contains(c) || b.contains(c) { Some(true) }
                else if cc.contains(c) { Some(adding) }
                else if d.contains(c) { Some(false) }
                else { None }
            }
            None => {
                if "beIk".contains(c) { Some(true) }
                else if "lfjLJ".contains(c) { Some(adding) }
                else if CONVENTIONAL_NO_PARAM.contains(c) { Some(false) }
                else { None }
            }
        }
    }
}

/// Walk a channel MODE change (`<modes> [args…]`, i.e. the params after the target) and
/// report the LAST `k` change in it: `Some(Some(key))` for `+k key`, `Some(None)` for `-k`,
/// `None` when no usable k change is present (a masked `+k *` is "not told", not a change).
/// Parameters are consumed per `cm` (see ChanModes); at an unknown letter the walk stops
/// and only what came before it counts.
pub fn channel_key_change(modes: &str, cm: &ChanModes) -> Option<Option<String>> {
    let mut it = modes.split_whitespace();
    let letters = it.next()?;
    let mut adding = true;
    let mut out = None;
    for c in letters.chars() {
        match c {
            '+' => adding = true,
            '-' => adding = false,
            'k' => {
                // r8 (agy P1 irc.rs:1883): `-k` consumes a parameter only if the server's
                // CHANMODES gives k one when unset (group B, the default).
                let arg = if cm.takes_param('k', adding) != Some(false) { it.next() } else { None };
                if adding {
                    if let Some(k) = arg.filter(|k| !k.is_empty() && *k != "*") {
                        out = Some(Some(k.to_string()));
                    }
                } else {
                    out = Some(None);
                }
            }
            _ => match cm.takes_param(c, adding) {
                Some(true) => { let _ = it.next(); }
                Some(false) => {}
                None => break,
            },
        }
    }
    out
}

/// Status-message prefixes assumed while the server's ISUPPORT `STATUSMSG` is unknown
/// (before 005, or after a web restart once the 005 line has aged out of the daemon's
/// ring): the PREFIX symbols servers use in practice.
pub const DEFAULT_STATUSMSG: &str = "~&@%+";

/// The `STATUSMSG=` value in one 005 line's params, if any (only plausible prefix symbols,
/// at most 8 of them; anything else is ignored).
pub fn statusmsg_from_isupport(params: &[String]) -> Option<String> {
    params.iter().find_map(|t| {
        let (k, v) = t.split_once('=')?;
        if !k.eq_ignore_ascii_case("STATUSMSG") { return None; }
        (v.len() <= 8 && v.chars().all(|c| "~&@%+!*.-=^".contains(c))).then(|| v.to_string())
    })
}

/// r4 (codex P1/P2 irc.rs:591): an incoming PRIVMSG/NOTICE/TAGMSG addressed to a
/// STATUSMSG target (`@#chan`, `+#chan`, `%#chan`, stacked `@+#chan`) is a message to the
/// members of that channel holding that status — not a private message. Returns
/// (status prefix, channel) for such a target, None otherwise. `statusmsg` = the server's
/// STATUSMSG= value (None = unknown → DEFAULT_STATUSMSG). Prefix characters are consumed
/// greedily, as servers do; if what is left is no channel name, fewer are consumed, so a
/// prefix character that is also a channel type (`&`, `+`) still yields the channel
/// (`@&chan` → `&chan`).
pub fn statusmsg_target<'a>(target: &'a str, statusmsg: Option<&str>) -> Option<(&'a str, &'a str)> {
    let set = statusmsg.unwrap_or(DEFAULT_STATUSMSG);
    let greedy = target.len() - target.trim_start_matches(|c: char| set.contains(c)).len();
    // Status symbols are ASCII, so every index up to `greedy` is a char boundary.
    (1..=greedy).rev().find_map(|i| {
        let chan = &target[i..];
        (chan.len() >= 2 && chan.starts_with(['#', '&', '+', '!'])).then(|| (&target[..i], chan))
    })
}

pub fn strip_pfx(n: &str) -> &str { let s = n.trim_start_matches(|c: char| "@+~&%".contains(c)); if s.is_empty() { n } else { s } }

/// modes, all additive). Only param-taking modes consume a param, in letter order (per `cm`,
/// see ChanModes); returns the key if present and not masked ('*'). Best-effort: lets us
/// learn a keyed channel's key on join so auto-rejoin can re-enter it even when we didn't
/// /join with it. r7: None (nothing learned, the saved key stays) when an unknown mode letter
/// comes before `k` — the parameter that looks like the key may be that mode's.
pub fn channel_key_from_modes(modes: &str, cm: &ChanModes) -> Option<String> {
    let mut it = modes.split_whitespace();
    let letters = it.next()?.trim_start_matches('+');
    for c in letters.chars() {
        match c {
            'k' => {
                let k = it.next()?;
                return if !k.is_empty() && k != "*" { Some(k.to_string()) } else { None };
            }
            '+' => {}
            _ => match cm.takes_param(c, true) {
                Some(true) => { let _ = it.next(); }
                Some(false) => {}
                None => return None,
            },
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncWriteExt, BufReader};
    use tokio::time::{sleep, Duration};

    /// r6 (agy P2 ircproto.rs:323): runs of spaces are one separator; the trailing parameter
    /// is kept verbatim.
    #[test]
    fn parse_irc_tolerates_runs_of_spaces() {
        let p = parse_irc(":srv.example  001   me  :Welcome  to   IRC ");
        assert_eq!((p.prefix.as_deref(), p.command.as_str()), (Some("srv.example"), "001"));
        assert_eq!(p.params, vec!["me".to_string(), "Welcome  to   IRC ".to_string()]);
        let p = parse_irc("@time=x;id=1   :n!u@h   PRIVMSG    #chan   :hi there");
        assert_eq!((p.tags.get("id").map(String::as_str), p.prefix.as_deref(), p.command.as_str()), (Some("1"), Some("n!u@h"), "PRIVMSG"));
        assert_eq!(p.params, vec!["#chan".to_string(), "hi there".to_string()]);
        let p = parse_irc(":n!u@h JOIN   #a  ");
        assert_eq!((p.command.as_str(), p.params.clone()), ("JOIN", vec!["#a".to_string()]), "no empty parameters");
        let p = parse_irc("PING  :token x");
        assert_eq!((p.prefix.is_none(), p.command.as_str(), p.params.clone()), (true, "PING", vec!["token x".to_string()]));
        let p = parse_irc(":srv MODE #c +k  key");
        assert_eq!(p.params, vec!["#c".to_string(), "+k".to_string(), "key".to_string()]);
        // Single spaces: unchanged.
        let p = parse_irc(":a!b@c PRIVMSG #x :one two");
        assert_eq!((p.command.as_str(), p.params.clone()), ("PRIVMSG", vec!["#x".to_string(), "one two".to_string()]));
        let p = parse_irc(":a!b@c PRIVMSG #x ::colon");
        assert_eq!(p.params[1], ":colon", "a trailing parameter may start with ':'");
        let p = parse_irc(":a!b@c PRIVMSG #x :");
        assert_eq!(p.params, vec!["#x".to_string(), String::new()], "an empty trailing parameter is kept");
    }

    /// r7 (codex P2 ircproto.rs:490): parameters are walked per the server's CHANMODES/PREFIX;
    /// with CHANMODES unknown an unknown letter before `k` means "don't know" — never a
    /// wrong key.
    #[test]
    fn mode_keys_follow_chanmodes_and_never_guess() {
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let unknown = ChanModes::default();
        assert_eq!(channel_key_from_modes("+Hk 50:10 secret", &unknown), None, "H unknown: the key is not guessed");
        assert_eq!(channel_key_change("+Hk 50:10 secret", &unknown), None);
        assert_eq!(channel_key_from_modes("+ntk secret", &unknown), Some("secret".into()));
        assert_eq!(channel_key_from_modes("+lk 10 secret", &unknown), Some("secret".into()));
        let mut insp = ChanModes::default();
        assert!(insp.learn(&p(&["me", "CHANMODES=IXbegw,k,FHJLfjl,BCDKMNOPQRSTcimnprstuz", "PREFIX=(Yqaohv)!~&@%+", "are supported"])));
        assert!(!insp.learn(&p(&["me", "CHANMODES=IXbegw,k,FHJLfjl,BCDKMNOPQRSTcimnprstuz"])), "unchanged");
        assert_eq!(channel_key_from_modes("+Hk 50:10 secret", &insp), Some("secret".into()), "H takes a parameter here");
        assert_eq!(channel_key_change("+Hk 50:10 secret", &insp), Some(Some("secret".into())));
        assert_eq!(channel_key_change("-H+Yk nick secret", &insp), Some(Some("secret".into())), "-H no param, Y a prefix mode");
        assert_eq!(channel_key_change("+Xk mask secret", &insp), Some(Some("secret".into())), "X a list mode");
        assert_eq!(channel_key_change("+k first", &insp), Some(Some("first".into())));
        assert_eq!(channel_key_change("+k-k first", &insp), Some(None));
        assert_eq!(channel_key_from_modes("+Zk x secret", &insp), None, "a letter the server did not list: unknown");
        assert_eq!(channel_key_change("+kZ ok x", &insp), Some(Some("ok".into())), "what came before an unknown letter counts");
        assert!(!ChanModes::default().learn(&p(&["me", "CHANMODES=a,b", "PREFIX=junk"])), "malformed values are ignored");
        // r8: `a` not a prefix mode here (group D); `-k` without a parameter where k is in C.
        let mut odd = ChanModes::default();
        odd.learn(&p(&["me", "CHANMODES=b,,kl,amnt", "PREFIX=(ov)@+"]));
        assert!(!odd.is_prefix_mode('a') && odd.is_prefix_mode('o') && ChanModes::default().is_prefix_mode('a'));
        assert_eq!(channel_key_change("+ak secret", &odd), Some(Some("secret".into())), "a takes no parameter");
        assert_eq!(channel_key_change("-k+o alice", &odd), Some(None), "-k takes none, +o takes alice");
        assert_eq!(channel_key_change("-k+k new", &odd), Some(Some("new".into())));
        // r8: the learned set round-trips through its ISUPPORT form (SessionSync).
        let mut back = ChanModes::default();
        assert!(back.learn(&insp.isupport().unwrap().split(' ').map(str::to_string).collect::<Vec<_>>()));
        assert_eq!(back, insp);
        assert_eq!(ChanModes::default().isupport(), None);
    }

    #[test]
    fn casemapping_tokens_and_folds() {
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(CaseMapping::from_isupport(&p(&["me", "CHANTYPES=#", "CASEMAPPING=ascii", "are supported"])), Some(CaseMapping::Ascii));
        assert_eq!(CaseMapping::from_isupport(&p(&["me", "casemapping=RFC1459"])), Some(CaseMapping::Rfc1459));
        assert_eq!(CaseMapping::from_isupport(&p(&["me", "CASEMAPPING=strict-rfc1459"])), Some(CaseMapping::StrictRfc1459));
        assert_eq!(CaseMapping::from_isupport(&p(&["me", "CASEMAPPING=rfc8265"])), Some(CaseMapping::Ascii));
        assert_eq!(CaseMapping::from_isupport(&p(&["me", "NETWORK=x"])), None);
        assert_eq!(CaseMapping::default().fold("#Foo[Bar]~"), irc_lower("#Foo[Bar]~"));
        assert_eq!(CaseMapping::Ascii.fold("#Foo[Bar]~"), "#foo[bar]~");
        assert_eq!(CaseMapping::StrictRfc1459.fold("#Foo[Bar]~\\"), "#foo{bar}~|");
        for cm in [CaseMapping::Rfc1459, CaseMapping::StrictRfc1459, CaseMapping::Ascii] {
            assert_eq!(CaseMapping::from_token(cm.token()), cm);
        }
    }

    /// The rust-irc audit's split-line forgery, as a unit test: the server sends the HEAD
    /// of one line, stalls (while a select! tick keeps cancelling the read), then sends
    /// a tail that looks like a whole NickServ NOTICE. The reader must hand out ONE line
    /// (the real one, from `attacker`), never the tail on its own.
    #[tokio::test]
    async fn reader_is_cancel_safe_across_select_ticks() {
        let (mut tx, rx) = tokio::io::duplex(64);
        let mut lr = CappedLineReader::new(BufReader::new(rx));
        let writer = tokio::spawn(async move {
            tx.write_all(b":attacker!a@evil.host PRIVMSG #t :hello ").await.unwrap();
            sleep(Duration::from_millis(60)).await;
            tx.write_all(b":NickServ!NickServ@services. NOTICE me ").await.unwrap();
            sleep(Duration::from_millis(60)).await;
            tx.write_all(b":FORGED\r\nPING :next\r\n").await.unwrap();
            tx // keep the stream open (no EOF) until the test ends
        });
        let mut tick = tokio::time::interval(Duration::from_millis(5));
        let mut lines = Vec::new();
        let mut ticks_mid_line = 0u32;
        while lines.len() < 2 {
            tokio::select! {
                _ = tick.tick() => { if lines.is_empty() { ticks_mid_line += 1; } }
                r = lr.next_line() => match r.unwrap() {
                    CappedLine::Line(l) => lines.push(l),
                    CappedLine::Oversized => panic!("unexpected Oversized"),
                    CappedLine::Eof => panic!("unexpected Eof"),
                },
            }
        }
        // The tick really did cancel the read while the line was half-received.
        assert!(ticks_mid_line >= 10, "only {ticks_mid_line} ticks raced the partial line");
        assert_eq!(lines[0], ":attacker!a@evil.host PRIVMSG #t :hello :NickServ!NickServ@services. NOTICE me :FORGED\r");
        assert_eq!(lines[1], "PING :next\r");
        let p = parse_irc(lines[0].trim_end_matches('\r'));
        assert_eq!(p.command, "PRIVMSG");
        assert_eq!(nick_from_prefix(&p.prefix), "attacker");
        drop(writer);
    }

    /// An oversized line that straddles cancellations is still drained as ONE
    /// oversized line; its tail must not resurface as a fresh line.
    #[tokio::test]
    async fn oversized_line_is_drained_across_cancellations() {
        let (mut tx, rx) = tokio::io::duplex(1024);
        let mut lr = CappedLineReader::new(BufReader::new(rx));
        let writer = tokio::spawn(async move {
            for _ in 0..12 {
                tx.write_all(&[b'A'; 1000]).await.unwrap();
                sleep(Duration::from_millis(10)).await;
            }
            tx.write_all(b":evil!e@h PRIVMSG #t :tail-of-oversized\r\n:ok!o@h PRIVMSG #t :next\r\n").await.unwrap();
            tx
        });
        let mut tick = tokio::time::interval(Duration::from_millis(2));
        let mut got = Vec::new();
        while got.len() < 2 {
            tokio::select! {
                _ = tick.tick() => {}
                r = lr.next_line() => got.push(r.unwrap()),
            }
        }
        assert!(matches!(got[0], CappedLine::Oversized));
        match &got[1] {
            CappedLine::Line(l) => assert_eq!(l, ":ok!o@h PRIVMSG #t :next\r"),
            _ => panic!("expected the next real line"),
        }
        drop(writer);
    }

    /// EOF semantics are unchanged: a final unterminated line is returned, then Eof.
    #[tokio::test]
    async fn reader_eof_semantics_unchanged() {
        let data: &[u8] = b"one\r\nlast-no-newline";
        let mut lr = CappedLineReader::new(BufReader::new(data));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l == "one\r"));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l == "last-no-newline"));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Eof));
        // An exactly-at-cap line is accepted; one byte over is Oversized.
        let mut ok = vec![b'x'; MAX_IRC_LINE_LEN]; ok.extend_from_slice(b"\r\n");
        let mut big = vec![b'y'; CONTENT_CEIL + 1]; big.extend_from_slice(b"\nz\n");
        ok.extend_from_slice(&big);
        let mut lr = CappedLineReader::new(BufReader::new(&ok[..]));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l.len() == MAX_IRC_LINE_LEN + 1));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Oversized));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l == "z"));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Eof));
        // The legacy free function still behaves the same for a plain loop.
        let mut r = BufReader::new(&b"a\nb\n"[..]);
        assert!(matches!(read_capped_line(&mut r).await.unwrap(), CappedLine::Line(ref l) if l == "a"));
        assert!(matches!(read_capped_line(&mut r).await.unwrap(), CappedLine::Line(ref l) if l == "b"));
        assert!(matches!(read_capped_line(&mut r).await.unwrap(), CappedLine::Eof));
    }

    #[test]
    fn channel_key_change_walks_params_in_order() {
        let cm = ChanModes::default();
        assert_eq!(channel_key_change("+k sekrit", &cm), Some(Some("sekrit".into())));
        assert_eq!(channel_key_change("-k sekrit", &cm), Some(None));
        assert_eq!(channel_key_change("-k", &cm), Some(None));
        assert_eq!(channel_key_change("+k *", &cm), None); // masked: not told
        assert_eq!(channel_key_change("+ovk a b key2", &cm), Some(Some("key2".into())));
        assert_eq!(channel_key_change("+lk 10 key3", &cm), Some(Some("key3".into())));
        assert_eq!(channel_key_change("-l+k key4", &cm), Some(Some("key4".into()))); // -l takes no param
        assert_eq!(channel_key_change("+b-k *!*@x old", &cm), Some(None));
        assert_eq!(channel_key_change("+nt", &cm), None);
        assert_eq!(channel_key_change("", &cm), None);
    }

    #[test]
    fn channel_key_lookup_tolerates_both_folds() {
        let mut keys = HashMap::new();
        // What main.rs / persist_channel_key store (str::to_lowercase).
        keys.insert("#key[x]".to_string(), "sekrit".to_string());
        assert_eq!(channel_key_lookup(&keys, "#Key[X]").map(String::as_str), Some("sekrit"));
        // A server/bouncer echoing the RFC1459-folded spelling still finds it.
        assert_eq!(channel_key_lookup(&keys, "#KEY{X}").map(String::as_str), Some("sekrit"));
        assert_eq!(channel_key_lookup(&keys, "#key{x}").map(String::as_str), Some("sekrit"));
        assert_eq!(channel_key_lookup(&keys, "#other"), None);
        // An irc_lower-keyed entry (old daemon-side form) is found too.
        let mut k2 = HashMap::new();
        k2.insert("#a{b}^".to_string(), "k2".to_string());
        assert_eq!(channel_key_lookup(&k2, "#A[B]~").map(String::as_str), Some("k2"));
        // Exact storage form wins over a fold-equal sibling (ascii-casemapping servers
        // treat #a[b] and #a{b} as different channels).
        let mut k3 = HashMap::new();
        k3.insert("#a[b]".to_string(), "square".to_string());
        k3.insert("#a{b}".to_string(), "curly".to_string());
        assert_eq!(channel_key_lookup(&k3, "#A[B]").map(String::as_str), Some("square"));
        assert_eq!(channel_key_lookup(&k3, "#A{B}").map(String::as_str), Some("curly"));
    }

    /// r4 (codex P2 ircproto.rs:384): strict-rfc1459 folds `[]\` but NOT `~`/`^`.
    #[test]
    fn strict_rfc1459_key_lookup_keeps_tilde_and_caret_apart() {
        let mut keys = HashMap::new();
        keys.insert("#private^".to_string(), "caret".to_string());
        keys.insert("#key[x]".to_string(), "sekrit".to_string());
        let s = CaseMapping::StrictRfc1459;
        assert_eq!(channel_key_lookup_cm(&keys, "#private~", s), None);
        assert_eq!(channel_key_lookup_cm(&keys, "#PRIVATE^", s).map(String::as_str), Some("caret"));
        assert_eq!(channel_key_lookup_cm(&keys, "#KEY{X}", s).map(String::as_str), Some("sekrit"));
        // Full rfc1459 still equates them; ascii only folds letters.
        assert_eq!(channel_key_lookup_cm(&keys, "#private~", CaseMapping::Rfc1459).map(String::as_str), Some("caret"));
        assert_eq!(channel_key_lookup_cm(&keys, "#key{x}", CaseMapping::Ascii), None);
    }

    /// r4 (codex P1/P2 irc.rs:591): STATUSMSG targets resolve to their channel.
    #[test]
    fn statusmsg_targets_resolve_to_the_channel() {
        assert_eq!(statusmsg_target("@#staff", None), Some(("@", "#staff")));
        assert_eq!(statusmsg_target("%#staff", None), Some(("%", "#staff")));
        assert_eq!(statusmsg_target("+#staff", None), Some(("+", "#staff")));
        assert_eq!(statusmsg_target("@+#staff", Some("@+")), Some(("@+", "#staff")));
        // A prefix char that is also a channel type: fewer prefix chars are consumed.
        assert_eq!(statusmsg_target("@&local", None), Some(("@", "&local")));
        // Only the announced set counts once STATUSMSG is known.
        assert_eq!(statusmsg_target("%#staff", Some("@+")), None);
        // Not STATUSMSG targets: plain channels, nicks, a bare prefix.
        assert_eq!(statusmsg_target("#staff", None), None);
        assert_eq!(statusmsg_target("+modeless", None), None);
        assert_eq!(statusmsg_target("&local", None), None);
        assert_eq!(statusmsg_target("alice", None), None);
        assert_eq!(statusmsg_target("@#", None), None);
        assert_eq!(statusmsg_target("@", None), None);
        let p = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert_eq!(statusmsg_from_isupport(&p(&["me", "STATUSMSG=@+", "are supported"])).as_deref(), Some("@+"));
        assert_eq!(statusmsg_from_isupport(&p(&["me", "statusmsg=~&@%+"])).as_deref(), Some("~&@%+"));
        assert_eq!(statusmsg_from_isupport(&p(&["me", "STATUSMSG=#ab"])), None);
        assert_eq!(statusmsg_from_isupport(&p(&["me", "PREFIX=(ov)@+"])), None);
    }

    /// r4 (agy P2 ircproto.rs:13): a compliant IRCv3 line — 8191 tag bytes + a 510-byte
    /// message — is read, and its worst-case IPC frame still fits MAX_FRAME_LEN.
    #[tokio::test]
    async fn compliant_tagged_lines_fit_the_reader_and_the_ipc_frame() {
        let tags = format!("@{} ", "a".repeat(8189));
        assert_eq!(tags.len(), 8191);
        let msg = format!(":n!u@h PRIVMSG #c :{}", "m".repeat(510 - ":n!u@h PRIVMSG #c :".len()));
        assert_eq!(msg.len(), 510);
        let mut wire = format!("{}{}\r\n", tags, msg).into_bytes();
        wire.extend_from_slice(b"PING :x\r\n");
        let mut lr = CappedLineReader::new(BufReader::new(&wire[..]));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l.len() == 8701 + 1));
        assert!(matches!(lr.next_line().await.unwrap(), CappedLine::Line(ref l) if l == "PING :x\r"));
        // Worst case for the frame: every byte a control char (6 JSON bytes each).
        let frame = crate::ipc::IpcMessage::RawLine {
            conn_id: "6f1c8a52-2d47-4d4e-9a39-0c1d2e3f4a5b".into(),
            line: "\u{1}".repeat(MAX_IRC_LINE_LEN), replayed: true, backlog: true, recv_ts: i64::MAX, seq: u64::MAX,
        };
        let body = serde_json::to_vec(&frame).unwrap();
        assert!(body.len() < crate::ipc_framing::MAX_FRAME_LEN as usize, "{} bytes", body.len());
    }
}
