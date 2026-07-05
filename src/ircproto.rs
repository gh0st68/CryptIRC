//! ircproto.rs — pure, dependency-free IRC line parsing/formatting primitives.
//!
//! Shared by the `cryptirc` web binary (via `src/irc.rs`) and the `irc-core` daemon
//! binary. Nothing in this module touches `AppState`/`ServerEvent`/`NetworkConfig`
//! or any vault/filesystem state — it only ever transforms strings/bytes, which is
//! exactly what makes it safe to share across the process boundary between the two
//! binaries introduced by the irc-core daemon split.

use std::collections::HashMap;
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// #S7: maximum IRC line length (prevent memory exhaustion from rogue server)
pub const MAX_IRC_LINE_LEN: usize = 8192;

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
/// Pulls from the `BufReader`'s internal buffer via `fill_buf()`/`consume()` and
/// copies at most `MAX_IRC_LINE_LEN + 2` content bytes into an owned buffer. Once
/// that ceiling is hit it keeps consuming (so the connection stays in sync) but
/// stops growing the buffer, then reports `Oversized`.
///
/// (e) LENIENT UTF-8: invalid bytes are decoded lossily (→ U+FFFD) so a single
///     non-UTF-8 byte in a server line (common in MOTD/topic/realname) can never
///     drop the connection.
pub async fn read_capped_line<R>(reader: &mut R) -> std::io::Result<CappedLine>
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
    // (Latin-1/CP1252 in MOTD art, topics, realnames). `from_utf8_lossy` maps
    // invalid bytes to U+FFFD so the line still parses and the connection
    // survives; the downstream CR/LF/NUL stripping and IRC tokenizer are
    // unaffected.
    let line = String::from_utf8_lossy(&buf).into_owned();
    Ok(CappedLine::Line(line))
}

// ─── IRC line parser ──────────────────────────────────────────────────────────

pub struct IrcLine {
    pub prefix: Option<String>,
    pub command: String,
    pub params: Vec<String>,
    pub tags: HashMap<String, String>,
}

pub fn parse_irc(line: &str) -> IrcLine {
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

pub fn strip_pfx(n: &str) -> &str { let s = n.trim_start_matches(|c: char| "@+~&%".contains(c)); if s.is_empty() { n } else { s } }

/// modes, all additive). Only param-taking modes consume a param, in letter order;
/// returns the key if present and not masked ('*'). Best-effort: lets us learn a keyed
/// channel's key on join so auto-rejoin can re-enter it even when we didn't /join with it.
pub fn channel_key_from_modes(modes: &str) -> Option<String> {
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
