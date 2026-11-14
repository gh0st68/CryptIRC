//! Client-side state: buffers, the buffer list, activity flags, input editing.
//!
//! The server is the source of truth for membership and topics (it sends a full
//! `State` snapshot); this only holds what a terminal needs to draw.

use std::collections::HashMap;
use crate::theme::Theme;

/// One rendered line. Kept pre-split from the wire event so the renderer never
/// has to know about protocol shapes.
#[derive(Clone)]
pub struct Line {
    pub ts: i64,
    pub from: String,
    pub text: String,
    pub kind: LineKind,
    /// Server-assigned id. 0 means "no id" (status lines, and replayed history —
    /// the server deliberately stamps replays with 0). Used for dedup.
    pub id: u64,
}

#[derive(Clone, Copy, PartialEq)]
pub enum LineKind { Msg, Action, Notice, Own, Status, Error }

/// A window: one channel, one DM, or a network's status buffer.
pub struct Buffer {
    pub conn_id: String,
    /// Channel name, nick, or "" for the network status buffer.
    pub target: String,
    pub label: String,
    pub topic: String,
    pub names: Vec<String>,
    pub lines: Vec<Line>,
    /// Rows (NOT messages) scrolled up from the bottom. 0 = pinned to newest.
    /// A wrapped message occupies several rows, so this must never be clamped
    /// against `lines.len()`.
    pub scroll: usize,
    /// Total RENDERED rows at the last draw, published by the renderer because it
    /// is the only place that knows the wrap width. `scroll` is clamped against
    /// this. 0 until the buffer has been drawn once.
    pub total_rows: usize,
    /// Highest activity seen since last visited: 0 none, 1 chatter, 2 highlight.
    pub activity: u8,
    /// Set once we have asked the server for history, so switching buffers
    /// repeatedly does not re-request it every time.
    pub history_asked: bool,
    /// An older page (GetLogs with `before`) is in flight. Kept apart from
    /// `history_asked`: sharing that flag made every wire event during a page
    /// fetch re-send the initial fetch, whose newest lines were then PREPENDED
    /// above the ones already on screen.
    pub page_pending: bool,
    /// The last page brought nothing new: the start of the history is reached,
    /// so stop asking on every key press at the top.
    pub history_end: bool,
}

impl Buffer {
    #[cfg(test)]
    pub fn test_new(conn_id: &str, target: &str) -> Buffer {
        Buffer { conn_id: conn_id.into(), target: target.into(), label: target.into(), topic: String::new(), names: Vec::new(),
                 lines: Vec::new(), scroll: 0, total_rows: 0, activity: 0, history_asked: false, page_pending: false, history_end: false }
    }

    pub fn is_channel(&self) -> bool {
        self.target.starts_with(['#', '&', '+', '!'])
    }
    pub fn push(&mut self, l: Line) {
        // Dedup by server id. The same message legitimately arrives twice in one
        // situation: we send it, the server echoes it to ALL our sessions
        // including this one. Both carry the same msg_id, so this catches it.
        if l.id != 0 && self.lines.iter().rev().take(200).any(|x| x.id == l.id) {
            return;
        }
        self.lines.push(l);
        // Bound memory on a long-running client. 5000 lines of scrollback is far
        // more than a terminal can show and keeps a week-long session flat.
        if self.lines.len() > 5000 {
            let drop = self.lines.len() - 5000;
            self.lines.drain(0..drop);
            self.scroll = self.scroll.saturating_sub(drop);
        }
    }
}

pub struct App {
    pub username: String,
    pub buffers: Vec<Buffer>,
    pub current: usize,
    pub input: String,
    /// Byte index of the caret within `input`. Byte-based, but only ever moved
    /// to char boundaries — see `move_left`/`move_right`.
    pub cursor: usize,
    pub history: Vec<String>,
    pub history_pos: Option<usize>,
    pub nicks: HashMap<String, String>,   // conn_id -> our nick
    pub connected: HashMap<String, bool>,
    pub lag: HashMap<String, Option<u64>>,
    pub vault_unlocked: bool,
    pub status: String,
    /// Set while a modal prompt is up (vault passphrase). Input is masked and
    /// Enter routes to the prompt instead of the channel.
    pub prompt: Option<Prompt>,
    pub show_nicklist: bool,
    pub show_buflist: bool,
    /// Rects of the buffer-list rows, recomputed each frame, so a mouse click
    /// can be mapped back to a buffer index without the renderer and the input
    /// handler having to agree on layout arithmetic separately.
    pub buflist_hits: Vec<(u16, usize)>,   // (screen row, buffer index)
    /// Buffer indices in DISPLAY order. Derived from state by `rebuild_order()`,
    /// NOT published by the renderer — a renderer-published order was empty
    /// before the first frame, empty forever on a terminal too narrow to draw the
    /// list, stale once the list was hidden, and truncated when it overflowed,
    /// each of which silently broke Alt+N and `/buffer N`.
    pub display_order: Vec<usize>,
    /// Active colour theme. Every colour the renderer draws comes from here.
    pub theme: Theme,
    /// Tab-cycle state: (word start, original partial, candidate index, text written).
    pub complete_state: Option<(usize, String, usize, String)>,
    pub should_quit: bool,
    /// /cycle requests waiting for a State snapshot (see run_pending_cycles).
    pub pending_cycles: Vec<PendingCycle>,
    /// r5: this TUI submitted the vault passphrase and awaits the server's answer.
    pub unlock_submitted: bool,
    /// Each network's CASEMAPPING, once known (the server's State says it, or a 005 line
    /// seen live). Absent = unknown. See `saved_channel_key`.
    pub casemap: HashMap<String, CaseMap>,
    /// Channels we asked to join whose JOIN the server has not confirmed yet: a State
    /// taken before the confirmation does not list them, and must not close their window.
    pub pending_joins: Vec<PendingJoin>,
    /// Frames produced while handling a server event (handle_event has no
    /// sender); the run loop sends them right after the event batch.
    pub outbox: Vec<crate::proto::ClientMessage>,
    /// r6: each network's channels in the latest State (wide fold) — windows for them are
    /// not counted against MAX_AUTO_BUFFERS_PER_NET.
    pub joined: HashMap<String, std::collections::HashSet<String>>,
    /// r6: networks whose *overflow* window has been announced.
    pub overflow_noticed: std::collections::HashSet<String>,
}

/// r6 (codex P2 tui/src/app.rs:239): at most this many windows per network are opened by
/// INCOMING lines (private messages, or channels we are not in). Past it a new conversation
/// goes to the network's one OVERFLOW_BUF window, prefixed with its target — as the server
/// logs it. Opening a window yourself (/msg, /query, /join) is never refused.
pub const MAX_AUTO_BUFFERS_PER_NET: usize = 200;
pub const OVERFLOW_BUF: &str = "*overflow*";

pub struct Prompt {
    pub label: String,
    pub value: String,
    pub masked: bool,
    pub kind: PromptKind,
}

#[derive(PartialEq)]
pub enum PromptKind {
    Vault,
    /// r5 (codex P2 tui/src/main.rs:706 HIGH): the vault was unlocked by another session
    /// while this passphrase prompt was up and before it was submitted. The prompt stays
    /// (masked) so that a passphrase pasted / typed right now still lands HERE and not in
    /// the chat line; Enter or Esc closes it and whatever was typed is discarded.
    VaultUnlockedElsewhere,
}

/// A /cycle waiting for the fresh State that tells us the channel's saved key.
pub struct PendingCycle {
    pub conn_id: String,
    pub channel: String,
    pub asked: std::time::Instant,
}

/// A /join waiting for the server's confirmation (see `App::pending_joins`).
pub struct PendingJoin {
    pub conn_id: String,
    pub channel: String,
    pub asked: std::time::Instant,
}

/// How long a /join's window survives State snapshots that do not list it yet.
pub const JOIN_GRACE: std::time::Duration = std::time::Duration::from_secs(30);

/// A server's ISUPPORT CASEMAPPING, the same three rules the server uses
/// (../src/ircproto.rs CaseMapping): which channel names are the same channel.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CaseMap { Rfc1459, StrictRfc1459, Ascii }

impl CaseMap {
    /// A CASEMAPPING token (unknown tokens fold letters only, like the server).
    pub fn from_token(v: &str) -> Self {
        match v.to_ascii_lowercase().as_str() {
            "rfc1459" => CaseMap::Rfc1459,
            "strict-rfc1459" | "rfc1459-strict" => CaseMap::StrictRfc1459,
            _ => CaseMap::Ascii,
        }
    }
    pub fn fold(self, s: &str) -> String {
        s.chars().map(|c| match (self, c) {
            (_, 'A'..='Z') => c.to_ascii_lowercase(),
            (CaseMap::Rfc1459 | CaseMap::StrictRfc1459, '[') => '{',
            (CaseMap::Rfc1459 | CaseMap::StrictRfc1459, ']') => '}',
            (CaseMap::Rfc1459 | CaseMap::StrictRfc1459, '\\') => '|',
            (CaseMap::Rfc1459, '~') => '^',
            _ => c,
        }).collect()
    }
}

/// The widest fold any server uses (Unicode lowercase + RFC1459 specials): two names
/// that differ under it are different channels on every server; equal ones may be one.
pub fn wide_fold(s: &str) -> String { CaseMap::Rfc1459.fold(&s.to_lowercase()) }

impl App {
    pub fn new(username: String) -> Self {
        Self {
            username,
            buffers: Vec::new(),
            current: 0,
            input: String::new(),
            cursor: 0,
            history: Vec::new(),
            history_pos: None,
            nicks: HashMap::new(),
            connected: HashMap::new(),
            lag: HashMap::new(),
            vault_unlocked: false,
            status: String::new(),
            prompt: None,
            show_nicklist: true,
            show_buflist: true,
            buflist_hits: Vec::new(),
            display_order: Vec::new(),
            theme: crate::theme::default_theme(),
            complete_state: None,
            should_quit: false,
            pending_cycles: Vec::new(),
            unlock_submitted: false,
            casemap: HashMap::new(),
            pending_joins: Vec::new(),
            outbox: Vec::new(),
            joined: HashMap::new(),
            overflow_noticed: std::collections::HashSet::new(),
        }
    }

    pub fn our_nick(&self, conn_id: &str) -> &str {
        self.nicks.get(conn_id).map(|s| s.as_str()).unwrap_or(&self.username)
    }

    /// Find a buffer, or create it. Channel and nick lookups are
    /// case-insensitive because IRC is: `#Dev` and `#dev` are one channel, and a
    /// server may echo either casing (this is the exact bug class that produced
    /// duplicate/empty channels in the web client's history).
    pub fn buf_index(&mut self, conn_id: &str, target: &str, label_hint: Option<&str>) -> usize {
        if let Some(i) = self.buffers.iter().position(|b| {
            b.conn_id == conn_id && b.target.eq_ignore_ascii_case(target)
        }) {
            return i;
        }
        // (order is rebuilt by the caller-visible push below)
        self.buffers.push(Buffer {
            conn_id: conn_id.to_string(),
            target: target.to_string(),
            label: label_hint.unwrap_or(target).to_string(),
            topic: String::new(),
            names: Vec::new(),
            lines: Vec::new(),
            scroll: 0,
            total_rows: 0,
            activity: 0,
            history_asked: false,
            page_pending: false,
            history_end: false,
        });
        self.rebuild_order();
        self.buffers.len() - 1
    }

    /// r6: the window an INCOMING line for `target` goes to — buf_index, except that a NEW
    /// window for a private message or a channel we are not in (nor joining) counts against
    /// MAX_AUTO_BUFFERS_PER_NET; past it the line goes to the network's OVERFLOW_BUF window
    /// (returns true: the caller prefixes the line with its target).
    pub fn event_buf(&mut self, conn_id: &str, target: &str, label_hint: Option<&str>) -> (usize, bool) {
        if let Some(i) = self.find_buf(conn_id, target) { return (i, false); }
        let chosen_channel = |app: &App, t: &str| t.starts_with(['#', '&', '+', '!'])
            && (app.join_pending(conn_id, t) || app.joined.get(conn_id).is_some_and(|j| j.contains(&wide_fold(t))));
        if target.is_empty() || chosen_channel(self, target) {
            return (self.buf_index(conn_id, target, label_hint), false);
        }
        let auto = self.buffers.iter()
            .filter(|b| b.conn_id == conn_id && !b.target.is_empty() && !chosen_channel(self, &b.target))
            .count();
        if auto < MAX_AUTO_BUFFERS_PER_NET { return (self.buf_index(conn_id, target, label_hint), false); }
        let i = self.buf_index(conn_id, OVERFLOW_BUF, Some(OVERFLOW_BUF));
        if self.overflow_noticed.insert(conn_id.to_string()) {
            let text = format!("too many new conversations on this network ({} windows) — new ones are shown here, \
                prefixed with their nick or channel; /msg <nick> opens a window for one", MAX_AUTO_BUFFERS_PER_NET);
            self.status = format!("⚠ {}", text);
            if let Some(b) = self.buffers.get_mut(i) {
                b.push(Line { ts: chrono::Utc::now().timestamp(), from: String::new(), text, kind: LineKind::Status, id: 0 });
            }
        }
        (i, true)
    }

    pub fn cur(&self) -> Option<&Buffer> { self.buffers.get(self.current) }
    pub fn cur_mut(&mut self) -> Option<&mut Buffer> { self.buffers.get_mut(self.current) }

    /// Record a line and raise the buffer's activity flag unless it is the one on
    /// screen. `highlight` marks it as a mention.
    pub fn add_line(&mut self, idx: usize, line: Line, highlight: bool) {
        self.add_line_ex(idx, line, highlight, false)
    }

    /// `replayed` lines are the daemon's ring-buffer history re-sent after a web
    /// restart. They belong in scrollback but are NOT new activity — without this
    /// every buffer lit up unread on every server restart.
    pub fn add_line_ex(&mut self, idx: usize, line: Line, highlight: bool, replayed: bool) {
        let is_current = idx == self.current;
        if let Some(b) = self.buffers.get_mut(idx) {
            // Anchor scrollback: if the user has scrolled up, keep their view
            // pinned to the same message instead of shifting it under them.
            let scrolled = b.scroll > 0;
            let before = b.lines.len();
            b.push(line);
            // Keep the reader anchored on the same text. We do not know the new
            // message's wrapped height here (that needs the render width), so
            // approximate by one row and let the renderer's clamp correct it on
            // the next frame — an under-estimate drifts at most a row, where the
            // previous message-vs-row mismatch drifted a whole message.
            if scrolled && b.lines.len() > before { b.scroll += 1; }
            if !is_current && !replayed {
                let want = if highlight { 2 } else { 1 };
                if b.activity < want { b.activity = want; }
            }
        }
    }

    /// Scroll by rows, clamped to what the renderer actually produced. `max` of
    /// total_rows means the top of the buffer is always reachable.
    pub fn scroll_by(&mut self, delta: isize) {
        if let Some(b) = self.buffers.get_mut(self.current) {
            let max = b.total_rows.saturating_sub(1).max(b.lines.len());
            let next = b.scroll as isize + delta;
            b.scroll = next.clamp(0, max as isize) as usize;
        }
    }
    pub fn scroll_to_top(&mut self) {
        if let Some(b) = self.buffers.get_mut(self.current) {
            b.scroll = b.total_rows.saturating_sub(1).max(b.lines.len());
        }
    }
    pub fn scroll_to_bottom(&mut self) {
        if let Some(b) = self.buffers.get_mut(self.current) { b.scroll = 0; }
    }

    /// Remove a buffer and keep `current` pointing at something sensible.
    /// Removing by index shifts everything after it, so `current` has to move
    /// with it — otherwise closing a buffer above the active one silently
    /// switches you to a different channel.
    pub fn remove_buffer(&mut self, idx: usize) {
        if idx >= self.buffers.len() { return; }
        self.buffers.remove(idx);
        if self.buffers.is_empty() { self.current = 0; self.rebuild_order(); return; }
        let moved = self.current == idx;
        if self.current > idx { self.current -= 1; }
        else if self.current == idx { self.current = idx.min(self.buffers.len() - 1); }
        // Only reset the view when we actually landed on a DIFFERENT buffer.
        // Doing it unconditionally snapped you to the bottom of whatever you were
        // reading whenever some OTHER buffer was removed.
        if moved {
            if let Some(b) = self.buffers.get_mut(self.current) { b.activity = 0; b.scroll = 0; }
        }
        self.rebuild_order();
    }

    /// The server confirmed our JOIN of `channel` (agy P2 tui/src/main.rs:708): it is no
    /// longer pending. If its window was opened under another spelling of the same name
    /// (`/join #chan[1]` answered with `JOIN #chan{1}` on an RFC1459 network) and none has
    /// the server's spelling yet, that window takes the server's spelling — instead of a
    /// second window opening next to an empty one.
    pub fn confirm_join(&mut self, conn_id: &str, channel: &str) {
        let wf = wide_fold(channel);
        let typed: Vec<String> = self.pending_joins.iter()
            .filter(|p| p.conn_id == conn_id && wide_fold(&p.channel) == wf)
            .map(|p| p.channel.clone()).collect();
        self.pending_joins.retain(|p| !(p.conn_id == conn_id && wide_fold(&p.channel) == wf));
        if self.find_buf(conn_id, channel).is_some() { return; }
        if let Some(i) = typed.iter().find_map(|t| self.find_buf(conn_id, t)) {
            self.buffers[i].target = channel.to_string();
            self.buffers[i].label = channel.to_string();
            self.rebuild_order();
        }
    }

    /// Is a /join of `channel` (any spelling of the same name) still awaiting its
    /// confirmation, within JOIN_GRACE?
    pub fn join_pending(&self, conn_id: &str, channel: &str) -> bool {
        let wf = wide_fold(channel);
        self.pending_joins.iter().any(|p| p.conn_id == conn_id && p.asked.elapsed() <= JOIN_GRACE && wide_fold(&p.channel) == wf)
    }

    /// Index of a buffer if it already exists — unlike `buf_index`, never creates one.
    pub fn find_buf(&self, conn_id: &str, target: &str) -> Option<usize> {
        self.buffers.iter().position(|b| b.conn_id == conn_id && b.target.eq_ignore_ascii_case(target))
    }

    pub fn switch_to(&mut self, idx: usize) {
        if idx < self.buffers.len() {
            self.current = idx;
            if let Some(b) = self.buffers.get_mut(idx) {
                b.activity = 0;
                b.scroll = 0;
            }
        }
    }

    /// Recompute display order: networks in first-seen order, each followed by
    /// its channels then its DMs, both alphabetical. This is the single source of
    /// truth for the numbers shown, Alt+N, `/buffer N` and the activity list.
    pub fn rebuild_order(&mut self) {
        // r6 (codex P2 tui/src/app.rs:395): one pass to group, a sort per group, and a
        // placed-flag for the leftovers — it used to rescan every buffer per network and
        // run `order.contains` per buffer (quadratic in the number of windows).
        struct Group { status: Option<usize>, chans: Vec<usize>, dms: Vec<usize> }
        let mut nets: Vec<String> = Vec::new();
        let mut groups: HashMap<String, Group> = HashMap::new();
        for (i, b) in self.buffers.iter().enumerate() {
            let g = groups.entry(b.conn_id.clone()).or_insert_with(|| {
                nets.push(b.conn_id.clone());
                Group { status: None, chans: Vec::new(), dms: Vec::new() }
            });
            if b.target.is_empty() {
                if g.status.is_none() { g.status = Some(i); }
            } else if b.is_channel() { g.chans.push(i) } else { g.dms.push(i) }
        }
        let mut order = Vec::with_capacity(self.buffers.len());
        let mut placed = vec![false; self.buffers.len()];
        for cid in nets {
            let Some(mut g) = groups.remove(&cid) else { continue };
            if let Some(i) = g.status { order.push(i); placed[i] = true; }
            g.chans.sort_by_cached_key(|i| self.buffers[*i].label.to_lowercase());
            g.dms.sort_by_cached_key(|i| self.buffers[*i].label.to_lowercase());
            for i in g.chans.into_iter().chain(g.dms) { order.push(i); placed[i] = true; }
        }
        // Anything left (a second network buffer for the same conn) still has to be
        // reachable, or it would vanish from every index.
        for (i, done) in placed.iter().enumerate() {
            if !done { order.push(i); }
        }
        self.display_order = order;
    }

    /// Switch by the number shown in the list (1-based display position).
    pub fn switch_to_display(&mut self, n1: usize) {
        if n1 == 0 { return; }
        if let Some(&idx) = self.display_order.get(n1 - 1) { self.switch_to(idx); }
    }

    /// r6 (agy P2 tui/src/app.rs:409): next / previous in the DISPLAY order (the list on
    /// screen), not in storage order, which jumped between unrelated networks and windows.
    pub fn next_buffer(&mut self) { self.step_buffer(1); }
    pub fn prev_buffer(&mut self) { self.step_buffer(-1); }
    fn step_buffer(&mut self, dir: isize) {
        if self.buffers.is_empty() { return; }
        if self.display_order.len() != self.buffers.len() { self.rebuild_order(); }
        let n = self.display_order.len() as isize;
        let pos = self.display_order.iter().position(|&i| i == self.current).map_or(0, |p| p as isize);
        let next = self.display_order[(pos + dir).rem_euclid(n) as usize];
        self.switch_to(next);
    }

    // ── Input editing. All indices are byte offsets kept on char boundaries so
    // multi-byte input (emoji, accents) can never panic on a slice. ──────────
    pub fn insert(&mut self, c: char) {
        self.input.insert(self.cursor, c);
        self.cursor += c.len_utf8();
    }
    pub fn backspace(&mut self) {
        if self.cursor == 0 { return; }
        let prev = self.input[..self.cursor].chars().next_back().map(|c| c.len_utf8()).unwrap_or(1);
        let at = self.cursor - prev;
        self.input.remove(at);
        self.cursor = at;
    }
    pub fn delete(&mut self) {
        if self.cursor >= self.input.len() { return; }
        self.input.remove(self.cursor);
    }
    pub fn move_left(&mut self) {
        if self.cursor == 0 { return; }
        let prev = self.input[..self.cursor].chars().next_back().map(|c| c.len_utf8()).unwrap_or(1);
        self.cursor -= prev;
    }
    pub fn move_right(&mut self) {
        if self.cursor >= self.input.len() { return; }
        let next = self.input[self.cursor..].chars().next().map(|c| c.len_utf8()).unwrap_or(1);
        self.cursor += next;
    }
    pub fn take_input(&mut self) -> String {
        let s = std::mem::take(&mut self.input);
        self.cursor = 0;
        if !s.trim().is_empty() {
            self.history.push(s.clone());
            if self.history.len() > 200 { self.history.remove(0); }
        }
        self.history_pos = None;
        s
    }
    pub fn history_up(&mut self) {
        if self.history.is_empty() { return; }
        let n = match self.history_pos {
            None => self.history.len() - 1,
            Some(0) => 0,
            Some(i) => i - 1,
        };
        self.history_pos = Some(n);
        self.input = self.history[n].clone();
        self.cursor = self.input.len();
    }
    pub fn history_down(&mut self) {
        match self.history_pos {
            Some(i) if i + 1 < self.history.len() => {
                self.history_pos = Some(i + 1);
                self.input = self.history[i + 1].clone();
            }
            Some(_) => { self.history_pos = None; self.input.clear(); }
            None => {}
        }
        self.cursor = self.input.len();
    }

    /// Tab-complete a nick, CYCLING through candidates on repeated presses.
    /// A plain `find()` returned whatever order the server sent NAMES in, so a
    /// channel with `bobby` before `bob` made `bob` unreachable — pressing Tab
    /// again did nothing, because the inserted trailing space left an empty
    /// partial.
    pub fn complete_nick(&mut self) {
        let Some(b) = self.buffers.get(self.current) else { return };
        // Continuing an existing cycle? Recognise it by the text we last wrote.
        let cont = self.complete_state.as_ref()
            .map(|(start, partial, _, written)| {
                *start + written.len() == self.cursor
                    && self.input.get(*start..self.cursor).map(|t| t == written).unwrap_or(false)
                    && !partial.is_empty()
            })
            .unwrap_or(false);
        let (start, partial, next_idx) = if cont {
            let (s0, p0, idx, _) = self.complete_state.clone().unwrap();
            (s0, p0, idx + 1)
        } else {
            let head = &self.input[..self.cursor];
            let s0 = head.rfind(' ').map(|i| i + 1).unwrap_or(0);
            (s0, head[s0..].to_string(), 0)
        };
        if partial.is_empty() { return; }
        let lower = partial.to_lowercase();
        // Names come from the server and the chosen one is written into the
        // input line (which is drawn to the terminal), so sanitise it first.
        let cands: Vec<String> = b.names.iter()
            .map(|n| crate::sanitize::clean(n.trim_start_matches(['~', '&', '@', '%', '+'])).into_owned())
            .filter(|n| n.to_lowercase().starts_with(&lower))
            .collect();
        if cands.is_empty() { self.complete_state = None; return; }
        let nick = &cands[next_idx % cands.len()];
        // Start of line gets the "nick: " convention, elsewhere a bare nick.
        let suffix = if start == 0 { ": " } else { " " };
        let written = format!("{}{}", nick, suffix);
        self.input.replace_range(start..self.cursor, &written);
        self.cursor = start + written.len();
        self.complete_state = Some((start, partial, next_idx % cands.len(), written));
    }
}
