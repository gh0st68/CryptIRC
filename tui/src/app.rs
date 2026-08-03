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
}

impl Buffer {
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
}

pub struct Prompt {
    pub label: String,
    pub value: String,
    pub masked: bool,
    pub kind: PromptKind,
}

#[derive(PartialEq)]
pub enum PromptKind { Vault }

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
        });
        self.rebuild_order();
        self.buffers.len() - 1
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
        let mut nets: Vec<String> = Vec::new();
        for b in self.buffers.iter() {
            if !nets.iter().any(|n| n == &b.conn_id) { nets.push(b.conn_id.clone()); }
        }
        let mut order = Vec::with_capacity(self.buffers.len());
        for cid in nets {
            if let Some(i) = self.buffers.iter().position(|b| b.conn_id == cid && b.target.is_empty()) {
                order.push(i);
            }
            let mut chans: Vec<usize> = Vec::new();
            let mut dms: Vec<usize> = Vec::new();
            for (i, b) in self.buffers.iter().enumerate() {
                if b.conn_id != cid || b.target.is_empty() { continue; }
                if b.is_channel() { chans.push(i) } else { dms.push(i) }
            }
            chans.sort_by_key(|i| self.buffers[*i].label.to_lowercase());
            dms.sort_by_key(|i| self.buffers[*i].label.to_lowercase());
            order.extend(chans);
            order.extend(dms);
        }
        // Anything orphaned (no status buffer for its conn) still has to be
        // reachable, or it would vanish from every index.
        for i in 0..self.buffers.len() {
            if !order.contains(&i) { order.push(i); }
        }
        self.display_order = order;
    }

    /// Switch by the number shown in the list (1-based display position).
    pub fn switch_to_display(&mut self, n1: usize) {
        if n1 == 0 { return; }
        if let Some(&idx) = self.display_order.get(n1 - 1) { self.switch_to(idx); }
    }

    pub fn next_buffer(&mut self) {
        if self.buffers.is_empty() { return; }
        let n = (self.current + 1) % self.buffers.len();
        self.switch_to(n);
    }
    pub fn prev_buffer(&mut self) {
        if self.buffers.is_empty() { return; }
        let n = if self.current == 0 { self.buffers.len() - 1 } else { self.current - 1 };
        self.switch_to(n);
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
        let cands: Vec<String> = b.names.iter()
            .map(|n| n.trim_start_matches(['~', '&', '@', '%', '+']).to_string())
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
