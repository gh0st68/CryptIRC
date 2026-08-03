//! Rendering. Layout is weechat's: buffer list left, chat centre, nick list
//! right, a status bar, then the input line.
//!
//! The renderer also records where the buffer-list rows landed
//! (`app.buflist_hits`) so the mouse handler can map a click back to a buffer
//! without duplicating the layout arithmetic. Deriving hit targets from the
//! ACTUAL draw is what stops the two drifting apart when the layout changes.

use ratatui::prelude::*;
use ratatui::widgets::*;
use unicode_width::UnicodeWidthStr;
use crate::app::{App, LineKind};
use crate::theme::Theme;

/// Colour a nick deterministically from the active theme's palette — same nick,
/// same colour, every session, and always inside the theme's own hues.
pub fn nick_color(th: &Theme, nick: &str) -> Color {
    // Simple FNV-1a; we only need stability, not distribution quality.
    let mut h: u32 = 2166136261;
    for b in nick.as_bytes() {
        h ^= *b as u32;
        h = h.wrapping_mul(16777619);
    }
    th.nicks[(h as usize) % th.nicks.len()]
}

fn hhmm(ts: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(ts, 0) {
        chrono::LocalResult::Single(t) => t.format("%H:%M").to_string(),
        _ => "--:--".to_string(),
    }
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),   // topic
            Constraint::Min(1),      // body
            Constraint::Length(1),   // status
            Constraint::Length(1),   // input
        ])
        .split(f.size());

    draw_topic(f, root[0], app);

    // Side panels collapse on a narrow terminal rather than squeezing the chat
    // into an unreadable column.
    let w = root[1].width;
    let show_buf = app.show_buflist && w >= 60;
    let show_nick = app.show_nicklist && w >= 80
        && app.cur().map(|b| b.is_channel()).unwrap_or(false);
    let mut cons: Vec<Constraint> = Vec::new();
    if show_buf { cons.push(Constraint::Length(20)); }
    cons.push(Constraint::Min(10));
    if show_nick { cons.push(Constraint::Length(18)); }
    let body = Layout::default().direction(Direction::Horizontal).constraints(cons).split(root[1]);

    let mut i = 0;
    if show_buf { draw_buflist(f, body[i], app); i += 1; } else { app.buflist_hits.clear(); }
    draw_chat(f, body[i], app);
    i += 1;
    if show_nick { draw_nicklist(f, body[i], app); }

    draw_status(f, root[2], app);
    draw_input(f, root[3], app);
}

fn draw_topic(f: &mut Frame, area: Rect, app: &App) {
    let (label, topic) = match app.cur() {
        Some(b) => (b.label.clone(), b.topic.clone()),
        None => (String::from("cryptirc"), String::new()),
    };
    let th = &app.theme;
    let line = Line::from(vec![
        Span::styled(format!(" {} ", label), Style::default().fg(th.accent_fg).bg(th.accent).add_modifier(Modifier::BOLD)),
        Span::raw(" "),
        Span::styled(topic, Style::default().fg(th.dim)),
    ]);
    f.render_widget(Paragraph::new(line).style(Style::default().bg(th.bg)), area);
}

fn draw_buflist(f: &mut Frame, area: Rect, app: &mut App) {
    let th = app.theme.clone();
    // Consumes App::display_order — it does NOT define it. The order must stay
    // valid when this pane is hidden or too narrow to draw, which is why it lives
    // in state. Rows scroll around the selection so no buffer can become
    // unreachable just because the list is taller than the pane.
    app.buflist_hits.clear();
    let order = app.display_order.clone();
    let h = area.height as usize;
    let sel_pos = order.iter().position(|i| *i == app.current).unwrap_or(0);
    let start = if order.len() <= h { 0 } else { sel_pos.saturating_sub(h / 2).min(order.len() - h) };

    let mut items: Vec<ListItem> = Vec::new();
    let mut row = area.y;
    for (pos, &i) in order.iter().enumerate().skip(start).take(h) {
        let Some(b) = app.buffers.get(i) else { continue };
        let sel = i == app.current;
        let num = pos + 1;                       // the number Alt+N takes
        app.buflist_hits.push((row, i));
        if b.target.is_empty() {
            // Network header: connection dot + name, like the web sidebar.
            let online = *app.connected.get(&b.conn_id).unwrap_or(&false);
            let name_style = if sel {
                Style::default().fg(th.accent_fg).bg(th.accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(th.accent).add_modifier(Modifier::BOLD)
            };
            items.push(ListItem::new(Line::from(vec![
                Span::styled(if online { "● " } else { "○ " },
                    Style::default().fg(if online { th.online } else { th.dim })),
                Span::styled(format!("{:>2} ", num), Style::default().fg(th.dim)),
                Span::styled(b.label.clone(), name_style),
            ])));
        } else {
            let (marker, mut style) = match b.activity {
                2 => ("*", Style::default().fg(th.highlight).add_modifier(Modifier::BOLD)),
                1 => ("+", Style::default().fg(th.fg)),
                _ => (" ", Style::default().fg(th.dim)),
            };
            if sel { style = Style::default().fg(th.accent_fg).bg(th.accent).add_modifier(Modifier::BOLD); }
            items.push(ListItem::new(Line::from(vec![
                // Indented under its network header, mirroring the web sidebar.
                Span::styled(format!("{}  {:>2} ", marker, num), style),
                Span::styled(b.label.clone(), style),
            ])));
        }
        row += 1;
    }

    let list = List::new(items).block(
        Block::default().borders(Borders::RIGHT).border_style(Style::default().fg(th.border))
    ).style(Style::default().bg(th.bg));
    f.render_widget(list, area);
}

fn draw_chat(f: &mut Frame, area: Rect, app: &mut App) {
    let width = area.width.saturating_sub(1) as usize;
    let cur = app.current;
    let Some(buf) = app.buffers.get(cur) else {
        f.render_widget(Paragraph::new("no buffers — /join #channel")
            .style(Style::default().fg(app.theme.fg).bg(app.theme.bg)), area);
        return;
    };
    // Total rendered rows for THIS width. Computed first so the scroll clamp is
    // against reality; without it the oldest part of a wrapped buffer was
    // unreachable because the clamps used the message count instead.
    let mut total_rows = 0usize;
    for l in buf.lines.iter() {
        let head = hhmm(l.ts).width() + 1 + match l.kind {
            LineKind::Msg | LineKind::Own => l.from.width() + 2,
            LineKind::Action => l.from.width() + 3,
            LineKind::Notice => l.from.width() + 2,
            LineKind::Status | LineKind::Error => 4,
        } + 1;
        total_rows += wrap(&l.text, width.saturating_sub(head).max(8)).len();
    }
    // Build from the newest backwards until the viewport is full, honouring the
    // scroll offset. Wrapping is done here (not by Paragraph) because we need an
    // exact line count to scroll by rendered rows rather than by messages — a
    // single long message must not jump the view by a whole screen.
    let th = app.theme.clone();
    let mut rows: Vec<Line> = Vec::new();
    let height = area.height as usize;
    let skip = buf.scroll;
    let mut taken = 0usize;
    for l in buf.lines.iter().rev() {
        let ts = hhmm(l.ts);
        let (prefix, body_style) = match l.kind {
            LineKind::Msg    => (Span::styled(format!("<{}>", l.from), Style::default().fg(nick_color(&th, &l.from))), Style::default().fg(th.fg)),
            LineKind::Own    => (Span::styled(format!("<{}>", l.from), Style::default().fg(th.own).add_modifier(Modifier::BOLD)), Style::default().fg(th.own)),
            LineKind::Action => (Span::styled(format!(" * {}", l.from), Style::default().fg(th.action)), Style::default().fg(th.action)),
            LineKind::Notice => (Span::styled(format!("-{}-", l.from), Style::default().fg(th.notice)), Style::default().fg(th.notice)),
            LineKind::Status => (Span::styled(" -!-".to_string(), Style::default().fg(th.dim)), Style::default().fg(th.dim)),
            LineKind::Error  => (Span::styled(" !! ".to_string(), Style::default().fg(th.error).add_modifier(Modifier::BOLD)), Style::default().fg(th.error)),
        };
        let head_w = ts.width() + 1 + prefix.content.width() + 1;
        let avail = width.saturating_sub(head_w).max(8);
        let wrapped = wrap(&l.text, avail);
        // Emit in reverse so continuation rows sit UNDER their first row once the
        // whole list is flipped back at the end.
        for (n, seg) in wrapped.iter().enumerate().rev() {
            if taken >= skip + height { break; }
            taken += 1;
            if taken <= skip { continue; }
            rows.push(if n == 0 {
                Line::from(vec![
                    Span::styled(format!("{} ", ts), Style::default().fg(th.dim)),
                    prefix.clone(),
                    Span::raw(" "),
                    Span::styled(seg.clone(), body_style),
                ])
            } else {
                Line::from(vec![
                    Span::raw(" ".repeat(head_w)),
                    Span::styled(seg.clone(), body_style),
                ])
            });
        }
        if taken >= skip + height { break; }
    }
    rows.reverse();
    f.render_widget(Paragraph::new(rows).style(Style::default().bg(th.bg)), area);
    // Publish for the scroll clamps, and correct a scroll that now overshoots
    // (e.g. after a resize made lines wrap differently).
    if let Some(b) = app.buffers.get_mut(cur) {
        b.total_rows = total_rows;
        let max = total_rows.saturating_sub(1);
        if b.scroll > max { b.scroll = max; }
    }
}

/// Wrap on whitespace, falling back to a hard split for a single word longer
/// than the line (a URL). Operates on chars so a multi-byte glyph is never cut
/// in half.
fn wrap(s: &str, width: usize) -> Vec<String> {
    if width == 0 { return vec![s.to_string()]; }
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut cur_w = 0usize;
    for word in s.split(' ') {
        let ww = word.width();
        if ww > width {
            if !cur.is_empty() { out.push(std::mem::take(&mut cur)); cur_w = 0; }
            let mut piece = String::new();
            let mut pw = 0;
            for ch in word.chars() {
                let cw = ch.to_string().width();
                if pw + cw > width { out.push(std::mem::take(&mut piece)); pw = 0; }
                piece.push(ch); pw += cw;
            }
            if !piece.is_empty() { cur = piece; cur_w = pw; }
            continue;
        }
        if cur_w == 0 { cur = word.to_string(); cur_w = ww; }
        else if cur_w + 1 + ww <= width { cur.push(' '); cur.push_str(word); cur_w += 1 + ww; }
        else { out.push(std::mem::take(&mut cur)); cur = word.to_string(); cur_w = ww; }
    }
    if !cur.is_empty() || out.is_empty() { out.push(cur); }
    out
}

fn draw_nicklist(f: &mut Frame, area: Rect, app: &App) {
    let th = &app.theme;
    let Some(b) = app.cur() else { return };
    let mut names = b.names.clone();
    // Ops first, then voiced, then the rest — each alphabetical, as clients do.
    fn rank(n: &str) -> u8 {
        match n.chars().next() {
            Some('~') => 0, Some('&') => 1, Some('@') => 2, Some('%') => 3, Some('+') => 4, _ => 5,
        }
    }
    names.sort_by(|a, b| rank(a).cmp(&rank(b))
        .then_with(|| a.trim_start_matches(['~','&','@','%','+']).to_lowercase()
            .cmp(&b.trim_start_matches(['~','&','@','%','+']).to_lowercase())));
    let items: Vec<ListItem> = names.iter().map(|n| {
        let (pfx, rest) = match n.chars().next() {
            Some(c @ ('~'|'&'|'@'|'%'|'+')) => (c.to_string(), &n[c.len_utf8()..]),
            _ => (" ".to_string(), n.as_str()),
        };
        let pc = match pfx.as_str() { "~"|"&"|"@" => th.notice, "%" => th.nicks[2], "+" => th.online, _ => th.dim };
        ListItem::new(Line::from(vec![
            Span::styled(pfx, Style::default().fg(pc)),
            Span::styled(rest.to_string(), Style::default().fg(nick_color(&th, rest))),
        ]))
    }).collect();
    let title = format!(" {} ", names.len());
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::LEFT).title(title)
            .border_style(Style::default().fg(th.border))).style(Style::default().bg(th.bg)),
        area,
    );
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let th = &app.theme;
    let now = chrono::Local::now().format("%H:%M").to_string();
    let (conn, nick, target, lag) = match app.cur() {
        Some(b) => (
            *app.connected.get(&b.conn_id).unwrap_or(&false),
            app.our_nick(&b.conn_id).to_string(),
            b.label.clone(),
            app.lag.get(&b.conn_id).copied().flatten(),
        ),
        None => (false, app.username.clone(), String::new(), None),
    };
    let sb = Style::default().fg(th.status_fg).bg(th.status_bg);
    let mut spans = vec![
        Span::styled(format!("[{}]", now), sb),
        Span::styled(format!("[{}]", nick), sb),
        Span::styled(format!("[{}]", target), sb),
    ];
    if !conn {
        spans.push(Span::styled("[disconnected]", Style::default().fg(th.bg).bg(th.error).add_modifier(Modifier::BOLD)));
    }
    if !app.vault_unlocked {
        spans.push(Span::styled("[vault locked]", Style::default().fg(th.status_fg).bg(th.nicks[2])));
    }
    if let Some(ms) = lag {
        spans.push(Span::styled(format!("[lag {}ms]", ms), sb));
    }
    // Activity list, weechat-style: the buffers with unread traffic. Numbers are
    // DISPLAY positions so they match the list and what Alt+N takes — using the
    // storage index here made the status bar cite a number that pointed at a
    // different channel.
    let act: Vec<String> = app.display_order.iter().enumerate()
        .filter(|(_, idx)| **idx != app.current
            && app.buffers.get(**idx).map(|b| b.activity > 0).unwrap_or(false))
        .map(|(pos, _)| (pos + 1).to_string()).collect();
    if !act.is_empty() {
        spans.push(Span::styled(format!("[Act: {}]", act.join(",")), sb));
    }
    if !app.status.is_empty() {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(app.status.clone(), Style::default().fg(th.status_fg).bg(th.status_bg).add_modifier(Modifier::BOLD)));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).style(Style::default().bg(th.status_bg)),
        area,
    );
}

fn draw_input(f: &mut Frame, area: Rect, app: &App) {
    let th = &app.theme;
    if let Some(p) = &app.prompt {
        let shown = if p.masked { "*".repeat(p.value.chars().count()) } else { p.value.clone() };
        f.render_widget(Paragraph::new(Line::from(vec![
            Span::styled(format!("{} ", p.label), Style::default().fg(th.nicks[2]).add_modifier(Modifier::BOLD)),
            Span::styled(shown.clone(), Style::default().fg(th.fg)),
        ])).style(Style::default().bg(th.bg)), area);
        let x = area.x + (p.label.width() + 1 + shown.width()) as u16;
        f.set_cursor(x.min(area.x + area.width.saturating_sub(1)), area.y);
        return;
    }
    let nick = app.cur().map(|b| app.our_nick(&b.conn_id).to_string()).unwrap_or_else(|| app.username.clone());
    let prompt = format!("[{}] ", nick);
    // Horizontal scroll: keep the caret on screen for input longer than the
    // terminal is wide, instead of truncating and freezing the cursor at the
    // right edge (which meant typing blind past ~74 columns).
    let avail = (area.width as usize).saturating_sub(prompt.width()).max(1);
    let before = &app.input[..app.cursor.min(app.input.len())];
    let before_w = before.width();
    // Drop whole chars off the front until the caret fits.
    let mut off = 0usize;
    let mut shown_w = before_w;
    if shown_w >= avail {
        for (i, ch) in before.char_indices() {
            if shown_w < avail { off = i; break; }
            shown_w -= ch.to_string().width();
            off = i + ch.len_utf8();
        }
    }
    let tail = &app.input[off.min(app.input.len())..];
    f.render_widget(Paragraph::new(Line::from(vec![
        Span::styled(prompt.clone(), Style::default().fg(th.online)),
        Span::styled(tail.to_string(), Style::default().fg(th.fg)),
    ])).style(Style::default().bg(th.bg)), area);
    // Caret measured in DISPLAY columns, not bytes.
    let x = area.x + (prompt.width() + before.width().saturating_sub(before_w - shown_w.min(before_w))) as u16;
    f.set_cursor(x.min(area.x + area.width.saturating_sub(1)), area.y);
}
