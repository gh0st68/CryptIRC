use std::collections::VecDeque;
use std::time::{Duration, Instant};

use cryptirc::ircproto::IrcLine;

use crate::irc::{incoming_channel_target, IrcConnection};
use crate::{AppState, ServerEvent};

pub(crate) const CAP: &str = "cryptirc.com/reactions";
pub(crate) const DISLIKE_CAP: &str = "cryptirc.com/reactions-dislike";
const REPLY: &str = "+reply";
const LEGACY_REPLY: &str = "+draft/reply";
const ADD: &str = "+draft/react";
const REMOVE: &str = "+draft/unreact";
const SEALED: &str = "+cryptirc.com/sealed-reaction";
const EMOJI: &[&str] = &["❤️", "👍", "😂", "🎉", "🔥", "👀", "✅", "🙏", "👎"];
const MAX_ANCHOR_TARGETS: usize = 48;
const MAX_TARGET_ANCHORS: usize = 256;
const MAX_PENDING: usize = 128;
const ECHO_LIFETIME: Duration = Duration::from_secs(15);

#[derive(Default)]
pub(crate) struct Reactions {
    pub(crate) advertised: bool,
    pub(crate) dislike_advertised: bool,
    anchors: VecDeque<(String, VecDeque<Anchor>)>,
    local_echoes: VecDeque<PendingEcho<u64>>,
    wire_echoes: VecDeque<PendingEcho<String>>,
}

struct Anchor {
    reference: String,
    encrypted: bool,
}

struct PendingEcho<T> {
    target: String,
    text: String,
    value: T,
    sent_at: Instant,
}

fn token(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}

pub(crate) fn valid_request_id(value: &str) -> bool {
    value.len() == 36 && token(value, 36)
}

fn valid_reference(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'/' | b'.')
        })
}

fn sealed_token(value: &str) -> bool {
    value.len() >= 12 && value.len() % 4 != 1 && token(value, 900)
}

fn take_echo<T>(entries: &mut VecDeque<PendingEcho<T>>, target: &str, text: &str) -> Option<T> {
    entries.retain(|entry| entry.sent_at.elapsed() < ECHO_LIFETIME);
    let matching = entries
        .iter()
        .position(|entry| entry.target == target && entry.text == text)?;
    entries.remove(matching).map(|entry| entry.value)
}

fn push_echo<T>(entries: &mut VecDeque<PendingEcho<T>>, target: String, text: &str, value: T) {
    if entries.len() == MAX_PENDING {
        entries.pop_front();
    }
    entries.push_back(PendingEcho {
        target,
        text: text.into(),
        value,
        sent_at: Instant::now(),
    });
}

pub(crate) fn refuse_echo(c: &mut IrcConnection, target: &str) {
    let folded = c.casemapping.fold(target);
    c.reactions
        .local_echoes
        .retain(|entry| entry.target != folded);
    c.reactions
        .wire_echoes
        .retain(|entry| entry.target != folded);
}

fn has_plain_anchor(c: &IrcConnection, target: &str, reference: &str) -> bool {
    let target = c.casemapping.fold(target);
    c.reactions
        .anchors
        .iter()
        .find(|(name, _)| *name == target)
        .is_some_and(|(_, anchors)| {
            anchors
                .iter()
                .any(|a| !a.encrypted && a.reference == reference)
        })
}

pub(crate) fn available(c: &IrcConnection) -> bool {
    c.connected
        && c.registered
        && c.message_tags
        && c.echo_message_enabled
        && c.reactions.advertised
}

pub(crate) fn support(c: &IrcConnection) -> (bool, bool) {
    let enabled = available(c);
    (enabled, enabled && c.reactions.dislike_advertised)
}

pub(crate) fn note_capabilities(c: &mut IrcConnection, sub: &str, caps: &str) {
    let has = |name| caps.split_ascii_whitespace().any(|cap| cap == name);
    let reactions = &mut c.reactions;
    match sub {
        "LS" | "NEW" => {
            reactions.advertised |= has(CAP);
            reactions.dislike_advertised |= has(DISLIKE_CAP);
        }
        "DEL" => {
            reactions.dislike_advertised &= !has(DISLIKE_CAP);
            if has(CAP) {
                *reactions = Reactions {
                    dislike_advertised: reactions.dislike_advertised,
                    ..Reactions::default()
                };
            }
        }
        _ => {}
    }
}

fn plain_emoji(c: &IrcConnection, emoji: &str) -> bool {
    EMOJI.contains(&emoji) && (emoji != "👎" || c.reactions.dislike_advertised)
}

pub(crate) fn remember(c: &mut IrcConnection, target: &str, reference: &str, encrypted: bool) {
    if !available(c) || !valid_reference(reference) || target == "status" {
        return;
    }
    let target = c.casemapping.fold(target);
    let mut anchors = c
        .reactions
        .anchors
        .iter()
        .position(|(name, _)| *name == target)
        .and_then(|index| c.reactions.anchors.remove(index))
        .map(|(_, anchors)| anchors)
        .unwrap_or_default();
    if !anchors.iter().any(|a| a.reference == reference) {
        if anchors.len() == MAX_TARGET_ANCHORS {
            anchors.pop_front();
        }
        anchors.push_back(Anchor {
            reference: reference.into(),
            encrypted,
        });
    }
    if c.reactions.anchors.len() == MAX_ANCHOR_TARGETS {
        c.reactions.anchors.pop_front();
    }
    c.reactions.anchors.push_back((target, anchors));
}

pub(crate) fn encrypted_wire(text: &str) -> bool {
    text.starts_with("sd8~") || text.starts_with("[e2edm")
}

pub(crate) fn anchorable_wire(text: &str) -> bool {
    !text.starts_with("[e2ex3dh]")
}

pub(crate) fn own_local(
    c: &mut IrcConnection,
    target: &str,
    text: &str,
    id: u64,
) -> Option<String> {
    if !available(c) || id == 0 || !anchorable_wire(text) {
        return None;
    }
    let target = c.casemapping.fold(target);
    if let Some(reference) = take_echo(&mut c.reactions.wire_echoes, &target, text) {
        return Some(reference);
    }
    push_echo(&mut c.reactions.local_echoes, target, text, id);
    None
}

pub(crate) fn own_wire(
    c: &mut IrcConnection,
    target: &str,
    text: &str,
    reference: &str,
) -> Option<u64> {
    if !available(c) || !valid_reference(reference) || !anchorable_wire(text) {
        return None;
    }
    remember(c, target, reference, encrypted_wire(text));
    let target = c.casemapping.fold(target);
    if let Some(id) = take_echo(&mut c.reactions.local_echoes, &target, text) {
        return Some(id);
    }
    push_echo(&mut c.reactions.wire_echoes, target, text, reference.into());
    None
}

pub(crate) fn anchor_event(
    conn_id: &str,
    target: &str,
    msg_id: u64,
    reference: &str,
) -> Option<ServerEvent> {
    (msg_id != 0 && target != "status" && valid_reference(reference)).then(|| {
        ServerEvent::ReactionAnchor {
            conn_id: conn_id.into(),
            target: target.into(),
            msg_id,
            reference: reference.into(),
        }
    })
}

pub(crate) fn receive(
    c: &IrcConnection,
    line: &IrcLine,
    from: &str,
    replayed: bool,
) -> Option<ServerEvent> {
    if replayed
        || !available(c)
        || line.params.len() != 1
        || from == "*"
        || from.contains('.')
        || from.is_empty()
    {
        return None;
    }
    let target = &line.params[0];
    let own = c.casemapping.fold(from) == c.casemapping.fold(&c.nick);
    let target = match incoming_channel_target(c, target) {
        Some((_, true)) => return None,
        Some((channel, false)) => channel,
        None if own => target.clone(),
        None if c.casemapping.fold(target) == c.casemapping.fold(&c.nick) => from.into(),
        None => return None,
    };
    let add = line.tags.get(ADD);
    let remove = line.tags.get(REMOVE);
    let reply = line.tags.get(REPLY);
    let legacy = line.tags.get(LEGACY_REPLY);
    if reply.is_some() && legacy.is_some() {
        return None;
    }
    let reply = reply.or(legacy);
    let sealed = line.tags.get(SEALED);
    match (add, remove, reply, sealed) {
        (None, None, None, Some(body)) if sealed_token(body) => Some(ServerEvent::SealedReaction {
            conn_id: c.conn_id.clone(),
            target,
            from: from.into(),
            prefix: line.prefix.clone(),
            body: body.clone(),
            own,
        }),
        (Some(emoji), None, Some(reference), None) | (None, Some(emoji), Some(reference), None)
            if plain_emoji(c, emoji) && has_plain_anchor(c, &target, reference) =>
        {
            Some(ServerEvent::IrcReaction {
                conn_id: c.conn_id.clone(),
                target,
                reference: reference.clone(),
                from: from.into(),
                prefix: line.prefix.clone(),
                emoji: emoji.clone(),
                remove: remove.is_some(),
                own,
            })
        }
        _ => None,
    }
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReactionSend {
    Plain {
        reference: String,
        emoji: String,
        remove: bool,
    },
    Sealed {
        body: String,
    },
}

pub(crate) async fn send(
    state: &AppState,
    username: &str,
    conn_id: &str,
    target: &str,
    reaction: ReactionSend,
) -> Result<(), &'static str> {
    const REFUSED: &str = "Reaction could not be sent.";
    if !state.owns_conn(username, conn_id)
        || !crate::is_plausible_target(target)
        || target == "status"
        || target.contains(',')
        || target.starts_with([':', '$'])
    {
        return Err(REFUSED);
    }
    let conn = state
        .connections
        .get(conn_id)
        .map(|c| c.clone())
        .ok_or(REFUSED)?;
    let (channels, peers) = state
        .e2e_store
        .protected_names(username)
        .await
        .map_err(|_| REFUSED)?;
    let protected = crate::match_e2e_target(target, conn_id, channels, peers).is_some();
    let mut c = conn.lock().await;
    let channel_target = incoming_channel_target(&c, target);
    if !available(&c)
        || !state.owns_conn(username, conn_id)
        || channel_target
            .as_ref()
            .is_some_and(|(_, restricted)| *restricted)
        || (channel_target.is_none() && target.contains('@'))
    {
        return Err(REFUSED);
    }
    let tag = match reaction {
        ReactionSend::Plain {
            reference,
            emoji,
            remove,
        } if !protected && plain_emoji(&c, &emoji) => {
            if !has_plain_anchor(&c, target, &reference) {
                return Err(REFUSED);
            }
            let action = if remove { REMOVE } else { ADD };
            format!("{REPLY}={reference};{action}={emoji}")
        }
        ReactionSend::Sealed { body } if protected && sealed_token(&body) => {
            format!("{SEALED}={body}")
        }
        _ => return Err(REFUSED),
    };
    c.send_raw(&format!("@{tag} TAGMSG {target}"))
        .await
        .map_err(|_| REFUSED)
}
