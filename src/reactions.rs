use std::collections::VecDeque;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
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
const PENDING_RECEIPT_TTL: Duration = Duration::from_secs(60);
const MAX_RECEIPTS: usize = 128;

#[derive(Default)]
pub(crate) struct Reactions {
    pub(crate) advertised: bool,
    pub(crate) dislike_advertised: bool,
    pub(crate) labeled_response: bool,
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
    value.len() == 36 && uuid::Uuid::parse_str(value).is_ok()
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
    // Each Signal or shared-key send has distinct ciphertext. A paced IRC
    // connection can echo it after the ordinary text window has elapsed.
    entries.retain(|entry| {
        entry.sent_at.elapsed() < ECHO_LIFETIME
            || entry.text.starts_with("[e2edm2]")
            || entry.text.starts_with("sd8~")
    });
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
        "ACK" | "LIST" => {
            if has("labeled-response") { reactions.labeled_response = true; }
            if has("-labeled-response") { reactions.labeled_response = false; }
        }
        "LS" | "NEW" => {
            reactions.advertised |= has(CAP);
            reactions.dislike_advertised |= has(DISLIKE_CAP);
        }
        "DEL" => {
            reactions.labeled_response &= !has("labeled-response");
            reactions.dislike_advertised &= !has(DISLIKE_CAP);
            if has(CAP) {
                *reactions = Reactions {
                    dislike_advertised: reactions.dislike_advertised,
                    labeled_response: reactions.labeled_response,
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
    // Callers supply a real IRC message target, including users nicknamed status.
    if !available(c) || !valid_reference(reference) {
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
    (msg_id != 0 && valid_reference(reference)).then(|| {
        ServerEvent::ReactionAnchor {
            conn_id: conn_id.into(),
            target: target.into(),
            msg_id,
            reference: reference.into(),
        }
    })
}

pub(crate) async fn receive(
    state: &AppState,
    username: &str,
    conn: &tokio::sync::Mutex<IrcConnection>,
    line: &IrcLine,
    from: &str,
    replayed: bool,
    backlog: bool,
    received_at: i64,
) -> Option<ServerEvent> {
    let c = conn.lock().await;
    if (replayed && !backlog) || line.tags.contains_key("batch")
        || line.params.len() != 1
        || from == "*"
        || from.contains('.')
        || from.is_empty()
    {
        return None;
    }
    let target = &line.params[0];
    let own = c.casemapping.fold(from) == c.casemapping.fold(&c.echo_nick(replayed));
    let mut display = !replayed && available(&c);
    if !display && !own { return None; }
    let target = match incoming_channel_target(&c, target) {
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
    let (mut event, wire) = match (add, remove, reply, sealed) {
        (None, None, None, Some(body)) if sealed_token(body) => (ServerEvent::SealedReaction {
            conn_id: c.conn_id.clone(),
            target: target.clone(),
            from: from.into(),
            prefix: line.prefix.clone(),
            body: body.clone(),
            own,
            receipt: None,
        }, sealed_reaction_tags(body)),
        (Some(emoji), None, Some(reference), None) | (None, Some(emoji), Some(reference), None)
            if EMOJI.contains(&emoji.as_str()) && valid_reference(reference) =>
        {
            display &= plain_emoji(&c, emoji) && has_plain_anchor(&c, &target, reference);
            (ServerEvent::IrcReaction {
                conn_id: c.conn_id.clone(),
                target: target.clone(),
                reference: reference.clone(),
                from: from.into(),
                prefix: line.prefix.clone(),
                emoji: emoji.clone(),
                remove: remove.is_some(),
                own,
                receipt: None,
            }, plain_reaction_tags(reference, emoji, remove.is_some()))
        }
        _ => return None,
    };
    if own {
        let target = c.casemapping.fold(&target);
        let conn_id = c.conn_id.clone();
        drop(c);
        // Only a live echo or an unprocessed core backlog line can settle an
        // outstanding click. Historical replay and IRC history batches cannot.
        match confirm_echo(state, username, &conn_id, &target, &wire, line.tags.get("label").map(String::as_str), received_at).await {
            Ok(Some(confirmation)) if !display => return Some(ServerEvent::ReactionReceipts {
                conn_id, receipts: vec![confirmation], retry_after_ms: None,
            }),
            Ok(Some(confirmation)) => match &mut event {
                ServerEvent::IrcReaction { receipt, .. } | ServerEvent::SealedReaction { receipt, .. } => *receipt = Some(confirmation),
                _ => {}
            },
            Ok(None) => {}
            Err(error) => tracing::warn!(%error, "could not save IRC reaction confirmation"),
        }
    }
    display.then_some(event)
}

fn plain_reaction_tags(reference: &str, emoji: &str, remove: bool) -> String {
    let action = if remove { REMOVE } else { ADD };
    format!("{REPLY}={reference};{action}={emoji}")
}

fn sealed_reaction_tags(body: &str) -> String {
    format!("{SEALED}={body}")
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ReactionReceipt {
    request_id: String,
    // Older clients read this wire field to order confirmed toggles. Keep the
    // name when decoding existing files and when talking to those clients.
    #[serde(rename = "expires_at")]
    order: i64,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct StoredReceipt {
    conn_id: String,
    #[serde(flatten)]
    receipt: ReactionReceipt,
}

fn receipt_path(state: &AppState, username: &str) -> PathBuf {
    PathBuf::from(&state.data_dir).join("users").join(crate::safe_username(username)).join("reaction-receipts.json")
}

async fn read_receipts(path: &Path) -> io::Result<Vec<StoredReceipt>> {
    let contents = match tokio::fs::read(path).await {
        Ok(contents) => contents,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut receipts: Vec<StoredReceipt> = serde_json::from_slice(&contents)?;
    // A sleeping phone may be the only device with the pending action. Keep
    // the account's most recent confirmations across an idle night or longer.
    if receipts.len() > MAX_RECEIPTS { receipts.drain(..receipts.len() - MAX_RECEIPTS); }
    Ok(receipts)
}

async fn record_receipt_locked(state: &AppState, username: &str, conn_id: &str, id: &str) -> io::Result<ReactionReceipt> {
    if !state.owns_conn(username, conn_id) || !state.auth.account_exists(username).await {
        return Err(io::Error::new(io::ErrorKind::NotFound, "reaction receipt account or network removed"));
    }
    let path = receipt_path(state, username);
    let now = chrono::Utc::now().timestamp_millis();
    let mut receipts = read_receipts(&path).await?;
    if let Some(existing) = receipts.iter().find(|entry| entry.conn_id == conn_id && entry.receipt.request_id == id) {
        return Ok(existing.receipt.clone());
    }
    // A restored confirmation can arrive after a newer live toggle. Continue
    // ordering from the last stored value, including across a web upgrade.
    let order = receipts.last().map_or(now, |entry| now.max(entry.receipt.order.saturating_add(1)));
    let receipt = ReactionReceipt { request_id: id.into(), order };
    receipts.push(StoredReceipt { conn_id: conn_id.into(), receipt: receipt.clone() });
    if receipts.len() > MAX_RECEIPTS {
        receipts.drain(..receipts.len() - MAX_RECEIPTS);
    }
    if let Some(dir) = path.parent() { tokio::fs::create_dir_all(dir).await?; }
    crate::write_secret_json_atomic(&path, &serde_json::to_value(receipts)?).await?;
    Ok(receipt)
}

#[derive(serde::Deserialize, serde::Serialize)]
struct OutstandingReaction {
    conn_id: String,
    request_id: String,
    sent_at: i64,
    digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

impl OutstandingReaction {
    fn matches_echo(&self, conn_id: &str, digest: &str, label: Option<&str>, received: i64) -> bool {
        self.conn_id == conn_id && self.digest == digest && self.label.as_deref() == label
            && received.saturating_add(999) >= self.sent_at
            && received <= self.sent_at.saturating_add(PENDING_RECEIPT_TTL.as_millis() as i64)
    }
}

fn wire_digest(target: &str, wire: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(target.as_bytes());
    hash.update([0]);
    hash.update(wire.as_bytes());
    format!("{:x}", hash.finalize())
}

async fn outstanding(path: &Path) -> io::Result<Vec<OutstandingReaction>> {
    match tokio::fs::read(path).await {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error),
    }
}

async fn save_outstanding(path: &Path, rows: &[OutstandingReaction]) -> io::Result<()> {
    if rows.is_empty() {
        return match tokio::fs::remove_file(path).await {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result,
        };
    }
    if let Some(dir) = path.parent() { tokio::fs::create_dir_all(dir).await?; }
    crate::write_secret_json_atomic(path, &serde_json::to_value(rows)?).await
}

async fn confirm_echo(state: &AppState, username: &str, conn_id: &str, target: &str, wire: &str, label: Option<&str>, recv_ts: i64) -> io::Result<Option<ReactionReceipt>> {
    let lock = state.auth.user_lock(username);
    let _held = lock.lock().await;
    let path = receipt_path(state, username).with_file_name("reaction-pending.json");
    let mut rows = outstanding(&path).await?;
    if rows.is_empty() { return Ok(None); }
    let digest = wire_digest(target, wire);
    // The IRC core timestamps in seconds. Compare when the line really arrived,
    // including when a replacement web process handles it much later.
    let received = if recv_ts > 0 { recv_ts.saturating_mul(1000) } else { chrono::Utc::now().timestamp_millis() };
    let index = rows.iter().position(|row| row.matches_echo(conn_id, &digest, label, received));
    let Some(index) = index else { return Ok(None); };
    let row = rows.remove(index);
    // Commit the confirmation first. Reprocessing after an interruption between
    // these writes is idempotent for the same opaque request ID.
    let receipt = record_receipt_locked(state, username, conn_id, &row.request_id).await?;
    if let Err(error) = save_outstanding(&path, &rows).await {
        tracing::warn!(%error, "could not remove completed reaction request");
    }
    Ok(Some(receipt))
}

pub(crate) async fn clear_receipts(state: &AppState, username: &str) -> io::Result<()> {
    let lock = state.auth.user_lock(username);
    let _held = lock.lock().await;
    let path = receipt_path(state, username);
    for file in [&path, &path.with_file_name("reaction-pending.json")] {
        match tokio::fs::remove_file(file).await {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        }
    }
    Ok(())
}

pub(crate) async fn refuse_labeled(state: &AppState, username: &str, conn_id: &str, label: &str) -> io::Result<()> {
    if !label.starts_with("cr-") || label.len() != 35 { return Ok(()); }
    let lock = state.auth.user_lock(username);
    let _held = lock.lock().await;
    let path = receipt_path(state, username).with_file_name("reaction-pending.json");
    let mut rows = outstanding(&path).await?;
    if let Some(i) = rows.iter().position(|row| row.conn_id == conn_id && row.label.as_deref() == Some(label)) {
        let request_id = rows.remove(i).request_id;
        save_outstanding(&path, &rows).await?;
        state.send_to_user(username, ServerEvent::ReactionResult { request_id, error: Some("IRC refused this reaction.".into()) });
    }
    Ok(())
}

pub(crate) async fn requested_receipts(state: &AppState, username: &str, conn_id: &str, ids: &[String]) -> Vec<ReactionReceipt> {
    if ids.is_empty() || ids.len() > MAX_RECEIPTS || ids.iter().any(|id| !valid_request_id(id)) ||
        !state.owns_network(username, conn_id).await { return Vec::new(); }
    let path = receipt_path(state, username);
    read_receipts(&path).await.unwrap_or_default().into_iter()
        .filter(|entry| entry.conn_id == conn_id && ids.contains(&entry.receipt.request_id))
        .map(|entry| entry.receipt).collect()
}

#[cfg(test)]
mod receipt_tests {
    use super::*;

    #[test]
    fn paced_signal_echo_matches_its_exact_target_and_ciphertext_once() {
        let mut pending = VecDeque::new();
        push_echo(&mut pending, "peer".into(), "[e2edm2]first", 7);
        push_echo(&mut pending, "peer".into(), "hello", 8);
        for entry in &mut pending {
            entry.sent_at = Instant::now() - ECHO_LIFETIME - Duration::from_secs(1);
        }
        assert_eq!(take_echo(&mut pending, "peer", "hello"), None);
        assert_eq!(take_echo(&mut pending, "another", "[e2edm2]first"), None);
        assert_eq!(take_echo(&mut pending, "peer", "[e2edm2]second"), None);
        assert_eq!(take_echo(&mut pending, "peer", "[e2edm2]first"), Some(7));
        assert_eq!(take_echo(&mut pending, "peer", "[e2edm2]first"), None);
    }

    #[test]
    fn delayed_shared_key_echo_anchors_the_exact_send_in_either_arrival_order() {
        // Two channelEncrypt sends of "hi" under the same disposable key.
        let first = "sd8~eyJ2IjoyLCJuIjoiV1NtK01JYmpxZHVDZkFnUyIsImMiOiJvS2RtMC80YTd5QXU1cVVXeW5zOGNVeVAiLCJ0IjoxNzk1Nzg2Nzk5fQ==";
        let second = "sd8~eyJ2IjoyLCJuIjoiand4MGpvNUtodVdsS29jZiIsImMiOiJWYjIxVzhrMlBTMmtodkltSmxSTHBnRWkiLCJ0IjoxNzk1Nzg2Nzk5fQ==";
        let mut conn = IrcConnection::for_test("fixture", "Alice", "fixture.invalid", 6667);
        conn.message_tags = true;
        conn.echo_message_enabled = true;
        conn.reactions.advertised = true;
        let delay = ECHO_LIFETIME + Duration::from_secs(1);

        assert_eq!(own_local(&mut conn, "#Room", first, 7), None);
        conn.reactions.local_echoes[0].sent_at -= delay;
        assert_eq!(own_wire(&mut conn, "#else", first, "other-room"), None);
        assert_eq!(own_wire(&mut conn, "#room", second, "msg-two"), None);
        conn.reactions.wire_echoes.back_mut().unwrap().sent_at -= delay;
        assert_eq!(own_wire(&mut conn, "#room", first, "msg-one"), Some(7));
        assert_eq!(own_local(&mut conn, "#Room", second, 8).as_deref(), Some("msg-two"));
        assert_eq!(own_wire(&mut conn, "#room", first, "msg-one"), None);
        assert_eq!(own_local(&mut conn, "#Room", second, 8), None);
    }

    #[test]
    fn confirmation_requires_the_same_connection_label_wire_and_arrival_window() {
        let digest = wire_digest("#one", "+reply=message;+draft/react=❤️");
        let mut pending = OutstandingReaction { conn_id: "route".into(), request_id: "request".into(),
            sent_at: 10_450, digest: digest.clone(), label: Some("opaque".into()) };
        assert!(pending.matches_echo("route", &digest, Some("opaque"), 10_000));
        assert!(!pending.matches_echo("different route", &digest, Some("opaque"), 11_000));
        assert!(!pending.matches_echo("route", &digest, Some("other"), 11_000));
        assert!(!pending.matches_echo("route", &digest, None, 11_000));
        assert!(!pending.matches_echo("route", &wire_digest("#two", "+reply=message;+draft/react=❤️"), Some("opaque"), 11_000));
        assert!(!pending.matches_echo("route", &digest, Some("opaque"), 9_000));
        assert!(!pending.matches_echo("route", &digest, Some("opaque"), 71_000));
        pending.label = None;
        assert!(pending.matches_echo("route", &digest, None, 11_000));
    }

    #[tokio::test]
    async fn keeps_the_most_recent_confirmations_when_the_account_has_been_idle() {
        let path = std::env::temp_dir().join(format!("cryptirc-receipts-{}", uuid::Uuid::new_v4()));
        let yesterday = chrono::Utc::now().timestamp_millis() - 86_400_000;
        let stored: Vec<_> = (0..MAX_RECEIPTS + 2).map(|i| serde_json::json!({
            "conn_id": "fixture", "request_id": uuid::Uuid::from_u128(i as u128 + 1).to_string(),
            "expires_at": yesterday + i as i64
        })).collect();
        tokio::fs::write(&path, serde_json::to_vec(&stored).unwrap()).await.unwrap();
        let restored = read_receipts(&path).await;
        tokio::fs::remove_file(path).await.unwrap();
        let restored = restored.unwrap();
        assert_eq!(restored.len(), MAX_RECEIPTS);
        assert_eq!(restored[0].receipt.order, yesterday + 2);
        assert_eq!(restored.last().unwrap().receipt.order, yesterday + MAX_RECEIPTS as i64 + 1);
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        e2e_identity_revision: Option<String>,
    },
}

pub(crate) async fn send(
    state: &AppState,
    username: &str,
    conn_id: &str,
    target: &str,
    request_id: String,
    reaction: ReactionSend,
    outdated_browser: bool,
) -> Result<(), &'static str> {
    const REFUSED: &str = "Reaction could not be sent.";
    if !state.owns_conn(username, conn_id)
        || !crate::is_plausible_target(target)
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
    let user_lock = state.auth.user_lock(username);
    let _held = user_lock.lock().await;
    if !state.auth.account_exists(username).await { return Err(REFUSED); }
    // Sealed Signal and shared-key reactions use distinct wire prefixes.
    // A Signal reaction can wait for its local journal while a sibling rotates.
    let _identity_permit = match &reaction {
        ReactionSend::Sealed { body, e2e_identity_revision } if sealed_token(body) &&
            URL_SAFE_NO_PAD.decode(body).is_ok_and(|wire| wire.starts_with(b"e2r1:")) =>
                Some(state.e2e_store.signal_delivery_permit(username, e2e_identity_revision.as_deref(), outdated_browser).await
                    .map_err(|_| "Reaction not sent. Your encryption identity changed. Reopen the conversation and try again.")?),
        _ => None,
    };
    // Without an identity permit (which already holds the account's slot lock), read
    // the protected names under that lock and keep it through the IRC handoff, so a
    // concurrent protection change is ordered before or after this reaction.
    let (_protection_permit, (channels, peers)) = if _identity_permit.is_some() {
        (None, state.e2e_store.protected_names(username).await.map_err(|_| REFUSED)?)
    } else {
        let (guard, channels, peers) = state.e2e_store.protected_names_permit(username).await.map_err(|_| REFUSED)?;
        (Some(guard), (channels, peers))
    };
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
            plain_reaction_tags(&reference, &emoji, remove)
        }
        ReactionSend::Sealed { body, .. } if protected && sealed_token(&body) => {
            sealed_reaction_tags(&body)
        }
        _ => return Err(REFUSED),
    };
    let folded = c.casemapping.fold(target);
    let confirmed = receipt_path(state, username);
    if read_receipts(&confirmed).await.map_err(|_| REFUSED)?.iter().any(|row|
        row.conn_id == conn_id && row.receipt.request_id == request_id) { return Ok(()); }
    let path = confirmed.with_file_name("reaction-pending.json");
    let mut pending = outstanding(&path).await.map_err(|_| REFUSED)?;
    let digest = wire_digest(&folded, &tag);
    let now = chrono::Utc::now().timestamp_millis();
    let lifetime = PENDING_RECEIPT_TTL.as_millis() as i64;
    if let Some(prior) = pending.iter().find(|row| row.conn_id == conn_id && row.request_id == request_id) {
        return if prior.digest == digest { Ok(()) } else { Err(REFUSED) };
    }
    if pending.iter().any(|row| row.conn_id == conn_id && row.digest == digest && now.saturating_sub(row.sent_at) <= lifetime) {
        return Err("Waiting for IRC to confirm this reaction.");
    }
    if pending.len() >= MAX_PENDING {
        let expired = pending.iter().position(|row| now.saturating_sub(row.sent_at) > lifetime)
            .ok_or("Waiting for IRC to confirm earlier reactions.")?;
        pending.remove(expired);
    }
    // A negotiated IRCv3 label is echoed only to the sender. The stored tuple
    // binds that unpredictable label to its account, connection and exact wire.
    let label = c.reactions.labeled_response.then(|| format!("cr-{}", uuid::Uuid::new_v4().simple()));
    let line = match &label {
        Some(value) => format!("@label={value};{tag} TAGMSG {target}"),
        None => format!("@{tag} TAGMSG {target}"),
    };
    pending.push(OutstandingReaction { conn_id: conn_id.into(), request_id, sent_at: now, digest, label });
    save_outstanding(&path, &pending).await.map_err(|_| REFUSED)?;
    if c.send_raw(&line).await.is_err() {
        pending.pop();
        let _ = save_outstanding(&path, &pending).await;
        return Err(REFUSED);
    }
    Ok(())
}
