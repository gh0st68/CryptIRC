use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

use crate::e2e::FetchedBundle;
use crate::irc::IrcConnection;
use crate::{AppState, ServerEvent};
use cryptirc::ircproto::{nick_from_prefix, IrcLine};
use tokio::sync::Mutex;

pub(crate) const CAP: &str = "cryptirc.com/e2e";
pub(crate) const TAG: &str = "+cryptirc.com/e2e";
pub(crate) const NO_TAGS_NUMERIC: &str = "794";
pub(crate) const SIGNAL_SUGGESTION: &str = "CryptIRC: I suggest using Signal encryption for our private chat. Open Encryption in our DM to review. This notice does not change your settings.";
const MAX_BUNDLE: usize = 1200;
const REQUEST_TTL: Duration = Duration::from_millis(1500);
// IRC flood pacing can delay the answer behind the contact's preceding chat.
// Manual setup and pinned peers can wait longer than first-contact discovery.
const KNOWN_PEER_TTL: Duration = Duration::from_secs(25);
const REPLY_WINDOW: Duration = Duration::from_secs(60);
const SETUP_NOTICE_WINDOW: Duration = Duration::from_secs(600);
// The existing b frame accepts opaque base64url data. Older clients ignore
// this marker as a non-bundle and retain their discovery timeout behavior.
const SETUP_REQUIRED: &[u8] = b"cryptirc-e2e-setup-required-v1";
const BUNDLE_UNAVAILABLE: &[u8] = b"cryptirc-e2e-unavailable-v1";

#[derive(Default)]
pub(crate) struct Bridge {
    pub(crate) advertised: bool,
    pending: Vec<(String, String, Instant)>,
    replies: Vec<(String, Instant)>,
    busy_replies: Vec<(String, Instant)>,
    setup_notices: Vec<(String, Instant)>,
    method_notices: Vec<(String, Instant)>,
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub(crate) fn valid_nick(nick: &str) -> bool {
    let mut bytes = nick.bytes();
    nick.len() <= 64
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b"[]\\`_^{|}".contains(&b))
        && bytes.all(|b| b.is_ascii_alphanumeric() || b"[]\\`_^{|}-".contains(&b))
}

fn supported(c: &IrcConnection) -> bool {
    c.connected && c.registered && c.message_tags && c.e2e_bridge.advertised
}

pub(crate) fn cancel_pending(state: &AppState, username: &str, c: &mut IrcConnection) {
    for (req, _, _) in c.e2e_bridge.pending.drain(..) {
        state.send_to_user(username, ServerEvent::E2EBundleMissing {
            conn_id: c.conn_id.clone(), req, reason: "unavailable",
        });
    }
}

pub(crate) fn signal_suggestion(c: &mut IrcConnection, from: &str, target: &str) -> bool {
    if !c.connected || !c.registered || !valid_nick(from) || !valid_nick(target) { return false; }
    let sender = c.casemapping.fold(from);
    let own = c.casemapping.fold(&c.nick);
    if sender == own || c.casemapping.fold(target) != own { return false; }
    let notices = &mut c.e2e_bridge.method_notices;
    notices.retain(|(_, at)| at.elapsed() < REPLY_WINDOW);
    if notices.len() >= 4 || notices.iter().any(|(nick, _)| nick == &sender) { return false; }
    notices.push((sender, Instant::now()));
    true
}

pub(crate) fn notify_setup(
    state: &AppState, username: &str, conn: &mut IrcConnection, from: &str, prefix: Option<&str>,
) {
    if !conn.connected || !conn.registered || !valid_nick(from) { return; }
    let sender = conn.casemapping.fold(from);
    if sender == conn.casemapping.fold(&conn.nick) { return; }
    let notices = &mut conn.e2e_bridge.setup_notices;
    notices.retain(|(_, at)| at.elapsed() < SETUP_NOTICE_WINDOW);
    let recent = notices.iter().filter(|(_, at)| at.elapsed() < REPLY_WINDOW);
    if notices.len() >= 12 || recent.clone().count() >= 4 || recent.clone().any(|(nick, _)| nick == &sender) { return; }
    notices.push((sender, Instant::now()));
    state.send_to_user(username, ServerEvent::E2ESetupNeeded {
        conn_id: conn.conn_id.clone(), from: from.into(), prefix: prefix.map(str::to_owned),
    });
}

pub(crate) async fn request(state: &AppState, username: &str, conn: Arc<Mutex<IrcConnection>>, nick: &str, id: &str, wait_for_peer: bool) -> Result<bool, &'static str> {
    let mut c = conn.lock().await;
    if !c.connected || !c.registered { return Err("unavailable"); }
    if !c.e2e_bridge.advertised { return Ok(false); }
    if !c.message_tags { return Err("unavailable"); }
    if !valid_nick(nick) || !valid_id(id) || c.casemapping.fold(nick) == c.casemapping.fold(&c.nick) {
        return Err("unavailable");
    }
    if c.e2e_bridge.pending.len() >= 16 || c.e2e_bridge.pending.iter().any(|(request_id, _, _)| request_id == id) {
        return Err("unavailable");
    }
    if state.auth.check_ws_kdf_rate_limit(username, "e2e_bundle").is_err() { return Err("rate-limited"); }
    c.send_raw(&format!("@{TAG}=q.{id} TAGMSG {nick}")).await.map_err(|_| "unavailable")?;
    let deadline = Instant::now() + if wait_for_peer { KNOWN_PEER_TTL } else { REQUEST_TTL };
    let registration = c.registration_epoch;
    let req = id.to_owned();
    c.e2e_bridge.pending.push((req.clone(), nick.to_owned(), deadline));
    drop(c);
    let state = state.clone();
    let username = username.to_owned();
    tokio::spawn(async move {
        tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
        let mut c = conn.lock().await;
        let Some(i) = c.e2e_bridge.pending.iter().position(|(id, _, expires)| id == &req && *expires == deadline) else { return };
        c.e2e_bridge.pending.swap_remove(i);
        let reason = if supported(&c) && c.registration_epoch == registration { "unconfirmed" } else { "unavailable" };
        state.send_to_user(&username, ServerEvent::E2EBundleMissing { conn_id: c.conn_id.clone(), req, reason });
    });
    Ok(true)
}

/// The recipient's UnrealIRCd can confirm that the current connection cannot
/// receive the tags this bridge requires. Silence alone never qualifies.
pub(crate) fn accept_no_tags(state: &AppState, username: &str, c: &mut IrcConnection, line: &IrcLine) {
    if !supported(c) || line.tags.contains_key("batch")
        || !line.prefix.as_deref().is_some_and(|prefix| prefix.contains('.') && !prefix.contains(['!', '@']))
    { return; }
    let [recipient, nick, req, marker] = line.params.as_slice() else { return };
    let mapping = c.casemapping;
    if marker != "CRYPTIRC-NO-TAGS" || !valid_id(req) || !valid_nick(nick) || mapping.fold(recipient) != mapping.fold(&c.nick) {
        return;
    }
    if let Some(index) = c.e2e_bridge.pending.iter().position(|(id, peer, deadline)|
        id == req && mapping.fold(peer) == mapping.fold(nick) && Instant::now() < *deadline)
    {
        let (req, _, _) = c.e2e_bridge.pending.swap_remove(index);
        state.send_to_user(username, ServerEvent::E2EBundleMissing {
            conn_id: c.conn_id.clone(), req, reason: "peer-no-bridge",
        });
    }
}

/// Stop discovery when the live IRC server reports a missing nickname.
pub(crate) fn refuse_offline_lookup(state: &AppState, username: &str, c: &mut IrcConnection, line: &IrcLine) {
    if !supported(c) || line.tags.contains_key("batch")
        || !line.prefix.as_deref().is_some_and(|prefix| !prefix.is_empty() && !prefix.contains(['!', '@']))
    { return; }
    let [recipient, nick, ..] = line.params.as_slice() else { return };
    let mapping = c.casemapping;
    if !valid_nick(nick) || mapping.fold(recipient) != mapping.fold(&c.nick) { return; }
    let target = mapping.fold(nick);
    let now = Instant::now();
    let conn_id = &c.conn_id;
    // A bare 401 identifies the nick, but carries no request ID. Leave all
    // other lookups on this connection untouched.
    c.e2e_bridge.pending.retain(|(req, nick, expires)| {
        if *expires <= now || mapping.fold(nick) != target { return true; }
        state.send_to_user(username, ServerEvent::E2EBundleMissing {
            conn_id: conn_id.clone(), req: req.clone(), reason: "peer-offline",
        });
        false
    });
}

/// Consume the bridge TAGMSG separately from regular messages and history.
pub(crate) async fn receive(state: &AppState, username: &str, conn: &Mutex<IrcConnection>, line: &IrcLine) {
    let Some(value) = line.tags.get(TAG) else { return };
    let Some(target) = line.params.first() else { return };
    let from = nick_from_prefix(&line.prefix);
    if !valid_nick(&from) || line.tags.contains_key("batch") { return; }
    let Some((kind, rest)) = value.split_once('.') else { return };
    let mut c = conn.lock().await;
    if !supported(&c) || c.casemapping.fold(target) != c.casemapping.fold(&c.nick)
        || c.casemapping.fold(&from) == c.casemapping.fold(&c.nick) { return; }

    if kind == "q" && valid_id(rest) {
        // The IRC server supplies the host. The ident can be chosen by the sender.
        let Some((_, host)) = line.prefix.as_deref().and_then(|p| p.rsplit_once('@')) else { return };
        let requester = host.to_ascii_lowercase();
        c.e2e_bridge.replies.retain(|(_, at)| at.elapsed() < REPLY_WINDOW);
        let busy = c.e2e_bridge.replies.len() >= 10
            || c.e2e_bridge.replies.iter().filter(|(key, _)| key == &requester).count() >= 2
            || state.auth.check_ws_kdf_rate_limit(username, "e2e_bridge").is_err();
        if busy {
            c.e2e_bridge.busy_replies.retain(|(_, at)| at.elapsed() < REPLY_WINDOW);
            if c.e2e_bridge.busy_replies.len() >= 12 || c.e2e_bridge.busy_replies.iter().any(|(key, _)| key == &requester) { return; }
            c.e2e_bridge.busy_replies.push((requester.clone(), Instant::now()));
        } else {
            c.e2e_bridge.replies.push((requester.clone(), Instant::now()));
        }
        let registration = c.registration_epoch;
        drop(c);
        // Public prekeys can be served with the vault locked. A remote request uses
        // the same target-wide OTPK budget as local requests.
        let bundle = if busy { None } else {
            state.e2e_store.fetch_bundle(username, &format!("@irc:{requester}")).await
        };
        let needs_setup = bundle.is_none() && state.e2e_store.needs_bundle_setup(username).await;
        let reply = if busy && !needs_setup {
            format!("n.{rest}")
        } else if let Some(bundle) = bundle {
            let remaining = state.e2e_store.otpk_count(username).await;
            if remaining < 10 && crate::otpk_low_should_notify(username) {
                state.send_to_user(username, ServerEvent::E2EOTPKLow { remaining });
            }
            let Ok(bytes) = serde_json::to_vec(&bundle) else { return };
            let payload = URL_SAFE_NO_PAD.encode(bytes);
            if payload.len() > MAX_BUNDLE { return; }
            format!("b.{rest}.{payload}")
        } else {
            let status = if needs_setup { SETUP_REQUIRED } else { BUNDLE_UNAVAILABLE };
            format!("b.{rest}.{}", URL_SAFE_NO_PAD.encode(status))
        };
        let mut c = conn.lock().await;
        if supported(&c) && c.registration_epoch == registration && c.casemapping.fold(target) == c.casemapping.fold(&c.nick) {
            if needs_setup { notify_setup(state, username, &mut c, &from, line.prefix.as_deref()); }
            let _ = c.send_raw(&format!("@{TAG}={reply} TAGMSG {from}")).await;
        }
    } else if matches!(kind, "b" | "n") {
        let (id, payload) = if kind == "n" { (rest, "") } else {
            let Some(parts) = rest.split_once('.') else { return };
            parts
        };
        if !valid_id(id) || payload.len() > MAX_BUNDLE { return; }
        let Some(index) = c.e2e_bridge.pending.iter().position(|(req, nick, expires)| {
            req == id && c.casemapping.fold(nick) == c.casemapping.fold(&from) && Instant::now() < *expires
        }) else { return };
        if kind == "n" {
            let (req, _, _) = c.e2e_bridge.pending.swap_remove(index);
            state.send_to_user(username, ServerEvent::E2EBundleMissing { conn_id: c.conn_id.clone(), req, reason: "peer-busy" });
            return;
        }
        let Ok(bytes) = URL_SAFE_NO_PAD.decode(payload) else { return };
        if bytes == SETUP_REQUIRED || bytes == BUNDLE_UNAVAILABLE {
            let (req, _, _) = c.e2e_bridge.pending.swap_remove(index);
            let reason = if bytes == SETUP_REQUIRED { "peer-setup" } else { "unavailable" };
            state.send_to_user(username, ServerEvent::E2EBundleMissing { conn_id: c.conn_id.clone(), req, reason });
            return;
        }
        let Ok(bundle) = serde_json::from_slice::<FetchedBundle>(&bytes) else { return };
        let (req, nick, _) = c.e2e_bridge.pending.swap_remove(index);
        state.send_to_user(username, ServerEvent::E2EBundle {
            username: nick, bundle, conn_id: Some(c.conn_id.clone()), req: Some(req), bridge: true,
        });
    }
}
