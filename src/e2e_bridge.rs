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
const MAX_BUNDLE: usize = 1200;
const REQUEST_TTL: Duration = Duration::from_secs(5);
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

pub(crate) async fn request(state: &AppState, username: &str, conn: Arc<Mutex<IrcConnection>>, nick: &str, id: &str) -> Result<bool, &'static str> {
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
    let started = Instant::now();
    let req = id.to_owned();
    c.e2e_bridge.pending.push((req.clone(), nick.to_owned(), started));
    drop(c);
    let state = state.clone();
    let username = username.to_owned();
    tokio::spawn(async move {
        tokio::time::sleep(REQUEST_TTL).await;
        let mut c = conn.lock().await;
        let Some(i) = c.e2e_bridge.pending.iter().position(|(id, _, at)| id == &req && *at == started) else { return };
        c.e2e_bridge.pending.swap_remove(i);
        state.send_to_user(&username, ServerEvent::E2EBundleMissing { conn_id: c.conn_id.clone(), req, reason: "unconfirmed" });
    });
    Ok(true)
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
        let Some(index) = c.e2e_bridge.pending.iter().position(|(req, nick, at)| {
            req == id && c.casemapping.fold(nick) == c.casemapping.fold(&from) && at.elapsed() < REQUEST_TTL
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
