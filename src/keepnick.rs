use std::path::Path;
use std::time::{Duration, Instant};

use cryptirc::ircproto::CaseMapping;
use serde_json::Value;

use crate::{AppState, ServerEvent};

const INTERVAL: Duration = Duration::from_secs(12);
const MAX_RETRY: Duration = Duration::from_secs(60);

#[derive(Default)]
pub(crate) struct Retry {
    last_attempt: Option<Instant>,
    delay: Duration,
    pending: Option<String>,
    limit: Option<usize>,
    rejected: bool,
}

impl Retry {
    fn ready(&self) -> bool {
        !self.rejected
            && self
                .last_attempt
                .is_none_or(|at| at.elapsed() >= self.delay)
    }

    fn sent(&mut self, nick: String) {
        self.last_attempt = Some(Instant::now());
        self.delay = (self.delay * 2).clamp(INTERVAL, MAX_RETRY);
        self.pending = Some(nick);
    }

    pub(crate) fn clear_pending(&mut self) {
        self.pending = None;
    }

    fn reset_attempts(&mut self) {
        *self = Self {
            limit: self.limit,
            ..Self::default()
        };
    }

    pub(crate) fn learn_limit(&mut self, tokens: &[String]) {
        let previous = self.limit;
        for token in tokens {
            if let Some(limit) = token
                .strip_prefix("NICKLEN=")
                .and_then(|n| n.parse::<usize>().ok())
                .filter(|n| *n > 0)
            {
                self.limit = Some(limit);
            } else if token == "-NICKLEN" {
                self.limit = None;
            }
        }
        if self.limit != previous {
            self.reset_attempts();
        }
    }

    pub(crate) fn pause(&mut self) {
        self.rejected = true;
    }

    pub(crate) fn matches_refusal(
        &mut self,
        params: &[String],
        mapping: CaseMapping,
        nickless: bool,
    ) -> bool {
        let matches = self.pending.as_ref().is_some_and(|pending| {
            let expected = mapping.fold(pending);
            params
                .iter()
                .skip(1)
                .take(2)
                .any(|nick| mapping.fold(nick) == expected)
                || (nickless && self.last_attempt.is_some_and(|at| at.elapsed() < INTERVAL))
        });
        if matches {
            self.clear_pending();
        }
        matches
    }
}

fn valid_nick(nick: &str) -> bool {
    const SPECIAL: &str = "_[]\\`^{}|";
    let mut chars = nick.chars();
    nick.len() <= 64
        && chars
            .next()
            .is_some_and(|c| c.is_alphabetic() || SPECIAL.contains(c))
        && chars.all(|c| c.is_alphanumeric() || c == '-' || SPECIAL.contains(c))
}

pub(crate) async fn set(
    state: &AppState,
    username: &str,
    conn_id: &str,
    nick: Option<String>,
    stop: bool,
    import: bool,
) -> Result<(), String> {
    if nick.as_deref().is_some_and(|n| !valid_nick(n))
        || (!stop && nick.is_none())
        || (import && stop)
    {
        if import {
            return Ok(());
        }
        return Err("Enter a valid nick to keep or stop keeping.".into());
    }
    let lock = crate::network_config_lock(username, conn_id);
    let _guard = lock.lock().await;
    if !state.owns_network(username, conn_id).await {
        return Err("Unknown network.".into());
    }
    let path = Path::new(&state.data_dir)
        .join("networks")
        .join(username)
        .join(format!("{conn_id}.json"));
    let bytes = tokio::fs::read(&path)
        .await
        .map_err(|_| "Could not read this network's settings.")?;
    let mut document: Value =
        serde_json::from_slice(&bytes).map_err(|_| "Could not read this network's settings.")?;
    let config = document
        .as_object_mut()
        .ok_or("Could not read this network's settings.")?;
    if import
        && (config.get("keep_nick_managed").and_then(Value::as_bool) == Some(true)
            || config.get("keep_nick").and_then(Value::as_str).is_some())
    {
        return Ok(());
    }
    let live = state
        .connections
        .get(conn_id)
        .map(|c| c.clone())
        .filter(|_| state.owns_conn(username, conn_id));
    if !stop {
        if let (Some(conn), Some(desired)) = (&live, nick.as_deref()) {
            if let Some(limit) = conn
                .lock()
                .await
                .keepnick_retry
                .limit
                .filter(|limit| desired.len() > *limit)
            {
                if import {
                    return Ok(());
                }
                return Err(format!(
                    "This network allows nicknames up to {limit} bytes."
                ));
            }
        }
    }
    if stop && nick.is_some() {
        let mapping = match &live {
            Some(conn) => conn.lock().await.casemapping,
            None => crate::irc::known_casemapping(conn_id).unwrap_or(CaseMapping::Ascii),
        };
        let current = config.get("keep_nick").and_then(Value::as_str);
        if current
            .zip(nick.as_deref())
            .is_none_or(|(current, requested)| mapping.fold(current) != mapping.fold(requested))
        {
            return Err("That nickname is not being kept on this network.".into());
        }
    }
    let saved = if stop { None } else { nick };
    config.insert("keep_nick".into(), serde_json::json!(saved));
    config.insert("keep_nick_managed".into(), Value::Bool(true));
    crate::write_secret_json_atomic(&path, &document)
        .await
        .map_err(|_| "Could not save KeepNick settings.")?;
    if let Some(conn) = live {
        let mut conn = conn.lock().await;
        conn.cfg.keep_nick.clone_from(&saved);
        conn.cfg.keep_nick_managed = true;
        conn.keepnick_retry.reset_attempts();
    }
    state.send_to_user(
        username,
        ServerEvent::KeepNickUpdated {
            conn_id: conn_id.to_owned(),
            nick: saved,
            imported: import,
        },
    );
    Ok(())
}

pub(crate) async fn poll(state: AppState) {
    let mut ticks = tokio::time::interval(INTERVAL);
    ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        ticks.tick().await;
        let live: Vec<_> = state
            .connections
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        for conn in live {
            let Ok(mut conn) = conn.try_lock() else {
                continue;
            };
            if !conn.connected
                || !conn.registered
                || state.disconnect_requested(&conn.conn_id)
                || crate::user_disconnected(&conn.conn_id)
            {
                continue;
            }
            let Some(desired) = conn.cfg.keep_nick.clone() else {
                continue;
            };
            if conn.casemapping.fold(&desired) == conn.casemapping.fold(&conn.nick) {
                conn.keepnick_retry.reset_attempts();
                continue;
            }
            if !valid_nick(&desired) || !conn.keepnick_retry.ready() {
                continue;
            }
            if let Some(limit) = conn
                .keepnick_retry
                .limit
                .filter(|limit| desired.len() > *limit)
            {
                conn.keepnick_retry.pause();
                if let Some(owner) = state.conn_owners.get(&conn.conn_id) {
                    state.send_to_user(owner.as_str(), ServerEvent::IrcMessage {
                        conn_id: conn.conn_id.clone(), from: "*".into(), target: "status".into(),
                        text: format!("KeepNick paused: this network allows nicknames up to {limit} bytes."),
                        ts: chrono::Utc::now().timestamp(), kind: crate::MessageKind::Notice, msg_id: 0, prefix: None, replayed: false,
                    });
                }
            } else if conn.send_raw(&format!("NICK {desired}")).await.is_ok() {
                conn.keepnick_retry.sent(desired);
            }
        }
    }
}
