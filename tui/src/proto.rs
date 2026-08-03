//! The CryptIRC WebSocket wire protocol, as spoken by the browser.
//!
//! These types are deliberately RE-DECLARED here rather than imported from the
//! server crate. Two reasons:
//!
//! 1. `ClientMessage`/`ServerEvent` live in the server's `main.rs`, which is a
//!    binary — Rust cannot import from it. Sharing them would mean hoisting them
//!    into the library, i.e. editing the very code gh0st asked us not to touch.
//! 2. Decoupling is the point. This client talks to the web process exactly the
//!    way the browser does, so it must tolerate a server that is NEWER than it —
//!    hence `#[serde(other)]` on the event enum and `Option`/`default` on
//!    anything not strictly required.
//!
//! ⚠️ CONSEQUENCE: this file is a COPY of a contract owned elsewhere. If the
//! server renames a variant or a field, the compiler cannot warn us — the event
//! simply falls into `Unknown` and is ignored. The tag names below are
//! snake_case because the server declares
//! `#[serde(tag = "type", rename_all = "snake_case")]` on both enums.

use serde::{Deserialize, Serialize};

// ── Client → server ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Must be the FIRST frame we send. The server opens with `auth_required`
    /// and drops the socket if this does not arrive within 5 seconds.
    Auth { token: String },
    UnlockVault { passphrase: String },
    /// A raw IRC line (`PRIVMSG #chan :hi`). The server strips CR/LF, logs it,
    /// echoes it back to every one of our sessions, and forwards it to the daemon.
    Send { conn_id: String, raw: String },
    JoinChannel { conn_id: String, channel: String, key: Option<String> },
    PartChannel { conn_id: String, channel: String },
    GetLogs { conn_id: String, target: String, limit: Option<usize>, before: Option<i64> },
    /// Re-dial a network. Field is `id`, not `conn_id` — the server is asymmetric
    /// here (see ../src/main.rs ClientMessage::Connect/Disconnect).
    Connect { id: String },
    Disconnect { id: String, reason: Option<String> },
    /// The owner's PRIVATE bot commands (/w, /ud, /ai, /q, /seen, …). The reply
    /// comes back as `BotResult` and is shown only to us — it is NOT sent to the
    /// channel. `conn_id`/`channel` are required by the bots that need context
    /// (quotedb/seen/tell/note); the rest ignore them.
    BotQuery { bot: String, query: String, conn_id: String, channel: String },
    /// The AI agent acting in a channel (/aido). Distinct from `/ai`, which is a
    /// BotQuery — this one is the only path that may run IRC actions.
    AiDo { conn_id: String, target: String, query: String },
    /// Marks this session idle so the server routes push notifications elsewhere.
    /// We send `active` on any keypress — matching the browser's behaviour means
    /// a TUI left open does not silently swallow the user's phone notifications.
    Idle {},
    Active {},
}

// ── Server → client ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkConfig {
    pub id: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelState {
    pub name: String,
    #[serde(default)]
    pub topic: String,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkState {
    pub config: NetworkConfig,
    #[serde(default)]
    pub connected: bool,
    #[serde(default)]
    pub nick: String,
    #[serde(default)]
    pub channels: Vec<ChannelState>,
    #[serde(default)]
    pub lag_ms: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogLine {
    #[serde(default)]
    pub id: u64,
    #[serde(default)]
    pub ts: i64,
    #[serde(default)]
    pub from: String,
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub kind: String,
}

/// ⚠️ `MessageKind` on the server has NO `rename_all`, so `kind` arrives
/// CAPITALISED — "Privmsg" / "Notice" / "Action" — on live events. But
/// `LogLine.kind` (history) is written lowercase. Always compare
/// case-insensitively or live actions/notices silently render as plain text.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerEvent {
    AuthRequired {},
    AuthOk { username: String },
    AuthFailed { message: String },
    VaultLocked {},
    /// The E2E subkey. This client does not implement E2E yet (see the README
    /// note), but the field is modelled so the variant round-trips faithfully.
    VaultUnlocked { #[serde(default)] #[allow(dead_code)] e2e_enc_key: String },
    VaultError { message: String },

    IrcMessage {
        conn_id: String, from: String, target: String, text: String,
        #[serde(default)] ts: i64,
        #[serde(default)] kind: String,
        #[serde(default)] msg_id: u64,
        /// True for daemon ring-buffer replay after a web restart. We render it
        /// into scrollback but must not treat it as new activity.
        #[serde(default)] replayed: bool,
    },
    /// Our own message, from ANY of our sessions — including this one, and
    /// including anything a server-side bot said on our behalf.
    IrcEcho {
        conn_id: String, from: String, target: String, text: String,
        #[serde(default)] ts: i64,
        #[serde(default)] kind: String,
        #[serde(default)] msg_id: u64,
    },
    IrcJoin { conn_id: String, nick: String, channel: String, #[serde(default)] ts: i64 },
    IrcPart { conn_id: String, nick: String, channel: String, #[serde(default)] reason: String, #[serde(default)] ts: i64 },
    IrcQuit { conn_id: String, nick: String, #[serde(default)] reason: String, #[serde(default)] ts: i64 },
    IrcNick { conn_id: String, #[serde(default)] old: String, #[serde(default)] new: String, #[serde(default)] ts: i64 },
    IrcTopic { conn_id: String, channel: String, #[serde(default)] topic: String, #[serde(default)] ts: i64 },
    IrcNames { conn_id: String, channel: String, #[serde(default)] names: Vec<String> },
    /// NOTE: the server does NOT send who set the mode — there is no `by` field
    /// (../src/main.rs:558). Do not invent one; it would render a lie.
    IrcMode { conn_id: String, #[serde(default)] target: String, #[serde(default)] modes: String, #[serde(default)] ts: i64 },
    /// The kicked user's field is `kicked`, NOT `nick`.
    IrcKick { conn_id: String, channel: String, #[serde(default)] kicked: String, #[serde(default)] by: String, #[serde(default)] reason: String, #[serde(default)] ts: i64 },

    /// Carries the nick the server actually gave us — which differs from the
    /// configured one after a collision. Discarding it left `app.nicks` stale,
    /// which silently broke highlight matching and self-part detection.
    Connected { conn_id: String, #[serde(default)] nick: String, #[serde(default)] server: String },
    /// The field is `reason`, NOT `message`.
    Disconnected { conn_id: String, #[serde(default)] reason: String },
    Connecting { conn_id: String },
    Reconnecting { conn_id: String, #[serde(default)] delay_secs: u64 },
    /// `ms`, a plain u64 — NOT `lag_ms: Option<u64>` (that is the shape inside
    /// NetworkState, which is a different type).
    LagUpdate { conn_id: String, #[serde(default)] ms: u64 },

    /// The full picture: every network, its channels, members and topics.
    /// Sent on auth and whenever the server-side view changes materially.
    State { #[serde(default)] networks: Vec<NetworkState>, #[serde(default)] vault_unlocked: bool },
    LogLines { conn_id: String, target: String, #[serde(default)] lines: Vec<LogLine> },

    Error { #[serde(default)] message: String },
    /// Reply to a `BotQuery` — private to us, rendered in the active buffer.
    BotResult { #[serde(default)] bot: String, #[serde(default)] text: String },

    /// Everything we do not model. The server has ~45 event types and will grow
    /// more; an unknown one must be ignored, never fatal. Without this a single
    /// new server event would break the whole client with a parse error.
    #[serde(other)]
    Unknown,
}
