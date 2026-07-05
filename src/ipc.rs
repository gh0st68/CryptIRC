//! ipc.rs — wire schema shared between the `cryptirc` web binary and the
//! `irc-core` daemon binary. Pure data shapes only — no transport/framing here
//! (that's `ipc_framing.rs`, added when the Unix-socket transport is wired up).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Every message on the wire carries this envelope. `conn_id` is the routing
/// key (matches the web side's existing conn_id); `Attach` is the one message
/// with no meaningful conn_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum IpcMessage {
    // ── web → daemon ──────────────────────────────────────────────────────
    /// Sent once, immediately after the web process establishes (or
    /// re-establishes) the IPC connection. Carries nothing conn_id-specific;
    /// the daemon replies with one SessionSync per conn_id it currently owns.
    Attach {},

    /// Start owning a brand-new connection. Only sent from the two call sites
    /// that today call `irc::connect()`: the `Connect` handler and
    /// `reconnect_for_user`. Carries fully-resolved, already-decrypted dial
    /// parameters — see `DialParams`. Rejected as a no-op if the daemon
    /// already owns this conn_id (reattach happens via `Attach`, not `Dial`).
    Dial { conn_id: String, params: DialParams },

    /// Forward one raw outbound IRC line verbatim. Covers every existing
    /// `send_raw()` call site except the registration burst (PASS/CAP
    /// LS/NICK/USER/AUTHENTICATE), which is internal to the daemon and never
    /// crosses IPC.
    RawSend { conn_id: String, line: String },

    /// User explicitly disconnected. Daemon sends QUIT with `reason`, tears
    /// down the real socket, and does not reconnect this conn_id again until
    /// a fresh `Dial` arrives.
    Drop { conn_id: String, reason: String },

    // ── daemon → web ───────────────────────────────────────────────────────
    /// One line received from the IRC server, forwarded verbatim (PING is
    /// answered daemon-side and never forwarded). Replayed from the ring
    /// buffer on a fresh `Attach` for any conn_id the daemon still owns.
    RawLine { conn_id: String, line: String },

    /// Daemon-level connection lifecycle. The web side re-derives its own
    /// `ServerEvent::Connected` from seeing the 001 line in a forwarded
    /// `RawLine`, exactly as it does today — this only covers the states the
    /// daemon is uniquely positioned to know about.
    ConnStatus { conn_id: String, state: ConnLifecycle },

    /// Sent once, after the daemon has finished replaying every conn_id's
    /// SessionSync + ring-buffer burst in response to an `Attach`. Marks "that
    /// is everything I currently own" — the web side uses this to know when
    /// it's safe to compare against what it expected and re-`Dial` anything
    /// missing (daemon-restart recovery), without racing the replay itself.
    AttachComplete {},

    /// Membership/nick snapshot, sent in response to `Attach` for every
    /// conn_id the daemon owns, and again whenever daemon-tracked nick or
    /// channel-membership drifts (self-JOIN/PART/KICK/QUIT/NICK).
    SessionSync {
        conn_id: String,
        nick: String,
        /// Channels the daemon believes we're currently in (case-folded
        /// names only — no topics/names/keys; those are rebuilt web-side via
        /// an ordinary NAMES/TOPIC resync burst issued through the daemon).
        channels: Vec<String>,
        registered: bool,
        connected: bool,
        lag_ms: Option<u64>,
        /// Negotiated CAPs the web side needs to correctly re-parse forwarded
        /// `RawLine`s (self-echo suppression, TAGMSG typing indicators). The
        /// daemon negotiates these once at connect time and they never change
        /// again for the connection's life, but a re-`Attach`'d web process
        /// (e.g. after a routine `cryptirc.service` restart) starts with
        /// fresh, un-negotiated state and would otherwise never learn them —
        /// see the matching fields on `irc::IrcConnection`/`irc_daemon::DaemonConn`.
        /// `#[serde(default)]` (= false, the safe "unknown, suppress nothing"
        /// value) so an old daemon talking to a freshly-upgraded web binary
        /// degrades gracefully (same stuck-false bug this fixes, not a hard
        /// IPC decode failure that would tear down the whole connection and
        /// crash-reconnect-loop) if the two binaries ever restart out of step.
        #[serde(default)]
        message_tags: bool,
        #[serde(default)]
        echo_message_enabled: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConnLifecycle {
    Connecting,
    Disconnected { reason: String },
    Reconnecting { attempt: u32, delay_secs: u64, reason: String },
}

/// Fully-resolved, already-decrypted dial parameters. Every field here is
/// exactly what `do_connect()`/`run_loop()` read out of `NetworkConfig` +
/// vault-decrypted cert material today — nothing new is decided daemon-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DialParams {
    pub server: String,
    pub port: u16,
    pub tls: bool,
    pub tls_accept_invalid_certs: bool,
    pub nick: String,
    pub username: String,
    pub realname: String,
    pub password: Option<String>,
    pub sasl_plain: Option<SaslParams>,
    pub sasl_external: bool,
    /// Present only when sasl_external is set and the vault was unlocked at
    /// Dial time. Raw PEM text — matches what `do_connect()` feeds to openssl
    /// today, so no format conversion happens at the IPC boundary.
    pub client_identity: Option<ClientIdentity>,
    pub oper_login: Option<String>,
    pub oper_pass: Option<String>,
    pub nickserv_pass: Option<String>,
    pub auto_identify: bool,
    pub auto_join: Vec<String>,
    pub channel_keys: HashMap<String, String>,
    pub perform_commands: Vec<String>,
    pub disabled_caps: Vec<String>,
    /// Needed for the EFnet-detection heuristic (skip CAP/SASL entirely).
    pub label: String,
    pub auto_reconnect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaslParams {
    pub account: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}
