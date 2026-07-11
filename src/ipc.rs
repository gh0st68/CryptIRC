//! ipc.rs — wire schema shared between the `cryptirc` web binary and the
//! `irc-core` daemon binary. Pure data shapes only — no transport/framing here
//! (that's `ipc_framing.rs`, added when the Unix-socket transport is wired up).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IPC protocol version. The daemon announces this in `Hello` so a newer web
/// binary can learn what a FROZEN daemon supports and gate its own behavior.
/// SCHEMA LAW (the daemon is byte-frozen for years): only ever ADD message
/// variants and ADD `#[serde(default)]` fields — never change a field's meaning
/// or type. Unknown variants deserialize to `Unknown` (ignored) and unknown
/// fields are ignored, so a newer web binary is always safe against this daemon.
pub const IPC_PROTO_VERSION: u32 = 1;

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
    ///
    /// `version`/`build` are the SENDING web binary's own `CARGO_PKG_VERSION` /
    /// `CRYPTIRC_BUILD` (see `ipc_client::handle_connection`) — additive fields
    /// (I4-style `#[serde(default)]`) so a pre-this-fix web binary (which sends
    /// bare `{"type":"attach"}`) still decodes against a patched daemon (both
    /// default to `""`), and a patched web binary still decodes against an
    /// old/frozen daemon that ignores the extra fields. The daemon caches the
    /// latest non-empty value (`ipc_server::Daemon::web_version`) and prefers it
    /// over its own compiled-in version when answering CTCP VERSION — see
    /// `WebVersionCell`. This is what lets a web-only redeploy (which always
    /// re-Attaches on restart) correct the daemon's CTCP reply without the
    /// long-running daemon itself being restarted.
    Attach {
        #[serde(default)]
        version: String,
        #[serde(default)]
        build: String,
    },

    /// Start owning a connection. Sent from the `Connect` handler and
    /// `reconnect_for_user`. Carries fully-resolved, already-decrypted dial
    /// parameters — see `DialParams`. (I3) If the daemon ALREADY owns this conn_id
    /// the Dial REPLACES it — the old task is dropped (its socket QUIT) and a fresh
    /// one spawned; this is the client-cert-renewal path (see ipc_server's Dial
    /// handler). It is NOT a daemon-side no-op. Safety against bouncing a healthy
    /// connection lives on the WEB side, which guards on `connections.contains_key`
    /// before issuing a Dial for an already-live conn (see main.rs Connect). Reattach
    /// after a web-process restart happens via `Attach`, never `Dial`.
    Dial { conn_id: String, params: Box<DialParams> },

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
    ///
    /// `replayed` is true only for a ring-buffer replay (`ipc_server.rs`'s
    /// `replay_messages`), false for a line forwarded live off the socket.
    /// The web side re-parses every line through the SAME code paths whether
    /// it's live or history, but a few of those paths have a side effect that
    /// is only correct ONCE per real-world event (e.g. logging "you joined" —
    /// see the JOIN handler in `irc.rs`) and must not re-fire just because a
    /// SessionSync-then-replay reattach re-shows a line that was already
    /// processed before the web process restarted. `#[serde(default)]` so an
    /// old daemon paired with a new web binary degrades to "always live"
    /// (the pre-fix behavior) instead of failing to deserialize.
    RawLine { conn_id: String, line: String, #[serde(default)] replayed: bool },

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
        /// The daemon's learned self `user@host` for this connection (from the
        /// self-JOIN / CHGHOST / accepted self-NICK). A freshly-reattached web
        /// process otherwise starts with this empty, silently disabling its
        /// forged-`NICK` spoof guard (`#30`) until the next self-JOIN — which a
        /// reattach never triggers. `#[serde(default)]` = "" for old daemons.
        #[serde(default)]
        self_userhost: String,
    },

    // ── Future-proofing (v1+) — kept additive so a byte-frozen daemon tolerates
    // anything a newer web binary sends. ─────────────────────────────────────
    /// Version handshake. The daemon sends this right after a web `Attach` (and a
    /// web client MAY send its own on connect). Lets a newer web binary discover
    /// the frozen daemon's capabilities instead of assuming.
    Hello { proto_version: u32 },

    /// Reserved out-of-band control channel (web → daemon) for future knobs that
    /// must not require a daemon schema change. The frozen daemon handles the
    /// verbs it knows and IGNORES the rest (logged), so a newer web binary can
    /// issue a verb this daemon predates without breaking anything. Known verbs
    /// today: `reconnect` (cycle a conn's socket), `rearm_sasl` (undo an auto-SASL-disable).
    DaemonControl { conn_id: String, verb: String, #[serde(default)] args: Vec<String> },

    /// Catch-all for any `type` this (frozen) daemon has never seen — a message
    /// variant added by a future web binary. Deserializes here instead of failing
    /// the whole frame, so the connection is never torn down over an unknown
    /// message. Handlers ignore it.
    #[serde(other)]
    Unknown,
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
///
/// SCHEMA LAW (I4): the fields below are FROZEN. Any field added in a FUTURE version
/// MUST carry `#[serde(default)]`. `DialParams` travels web→daemon, so an OLDER web
/// binary won't send a newer field — without a default the daemon's serde decode
/// fails, drops the client, and it reconnects re-sending the same undecodable Dial =
/// crash-loop. (Unlike the additive `IpcMessage` enum, whose `#[serde(other)]`
/// tolerates the unknown; a missing REQUIRED struct field has no such escape.)
/// `Debug` is hand-REDACTED below (fix 7) so an accidental `{:?}` — including via
/// `IpcMessage`'s derived Debug, which boxes this — never dumps password / SASL /
/// oper / nickserv secrets or PEM keys to the journal.
#[derive(Clone, Serialize, Deserialize)]
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

/// Shared, lock-guarded holder for the most recently `Attach`-announced web
/// binary `(version, build)`. Lives here (not in `ipc_server`) purely to avoid
/// a dependency cycle: `ipc_server` (writer, on every `Attach`) and
/// `irc_daemon` (reader, for CTCP VERSION) both already depend on this module,
/// and neither should depend on the other's private types. A plain
/// `std::sync::Mutex` is enough — the critical section is a single clone, held
/// across no `.await` point, so it can never contend with the async runtime.
#[derive(Default)]
pub struct WebVersionCell(std::sync::Mutex<Option<(String, String)>>);

impl WebVersionCell {
    /// Record a freshly-Attached web binary's version/build. Never overwrites
    /// with a blank value — an `Attach` from a pre-fix web binary (empty
    /// `#[serde(default)]` fields) must not erase a previously known-good
    /// version the daemon is still correctly serving.
    pub fn set(&self, version: String, build: String) {
        if version.is_empty() {
            return;
        }
        *self.0.lock().unwrap() = Some((version, build));
    }

    /// The last-announced `(version, build)`, or `None` if no web binary has
    /// ever Attached with one (fresh daemon start, or every web peer so far
    /// predates this fix) — callers fall back to their own compiled version.
    pub fn get(&self) -> Option<(String, String)> {
        self.0.lock().unwrap().clone()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SaslParams {
    pub account: String,
    pub password: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ClientIdentity {
    pub cert_pem: String,
    pub key_pem: String,
}

// ── Hand-redacted Debug for the secret-bearing structs (fix 7) ────────────────
// These derive everything EXCEPT Debug; the impls below never render a credential
// or PEM key. This also makes `IpcMessage::Dial`'s derived Debug safe, since it
// boxes a `DialParams`.
impl std::fmt::Debug for SaslParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SaslParams").field("account", &self.account).field("password", &"<redacted>").finish()
    }
}
impl std::fmt::Debug for ClientIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientIdentity").field("cert_pem", &"<redacted>").field("key_pem", &"<redacted>").finish()
    }
}
impl std::fmt::Debug for DialParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DialParams")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("tls", &self.tls)
            .field("nick", &self.nick)
            .field("username", &self.username)
            .field("sasl_external", &self.sasl_external)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("sasl_plain", &self.sasl_plain.as_ref().map(|_| "<redacted>"))
            .field("oper_login", &self.oper_login)
            .field("oper_pass", &self.oper_pass.as_ref().map(|_| "<redacted>"))
            .field("nickserv_pass", &self.nickserv_pass.as_ref().map(|_| "<redacted>"))
            .field("client_identity", &self.client_identity.as_ref().map(|_| "<redacted>"))
            .field("label", &self.label)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params() -> DialParams {
        DialParams {
            server: "irc.example.org".into(), port: 6697, tls: true,
            tls_accept_invalid_certs: false, nick: "n".into(), username: "u".into(),
            realname: "r".into(), password: Some("hunter2".into()),
            sasl_plain: Some(SaslParams { account: "acct".into(), password: "saslpw".into() }),
            sasl_external: false,
            client_identity: Some(ClientIdentity { cert_pem: "CERTPEM".into(), key_pem: "PRIVKEYPEM".into() }),
            oper_login: None, oper_pass: Some("operpw".into()), nickserv_pass: Some("nspw".into()),
            auto_identify: false, auto_join: vec![], channel_keys: HashMap::new(),
            perform_commands: vec![], disabled_caps: vec![], label: "l".into(), auto_reconnect: true,
        }
    }

    // I4: a newer web binary that adds a field the frozen daemon predates must still
    // decode (no `deny_unknown_fields`) — the daemon ignores what it doesn't know.
    #[test]
    fn dialparams_tolerates_unknown_fields() {
        let j = r#"{"type":"dial","conn_id":"n","params":{
            "server":"x","port":6697,"tls":true,"tls_accept_invalid_certs":false,
            "nick":"n","username":"u","realname":"r","password":null,"sasl_plain":null,
            "sasl_external":false,"client_identity":null,"oper_login":null,"oper_pass":null,
            "nickserv_pass":null,"auto_identify":false,"auto_join":[],"channel_keys":{},
            "perform_commands":[],"disabled_caps":[],"label":"l","auto_reconnect":true,
            "some_future_field":123}}"#;
        let msg: IpcMessage = serde_json::from_str(j).expect("unknown field must be ignored, not fail");
        assert!(matches!(msg, IpcMessage::Dial { .. }));
    }

    // Forward-compat: an unknown message `type` must map to Unknown, never error.
    #[test]
    fn unknown_message_type_becomes_unknown() {
        let msg: IpcMessage = serde_json::from_str(r#"{"type":"future_variant","foo":1}"#).unwrap();
        assert!(matches!(msg, IpcMessage::Unknown));
    }

    // fix 7: Debug must never render a credential or PEM key, including via the
    // enclosing IpcMessage's derived Debug (which boxes DialParams).
    #[test]
    fn debug_redacts_all_secrets() {
        let secrets = ["hunter2", "saslpw", "CERTPEM", "PRIVKEYPEM", "operpw", "nspw"];
        let direct = format!("{:?}", sample_params());
        for s in secrets { assert!(!direct.contains(s), "DialParams Debug leaked {s}"); }
        let wrapped = format!("{:?}", IpcMessage::Dial { conn_id: "n".into(), params: Box::new(sample_params()) });
        for s in secrets { assert!(!wrapped.contains(s), "IpcMessage Debug leaked {s}"); }
    }

    // A pre-fix web binary sends bare `{"type":"attach"}` — a patched daemon must
    // still decode it (version/build default to "") instead of failing the frame.
    #[test]
    fn attach_tolerates_missing_version_fields() {
        let msg: IpcMessage = serde_json::from_str(r#"{"type":"attach"}"#).unwrap();
        match msg {
            IpcMessage::Attach { version, build } => {
                assert_eq!(version, "");
                assert_eq!(build, "");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    // A patched web binary's Attach carries its version/build.
    #[test]
    fn attach_decodes_version_fields() {
        let msg: IpcMessage = serde_json::from_str(
            r#"{"type":"attach","version":"0.4.3","build":"abc1234"}"#,
        ).unwrap();
        match msg {
            IpcMessage::Attach { version, build } => {
                assert_eq!(version, "0.4.3");
                assert_eq!(build, "abc1234");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[test]
    fn web_version_cell_defaults_to_none() {
        let cell = WebVersionCell::default();
        assert_eq!(cell.get(), None);
    }

    #[test]
    fn web_version_cell_set_then_get_roundtrips() {
        let cell = WebVersionCell::default();
        cell.set("0.4.3".into(), "abc1234".into());
        assert_eq!(cell.get(), Some(("0.4.3".into(), "abc1234".into())));
    }

    #[test]
    fn web_version_cell_ignores_blank_version() {
        // A pre-fix Attach (defaulted-empty fields) must never clobber a
        // previously learned good version — see `WebVersionCell::set`'s doc.
        let cell = WebVersionCell::default();
        cell.set("0.4.3".into(), "abc1234".into());
        cell.set("".into(), "".into());
        assert_eq!(cell.get(), Some(("0.4.3".into(), "abc1234".into())));
    }
}
