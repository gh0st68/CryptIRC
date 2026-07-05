//! lib.rs — shared library crate, reused by the `cryptirc` web binary (src/main.rs)
//! and the `irc-core` daemon binary (src/bin/irc_core.rs).
//!
//! Only genuinely shared, dependency-free code lives here. Everything else
//! (AppState, the web routes, vault/crypto/logging/E2E/push) stays in the web
//! binary's own modules — the daemon never needs them (see the irc-core daemon
//! split plan).

pub mod ipc;
pub mod ipc_framing;
pub mod ipc_server;
pub mod irc_daemon;
pub mod ircproto;
