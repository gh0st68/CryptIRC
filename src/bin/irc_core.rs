//! irc_core.rs — the irc-core daemon binary. Listens on a Unix domain socket
//! (see `ipc_server`) and holds every user's raw IRC connection, independent
//! of the web process's lifecycle.
//!
//! FLIGHT-SOFTWARE POSTURE: this daemon is meant to run for years without a
//! restart or a code edit. `main` therefore installs the process-wide safety
//! rails that can never be added later: a panic hook (so an isolated task panic
//! is at least logged), an explicit SIGPIPE ignore, and a runtime log-level
//! lever on SIGUSR1/SIGUSR2 (the only knob a frozen binary can expose — raise
//! with `systemctl kill -s SIGUSR1 irc-core`, lower with SIGUSR2). Graceful
//! SIGTERM shutdown + the systemd watchdog heartbeat live in `ipc_server::run`,
//! which owns the connection state.
//!
//! Socket path: `$CRYPTIRC_IPC_SOCK`, else `$CRYPTIRC_DATA/irc-core.sock`, else
//! `$XDG_RUNTIME_DIR/irc-core.sock` (per-user, 0700). It deliberately does NOT
//! fall back to a world-writable shared dir like /tmp — it refuses to start
//! instead (a predictable /tmp path is a symlink-hijack / unauth-connect risk).

use tracing_subscriber::{prelude::*, reload, EnvFilter};

#[tokio::main]
async fn main() {
    // ── Reloadable log filter: SIGUSR1 → debug, SIGUSR2 → back to info. ──
    let env = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let (filter_layer, reload_handle) = reload::Layer::new(env);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    // ── Panic hook: a per-connection task panic is ISOLATED (panic=unwind) but
    // otherwise silent — log it so a future post-mortem has a trace. ──
    std::panic::set_hook(Box::new(|info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "<unknown>".into());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(|s| s.as_str()))
            .unwrap_or("<non-string panic>");
        tracing::error!(target: "panic", event = "task_panic", "PANIC at {loc}: {msg} (task isolated; connection will be reaped)");
    }));

    // ── Explicitly ignore SIGPIPE. Rust's runtime already does this, but with
    // the unit's SystemCallFilter + the openssl/native-tls write paths, a stray
    // SIGPIPE on a dead-peer write would be process death — belt-and-suspenders. ──
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN); }

    // ── Runtime log-level lever (the only in-band knob a frozen daemon exposes). ──
    if let (Ok(mut usr1), Ok(mut usr2)) = (
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1()),
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2()),
    ) {
        let handle = reload_handle.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = usr1.recv() => { let _ = handle.reload(EnvFilter::new("debug")); tracing::warn!("log level → debug (SIGUSR1)"); }
                    _ = usr2.recv() => { let _ = handle.reload(EnvFilter::new("info"));  tracing::warn!("log level → info (SIGUSR2)"); }
                }
            }
        });
    }

    // ── Socket path resolution — never a shared world-writable dir. ──
    let sock_path = std::env::var("CRYPTIRC_IPC_SOCK").ok()
        .or_else(|| std::env::var("CRYPTIRC_DATA").ok().map(|d| format!("{}/irc-core.sock", d.trim_end_matches('/'))))
        .or_else(|| std::env::var("XDG_RUNTIME_DIR").ok().map(|d| format!("{}/irc-core.sock", d.trim_end_matches('/'))));
    let sock_path = match sock_path {
        Some(p) => p,
        None => {
            eprintln!("irc-core: refusing to start — set CRYPTIRC_IPC_SOCK, CRYPTIRC_DATA, or XDG_RUNTIME_DIR (a shared /tmp path is unsafe)");
            std::process::exit(2);
        }
    };

    // run() only returns on a bind failure or graceful shutdown. A bind failure
    // is a legitimate startup error → exit non-zero so systemd retries (it never
    // gives up now — StartLimitIntervalSec=0 + Restart=always). This is NOT the
    // per-accept error path (that is swallowed inside run's accept loop).
    if let Err(e) = cryptirc::ipc_server::run(&sock_path).await {
        tracing::error!("irc-core exited: {}", e);
        std::process::exit(1);
    }
}
