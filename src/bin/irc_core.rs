//! irc_core.rs — the irc-core daemon binary. Listens on a Unix domain socket
//! (see `ipc_server`) and holds every user's raw IRC connection, independent
//! of the web process's lifecycle.
//!
//! Socket path: `$CRYPTIRC_IPC_SOCK`, defaulting to
//! `$CRYPTIRC_DATA/irc-core.sock` (or `/tmp/cryptirc-irc-core.sock` if
//! `$CRYPTIRC_DATA` is also unset — convenient for throwaway local testing).

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let sock_path = std::env::var("CRYPTIRC_IPC_SOCK").unwrap_or_else(|_| {
        let data_dir = std::env::var("CRYPTIRC_DATA").unwrap_or_else(|_| "/tmp".to_string());
        format!("{}/irc-core.sock", data_dir.trim_end_matches('/'))
    });

    if let Err(e) = cryptirc::ipc_server::run(&sock_path).await {
        tracing::error!("irc-core failed: {}", e);
        std::process::exit(1);
    }
}
