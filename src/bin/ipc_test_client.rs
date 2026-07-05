//! ipc_test_client.rs — DEV/TEST TOOL ONLY, not part of the shipped
//! architecture. A minimal interactive client for exercising `ipc_server`
//! directly (Attach/Dial/RawSend/Drop) before the real web-side IPC client
//! (Phase 5) exists. Useful for verifying reattach/replay behavior: connect,
//! Dial, disconnect this tool, reconnect it, and confirm the daemon replays
//! the SessionSync + buffered lines from its cache.
//!
//! Usage: ipc_test_client <sock_path> [dial_params.json] [conn_id]
//! Then type commands on stdin:
//!   send <conn_id> <raw line>
//!   drop <conn_id> <reason>
//!   quit          (exits this tool only — the daemon and its connections
//!                  keep running; reconnect by re-running this binary)

use cryptirc::ipc::{DialParams, IpcMessage};
use cryptirc::ipc_framing::{read_frame, write_frame};
use tokio::io::{AsyncBufReadExt, BufReader as StdBufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <sock_path> [dial_params.json] [conn_id]", args.get(0).map(String::as_str).unwrap_or("ipc_test_client"));
        std::process::exit(1);
    }
    let sock_path = &args[1];

    let stream = UnixStream::connect(sock_path).await.unwrap_or_else(|e| panic!("connect {}: {}", sock_path, e));
    let (mut read_half, mut write_half) = stream.into_split();

    // Reader task: print every incoming IpcMessage.
    tokio::spawn(async move {
        loop {
            match read_frame(&mut read_half).await {
                Ok(Some(msg)) => println!("<< {:?}", msg),
                Ok(None) => { println!("-- daemon closed the connection --"); break; }
                Err(e) => { println!("-- read error: {} --", e); break; }
            }
        }
    });

    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<IpcMessage>();
    tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write_frame(&mut write_half, &msg).await.is_err() { break; }
        }
    });

    out_tx.send(IpcMessage::Attach {}).ok();
    println!(">> Attach {{}}");

    if args.len() >= 4 {
        let params_path = &args[2];
        let conn_id = args[3].clone();
        let json = std::fs::read_to_string(params_path).unwrap_or_else(|e| panic!("read {}: {}", params_path, e));
        let params: DialParams = serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse {}: {}", params_path, e));
        println!(">> Dial {{ conn_id: {:?}, server: {}:{} }}", conn_id, params.server, params.port);
        out_tx.send(IpcMessage::Dial { conn_id, params: Box::new(params) }).ok();
    }

    // Simple stdin command loop: "send <conn_id> <line...>" / "drop <conn_id> <reason...>" / "quit"
    let stdin = tokio::io::stdin();
    let mut lines = StdBufReader::new(stdin).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut it = line.splitn(3, ' ');
        match (it.next(), it.next(), it.next()) {
            (Some("send"), Some(conn_id), Some(rest)) => {
                out_tx.send(IpcMessage::RawSend { conn_id: conn_id.to_string(), line: rest.to_string() }).ok();
            }
            (Some("drop"), Some(conn_id), reason) => {
                out_tx.send(IpcMessage::Drop { conn_id: conn_id.to_string(), reason: reason.unwrap_or("test").to_string() }).ok();
            }
            (Some("quit"), _, _) => break,
            _ => println!("commands: send <conn_id> <line> | drop <conn_id> <reason> | quit"),
        }
    }
}
