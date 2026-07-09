//! ipc_framing.rs — length-prefixed framing for `IpcMessage`, generic over any
//! `AsyncRead`/`AsyncWrite` so both the web-side client and daemon-side server
//! share the exact same wire encoding over their Unix socket connection.
//!
//! Frame = 4-byte big-endian length prefix + that many bytes of JSON body.

use crate::ipc::IpcMessage;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// 64 KiB — generous vs. `ircproto::MAX_IRC_LINE_LEN` (8192): a `RawLine`/`RawSend`
/// frame is one IRC line plus JSON envelope, plus headroom for the largest
/// `SessionSync` snapshot. Tightened from 1 MiB so a malformed/adversarial length
/// prefix can't force a large speculative allocation on either end of the socket.
pub const MAX_FRAME_LEN: u32 = 64 * 1024;

/// A single frame write must never wedge the caller forever. A peer that stops
/// reading (crashed mid-frame, SIGSTOP'd, kernel buffer full) makes `write_all`
/// block indefinitely — in a never-restart daemon that stalls every branch of the
/// select! loop. A timeout turns "stuck peer" into "dead connection, close it."
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Once a length prefix declares N body bytes, they must arrive promptly. This
/// bounds the "declare a big body then withhold it" reader-pin. (The length prefix
/// itself is NOT timed — an idle-but-alive peer legitimately sends nothing.)
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Serialize `msg` and write it as one length-prefixed frame, flushed. Never
/// panics (a frozen binary must not die on its own send path) and never blocks
/// forever (bounded by `WRITE_TIMEOUT`).
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &IpcMessage) -> std::io::Result<()> {
    // Every current IpcMessage variant is infallibly serializable (string-keyed
    // maps only), so this is a latent-only guard today — but the alternative is a
    // bare panic on the send path if a future field ever isn't. Drop the frame,
    // never crash.
    let body = match serde_json::to_vec(msg) {
        Ok(b) => b,
        Err(e) => { tracing::error!("ipc: dropping unserializable frame: {}", e); return Ok(()); }
    };
    // Symmetric with read_frame's MAX_FRAME_LEN check: NEVER emit a frame the peer is
    // guaranteed to reject. read_frame treats an oversized length prefix as a fatal read
    // error → the peer tears the connection down → on reattach the SAME oversized frame
    // (e.g. a SessionSync whose channel list is pathologically large — a hostile server
    // spoofing self-JOINs with huge names) rebuilds first → permanent teardown loop.
    // Drop it loudly instead; the stream stays healthy and the next message (or a fresh
    // SessionSync after the next membership change) recovers.
    if body.len() > MAX_FRAME_LEN as usize {
        tracing::error!("ipc: dropping oversized frame ({} bytes > {} max) — not sending", body.len(), MAX_FRAME_LEN);
        return Ok(());
    }
    let len = body.len() as u32;
    let fut = async {
        w.write_all(&len.to_be_bytes()).await?;
        w.write_all(&body).await?;
        w.flush().await
    };
    match tokio::time::timeout(WRITE_TIMEOUT, fut).await {
        Ok(res) => res,
        Err(_) => Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "ipc write timed out")),
    }
}

/// Read one length-prefixed frame and deserialize it. Returns `Ok(None)` on a
/// clean EOF at the length-prefix boundary (peer closed); `Err` for a truncated /
/// oversized / slow / malformed frame.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<IpcMessage>> {
    // First prefix byte is UNTIMED: an idle-but-alive peer legitimately sends nothing
    // for long stretches, and a clean close at this exact boundary is EOF → Ok(None).
    let mut first = [0u8; 1];
    match r.read_exact(&mut first).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    // Once the first byte has arrived, the peer has COMMITTED to a frame; the remaining
    // 3 prefix bytes must arrive promptly. Without this bound a partial-prefix stall (a
    // wedged / SIGSTOP'd writer that sent 1-3 bytes then froze) would pin this reader
    // task forever — the length-prefix read used to be fully untimed.
    let mut rest = [0u8; 3];
    match tokio::time::timeout(BODY_READ_TIMEOUT, r.read_exact(&mut rest)).await {
        Ok(res) => { res?; }
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "ipc length-prefix read timed out")),
    }
    let len = u32::from_be_bytes([first[0], rest[0], rest[1], rest[2]]);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "IPC frame too large"));
    }
    let mut body = vec![0u8; len as usize];
    match tokio::time::timeout(BODY_READ_TIMEOUT, r.read_exact(&mut body)).await {
        Ok(res) => { res?; }
        Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "ipc body read timed out")),
    }
    serde_json::from_slice(&body).map(Some).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ConnLifecycle;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trip_single_frame() {
        let msg = IpcMessage::RawLine { conn_id: "net1".into(), line: ":server PRIVMSG #chan :hi".into(), replayed: false };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).await.unwrap().expect("expected a frame");
        match got {
            IpcMessage::RawLine { conn_id, line, .. } => {
                assert_eq!(conn_id, "net1");
                assert_eq!(line, ":server PRIVMSG #chan :hi");
            }
            other => panic!("unexpected variant: {:?}", other),
        }
    }

    #[tokio::test]
    async fn round_trip_multiple_frames_in_sequence() {
        let msgs = vec![
            IpcMessage::Attach {},
            IpcMessage::ConnStatus { conn_id: "n".into(), state: ConnLifecycle::Connecting },
            IpcMessage::Drop { conn_id: "n".into(), reason: "bye".into() },
        ];
        let mut buf = Vec::new();
        for m in &msgs {
            write_frame(&mut buf, m).await.unwrap();
        }
        let mut cursor = Cursor::new(buf);
        for expected in &msgs {
            let got = read_frame(&mut cursor).await.unwrap().expect("expected a frame");
            assert_eq!(format!("{:?}", got), format!("{:?}", expected));
        }
        // Nothing left — next read is a clean EOF, not an error.
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn oversized_length_prefix_is_rejected() {
        let mut buf = Vec::new();
        // Claim a body far larger than MAX_FRAME_LEN, then supply none of it.
        buf.extend_from_slice(&(MAX_FRAME_LEN + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.expect_err("oversized frame must error, not hang/allocate");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn truncated_frame_is_an_error_not_a_clean_eof() {
        let msg = IpcMessage::RawLine { conn_id: "n".into(), line: "x".into(), replayed: false };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();
        buf.truncate(buf.len() - 1); // chop the last body byte
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.expect_err("a truncated body must error");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn clean_eof_with_nothing_written_is_none_not_error() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert!(read_frame(&mut cursor).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn malformed_json_body_is_rejected() {
        let mut buf = Vec::new();
        let bad_body = b"{not valid json";
        buf.extend_from_slice(&(bad_body.len() as u32).to_be_bytes());
        buf.extend_from_slice(bad_body);
        let mut cursor = Cursor::new(buf);
        let err = read_frame(&mut cursor).await.expect_err("malformed JSON must error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
