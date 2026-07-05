//! ipc_framing.rs — length-prefixed framing for `IpcMessage`, generic over any
//! `AsyncRead`/`AsyncWrite` so both the web-side client and daemon-side server
//! share the exact same wire encoding over their Unix socket connection.
//!
//! Frame = 4-byte big-endian length prefix + that many bytes of JSON body.

use crate::ipc::IpcMessage;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Generous vs. `ircproto::MAX_IRC_LINE_LEN` (8192) — a `RawLine`/`RawSend`
/// frame is one IRC line plus JSON envelope overhead, so this is nowhere near
/// the ceiling for legitimate traffic. Bounds a malformed/adversarial length
/// prefix from driving an unbounded allocation on either end of the socket.
pub const MAX_FRAME_LEN: u32 = 1 << 20; // 1 MiB

/// Serialize `msg` and write it as one length-prefixed frame. Flushes so the
/// frame is actually on the wire before returning (both ends read frame-by-frame).
pub async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, msg: &IpcMessage) -> std::io::Result<()> {
    let body = serde_json::to_vec(msg).expect("IpcMessage always serializes");
    let len = body.len() as u32;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(&body).await?;
    w.flush().await
}

/// Read one length-prefixed frame and deserialize it. Returns `Ok(None)` on a
/// clean EOF at the length-prefix boundary (the other end closed the
/// connection); returns `Err` for a truncated frame, an oversized length
/// prefix, or a body that fails to deserialize as `IpcMessage`.
pub async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> std::io::Result<Option<IpcMessage>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "IPC frame too large"));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body).await?;
    serde_json::from_slice(&body).map(Some).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ConnLifecycle;
    use std::io::Cursor;

    #[tokio::test]
    async fn round_trip_single_frame() {
        let msg = IpcMessage::RawLine { conn_id: "net1".into(), line: ":server PRIVMSG #chan :hi".into() };
        let mut buf = Vec::new();
        write_frame(&mut buf, &msg).await.unwrap();

        let mut cursor = Cursor::new(buf);
        let got = read_frame(&mut cursor).await.unwrap().expect("expected a frame");
        match got {
            IpcMessage::RawLine { conn_id, line } => {
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
        let msg = IpcMessage::RawLine { conn_id: "n".into(), line: "x".into() };
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
