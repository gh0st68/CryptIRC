/// logs.rs — Encrypted append-only log storage (per-user encryption)

use anyhow::Result;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::{crypto::CryptoManager, LogLine};

pub struct EncryptedLogger {
    data_dir: String,
    crypto:   Arc<CryptoManager>,
    /// Per-user monotonic message ID counter
    seq: Mutex<HashMap<String, u64>>,
}

impl EncryptedLogger {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self { data_dir: data_dir.to_string(), crypto, seq: Mutex::new(HashMap::new()) }
    }

    pub fn data_dir(&self) -> &str { &self.data_dir }

    /// Get next message ID for a user (loads from disk on first call per session)
    async fn next_id(&self, username: &str) -> u64 {
        let mut map = self.seq.lock().await;
        let entry = map.entry(username.to_string()).or_insert(0);
        if *entry == 0 {
            let path = self.seq_path(username);
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                *entry = content.trim().parse().unwrap_or(0);
            }
        }
        *entry += 1;
        let id = *entry;
        drop(map);
        // Persist counter (best-effort)
        let path = self.seq_path(username);
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let _ = tokio::fs::write(&path, id.to_string()).await;
        id
    }

    fn seq_path(&self, username: &str) -> PathBuf {
        PathBuf::from(&self.data_dir)
            .join("logs")
            .join(format!(".seq_{}", sanitize_lossy(username)))
    }

    /// Append a message to the log; returns the assigned msg_id.
    pub async fn append(
        &self, username: &str, conn_id: &str, target: &str,
        ts: i64, from: &str, text: &str, kind: &str,
    ) -> u64 {
        if !self.crypto.is_unlocked(username).await { return 0; }
        let id = self.next_id(username).await;
        let record    = serde_json::json!({ "id": id, "ts": ts, "from": from, "text": text, "kind": kind });
        let plaintext = record.to_string();
        match self.crypto.encrypt(username, plaintext.as_bytes()).await {
            Ok(enc) => {
                let path = self.log_path(conn_id, target, ts);
                if let Some(parent) = path.parent() {
                    let _ = tokio::fs::create_dir_all(parent).await;
                }
                if let Ok(mut file) = tokio::fs::OpenOptions::new()
                    .create(true).append(true).open(&path).await
                {
                    let _ = file.write_all(format!("{}\n", enc).as_bytes()).await;
                    let _ = file.flush().await;
                }
            }
            Err(e) => tracing::warn!("Log encrypt failed: {}", e),
        }
        id
    }

    pub async fn read_logs(&self, username: &str, conn_id: &str, target: &str, limit: usize) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let safe_limit = limit.min(10000);

        let lines = self.read_all_lines(username, conn_id, target).await?;

        let start = lines.len().saturating_sub(safe_limit);
        Ok(lines[start..].to_vec())
    }

    /// Return all messages with id > after_id for a given target (for sync).
    pub async fn read_logs_since(&self, username: &str, conn_id: &str, target: &str, after_id: u64) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }

        let lines = self.read_all_lines(username, conn_id, target).await?;
        let filtered: Vec<LogLine> = lines.into_iter().filter(|l| l.id > after_id).collect();
        Ok(filtered)
    }

    /// Read and decrypt all log lines for a target (shared by read_logs and read_logs_since).
    async fn read_all_lines(&self, username: &str, conn_id: &str, target: &str) -> Result<Vec<LogLine>> {
        let dir = PathBuf::from(&self.data_dir)
            .join("logs")
            .join(sanitize_path_component(conn_id)?)
            .join(sanitize_path_component(target)?);

        let mut day_files: Vec<PathBuf> = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let p = e.path();
                if p.extension().map(|x| x == "log").unwrap_or(false) {
                    day_files.push(p);
                }
            }
        }
        day_files.sort();

        let mut lines: Vec<LogLine> = Vec::new();
        for path in day_files {
            if let Ok(content) = tokio::fs::read_to_string(&path).await {
                for enc_line in content.lines() {
                    if enc_line.is_empty() { continue; }
                    match self.crypto.decrypt(username, enc_line).await {
                        Ok(plain) => {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) {
                                lines.push(LogLine {
                                    id:   v["id"].as_u64().unwrap_or(0),
                                    ts:   v["ts"].as_i64().unwrap_or(0),
                                    from: v["from"].as_str().unwrap_or("").to_string(),
                                    text: v["text"].as_str().unwrap_or("").to_string(),
                                    kind: v["kind"].as_str().unwrap_or("privmsg").to_string(),
                                });
                            }
                        }
                        Err(e) => tracing::warn!("Log decrypt failed: {}", e),
                    }
                }
            }
        }

        Ok(lines)
    }

    fn log_path(&self, conn_id: &str, target: &str, ts: i64) -> PathBuf {
        let safe_conn   = sanitize_lossy(conn_id);
        let safe_target = sanitize_lossy(target);
        let dt = chrono::DateTime::from_timestamp(ts, 0)
            .unwrap_or_else(|| chrono::Utc::now().into());
        let date = dt.date_naive().to_string();
        PathBuf::from(&self.data_dir)
            .join("logs")
            .join(safe_conn)
            .join(safe_target)
            .join(format!("{}.log", date))
    }
}

fn sanitize_path_component(s: &str) -> Result<String> {
    let out = sanitize_lossy(s);
    if out.is_empty()        { anyhow::bail!("Empty path component"); }
    if out == ".."           { anyhow::bail!("Path traversal attempt"); }
    if out.contains("..") || out.starts_with('.') {
        anyhow::bail!("Invalid path component");
    }
    Ok(out)
}

fn sanitize_lossy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dot = false;
    for c in s.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
            last_dot = false;
        } else if c == '.' && !last_dot {
            out.push('_');
            last_dot = true;
        } else {
            out.push('_');
            last_dot = false;
        }
    }
    out.trim_matches('_').to_string()
}
