/// logs.rs — Encrypted append-only log storage
///
/// Fixes applied:
///   C3 — sanitize() now rejects path traversal ("..") components

use anyhow::Result;
use std::{path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;

use crate::{crypto::CryptoManager, LogLine};

pub struct EncryptedLogger {
    data_dir: String,
    crypto:   Arc<CryptoManager>,
}

impl EncryptedLogger {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self { data_dir: data_dir.to_string(), crypto }
    }

    pub fn data_dir(&self) -> &str { &self.data_dir }

    pub async fn append(
        &self, conn_id: &str, target: &str,
        ts: i64, from: &str, text: &str, kind: &str,
    ) {
        if !self.crypto.is_unlocked().await { return; }
        let record    = serde_json::json!({ "ts": ts, "from": from, "text": text, "kind": kind });
        let plaintext = record.to_string();
        match self.crypto.encrypt(plaintext.as_bytes()).await {
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
    }

    pub async fn read_logs(&self, conn_id: &str, target: &str, limit: usize) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked().await { anyhow::bail!("Vault locked"); }
        let safe_limit = limit.min(10000);

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
                    match self.crypto.decrypt(enc_line).await {
                        Ok(plain) => {
                            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) {
                                lines.push(LogLine {
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

        let start = lines.len().saturating_sub(safe_limit);
        Ok(lines[start..].to_vec())
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

/// C3: Reject any path component that is or contains "..".
/// Returns an error if the component is unsafe, otherwise returns the sanitized string.
fn sanitize_path_component(s: &str) -> Result<String> {
    let out = sanitize_lossy(s);
    // After lossy sanitize, reject if it's empty, is ".", or starts with ".."
    if out.is_empty()        { anyhow::bail!("Empty path component"); }
    if out == ".."           { anyhow::bail!("Path traversal attempt"); }
    if out.contains("..") || out.starts_with('.') {
        anyhow::bail!("Invalid path component");
    }
    Ok(out)
}

/// Replace all non-safe characters with '_', no dot sequences allowed.
fn sanitize_lossy(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_dot = false;
    for c in s.chars() {
        if c.is_alphanumeric() || c == '-' || c == '_' {
            out.push(c);
            last_dot = false;
        } else if c == '.' && !last_dot {
            // Allow single dots but never consecutive
            out.push('_'); // Replace dots with underscores to be safe
            last_dot = true;
        } else {
            out.push('_');
            last_dot = false;
        }
    }
    // Trim leading/trailing underscores that could be problematic
    out.trim_matches('_').to_string()
}
