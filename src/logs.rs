/// logs.rs — Encrypted append-only log storage (per-user encryption)

use anyhow::Result;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use crate::{crypto::CryptoManager, LogLine};

/// Hard ceiling on how many decrypted lines a single read request may
/// materialize in RAM. Without this, a target with a huge history forces the
/// whole (decrypted) history into memory before `limit` is applied. Tail/before
/// reads stop once they have `limit` lines; this bounds the scan-everything
/// paths (read_tail / read_logs_since) so one request can't exhaust memory.
const MAX_DECRYPT_LINES: usize = 50_000;

/// Hard ceiling on how many decrypted lines a single search request may scan.
const MAX_SEARCH_SCAN_LINES: usize = 50_000;

/// Default and absolute caps for search result counts.
const SEARCH_DEFAULT_LIMIT: usize = 500;
const SEARCH_MAX_LIMIT: usize = 1000;

/// Minimum query length for search_logs (shorter queries return empty).
const SEARCH_MIN_QUERY_LEN: usize = 2;

pub struct EncryptedLogger {
    data_dir: String,
    crypto:   Arc<CryptoManager>,
    /// Per-user monotonic message ID counter, sharded by username.
    ///
    /// `seq_locks` maps a username to its own `Mutex<u64>`. The outer mutex is
    /// held only briefly to look up (or create) a user's lock; all FS I/O and
    /// the await points that go with it happen under the *per-user* lock. That
    /// way one user's slow disk can't wedge id issuance for every other user
    /// (which a single global lock held across `.await` would do — see #53).
    seq_locks: Mutex<HashMap<String, Arc<Mutex<u64>>>>,
}

impl EncryptedLogger {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self { data_dir: data_dir.to_string(), crypto, seq_locks: Mutex::new(HashMap::new()) }
    }

    pub fn data_dir(&self) -> &str { &self.data_dir }

    /// Fetch (or lazily create) the per-user sequence lock. The global map lock
    /// is held only for this cheap lookup, never across FS I/O.
    async fn user_seq_lock(&self, username: &str) -> Arc<Mutex<u64>> {
        let mut map = self.seq_locks.lock().await;
        map.entry(username.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(0)))
            .clone()
    }

    /// Get next message ID for a user (loads from disk on first call per session).
    ///
    /// Locking is sharded per user (#53): we take the user's own lock, do all
    /// disk work under it, then release. A stall on one user's disk only blocks
    /// that user's id issuance, not the whole process.
    async fn next_id(&self, username: &str) -> u64 {
        let lock = self.user_seq_lock(username).await;
        let mut cur = lock.lock().await;
        if *cur == 0 {
            let path = self.seq_path(username);
            match tokio::fs::read_to_string(&path).await {
                Ok(content) => match content.trim().parse::<u64>() {
                    Ok(v) => *cur = v,
                    Err(e) => {
                        // #50: don't silently reset to 0 on a corrupt .seq file —
                        // that would re-issue already-used ids. Recover the high
                        // water mark by scanning the user's existing logs.
                        tracing::warn!(
                            "Corrupt .seq for {} ({}): recovering max id from logs",
                            username, e
                        );
                        *cur = self.recover_max_id(username).await;
                    }
                },
                Err(_) => {
                    // No .seq yet: this could be a fresh user OR a lost counter
                    // file with logs still on disk. Recover from logs to be safe.
                    *cur = self.recover_max_id(username).await;
                }
            }
        }
        *cur += 1;
        let id = *cur;
        // Persist the counter while STILL holding the (per-user) lock. If the
        // write happened after releasing it, two concurrent callers for the same
        // user could persist out of order — writing N then N-1 — leaving the
        // on-disk value below the max id actually issued; after a restart next_id
        // would reload the stale value and re-issue ids, breaking the monotonic
        // msg_id invariant the sync/dedup logic relies on. The write is a few
        // bytes and is done atomically (#50: tmp + rename).
        let path = self.seq_path(username);
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        if let Err(e) = atomic_write(&path, id.to_string().as_bytes()).await {
            tracing::error!("Failed to persist .seq for {}: {}", username, e);
        }
        drop(cur);
        id
    }

    /// Scan all of a user's existing logs and return the maximum msg_id seen
    /// (0 if there are none). Used to recover the sequence counter when the
    /// `.seq` file is missing or corrupt (#50). L10: this recovers the max *logged*
    /// id — an id that was issued (via next_id) but whose append FAILED before any
    /// line was written leaves no on-disk record, so it can be re-issued. That is
    /// harmless (no on-disk row exists to collide with); the guarantee is only that
    /// we never re-issue an id that actually made it to disk.
    async fn recover_max_id(&self, username: &str) -> u64 {
        let logs_root = PathBuf::from(&self.data_dir).join("logs");
        let mut max_id: u64 = 0;
        // logs/<conn>/<target>/<date>.log
        let mut conns = match tokio::fs::read_dir(&logs_root).await {
            Ok(rd) => rd,
            Err(_) => return 0,
        };
        while let Ok(Some(conn_entry)) = conns.next_entry().await {
            let conn_path = conn_entry.path();
            if !conn_path.is_dir() { continue; }
            let mut targets = match tokio::fs::read_dir(&conn_path).await {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            while let Ok(Some(target_entry)) = targets.next_entry().await {
                let target_path = target_entry.path();
                if !target_path.is_dir() { continue; }
                let mut days = match tokio::fs::read_dir(&target_path).await {
                    Ok(rd) => rd,
                    Err(_) => continue,
                };
                while let Ok(Some(day_entry)) = days.next_entry().await {
                    let p = day_entry.path();
                    if p.extension().map(|x| x == "log").unwrap_or(false) {
                        if let Ok(content) = tokio::fs::read_to_string(&p).await {
                            for enc_line in content.lines() {
                                if enc_line.is_empty() { continue; }
                                if let Ok(plain) = self.crypto.decrypt(username, enc_line).await {
                                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) {
                                        let id = v["id"].as_u64().unwrap_or(0);
                                        if id > max_id { max_id = id; }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        max_id
    }

    fn seq_path(&self, username: &str) -> PathBuf {
        PathBuf::from(&self.data_dir)
            .join("logs")
            .join(format!(".seq_{}", sanitize_username(username)))
    }

    /// Append a message to the log; returns the assigned msg_id, or 0 if the
    /// message was NOT logged.
    ///
    /// 0 reliably means "not written" (#51): we only return a non-zero id once
    /// the line has actually been encrypted, written, AND flushed to disk. Any
    /// failure along the way (locked vault, bad target, encrypt error, open/
    /// write/flush error) logs the cause and returns 0 so the caller doesn't
    /// hand out an id for a message that isn't in the log.
    pub async fn append(
        &self, username: &str, conn_id: &str, target: &str,
        ts: i64, from: &str, text: &str, kind: &str,
    ) -> u64 {
        if !self.crypto.is_unlocked(username).await { return 0; }
        // Only log to a path the read/delete side can actually reach. We now
        // WRITE using encode_path_component (a disambiguating, collision-free
        // encoding — see #52), and the reader validates the same way; reject
        // anything that can't be addressed.
        if encode_path_component(conn_id).is_err() || encode_path_component(target).is_err() {
            return 0;
        }
        let id = self.next_id(username).await;
        let record    = serde_json::json!({ "id": id, "ts": ts, "from": from, "text": text, "kind": kind });
        let plaintext = record.to_string();
        let enc = match self.crypto.encrypt(username, plaintext.as_bytes()).await {
            Ok(enc) => enc,
            Err(e) => {
                tracing::error!("Log encrypt failed for {}: {}", username, e);
                return 0;
            }
        };
        let path = self.log_path(conn_id, target, ts);
        if let Some(parent) = path.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                tracing::error!("Log dir create failed ({:?}): {}", parent, e);
                return 0;
            }
        }
        let mut file = match tokio::fs::OpenOptions::new()
            .create(true).append(true).open(&path).await
        {
            Ok(f) => f,
            Err(e) => {
                tracing::error!("Log open failed ({:?}): {}", path, e);
                return 0;
            }
        };
        if let Err(e) = file.write_all(format!("{}\n", enc).as_bytes()).await {
            tracing::error!("Log write failed ({:?}): {}", path, e);
            return 0;
        }
        if let Err(e) = file.flush().await {
            tracing::error!("Log flush failed ({:?}): {}", path, e);
            return 0;
        }
        // Only now is the line durably appended — safe to report its id.
        id
    }

    pub async fn read_logs(&self, username: &str, conn_id: &str, target: &str, limit: usize) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        // Tail read: only the most-recent `limit` lines are wanted, so read
        // newest-first and stop early instead of decrypting the full history (#12).
        let safe_limit = limit.min(MAX_DECRYPT_LINES);
        self.read_tail(username, conn_id, target, safe_limit, MAX_DECRYPT_LINES, None).await
    }

    /// Return all messages with id > after_id for a given target (for sync).
    pub async fn read_logs_since(&self, username: &str, conn_id: &str, target: &str, after_id: u64) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }

        // This is an inherently "scan everything newer than X" query; bound the
        // total lines decrypted with the hard ceiling (#12). We read the most
        // recent MAX_DECRYPT_LINES and filter — older-than-ceiling history won't
        // be re-synced, which is acceptable vs. unbounded memory use.
        let lines = self.read_tail(username, conn_id, target, MAX_DECRYPT_LINES, MAX_DECRYPT_LINES, None).await?;
        let filtered: Vec<LogLine> = lines.into_iter().filter(|l| l.id > after_id).collect();
        Ok(filtered)
    }

    /// Search ALL logs for a target, returning matching lines in chronological
    /// order. Case-insensitive substring match on the message text, skipping
    /// status/system lines (from == "*").
    ///
    /// Defensive limits (#13): the query must be at least SEARCH_MIN_QUERY_LEN
    /// chars (else empty result); `limit` is clamped — 0 (or anything) maps to
    /// at most SEARCH_MAX_LIMIT, defaulting to SEARCH_DEFAULT_LIMIT when 0 — so
    /// it is never treated as "unbounded". At most MAX_SEARCH_SCAN_LINES of the
    /// most-recent history are scanned.
    pub async fn search_logs(&self, username: &str, conn_id: &str, target: &str, query: &str, limit: usize) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let q = query.trim().to_lowercase();
        // Require a minimum query length to avoid scanning everything for a
        // trivial/empty query.
        if q.chars().count() < SEARCH_MIN_QUERY_LEN { return Ok(Vec::new()); }
        // Clamp the effective result limit: 0 is NOT unbounded.
        let eff_limit = if limit == 0 { SEARCH_DEFAULT_LIMIT } else { limit };
        let eff_limit = eff_limit.min(SEARCH_MAX_LIMIT);

        // Scan at most the most-recent MAX_SEARCH_SCAN_LINES lines, newest-first,
        // collecting matches until we have eff_limit of them.
        let matches = self
            .read_tail(username, conn_id, target, eff_limit, MAX_SEARCH_SCAN_LINES, Some(&q))
            .await?;
        Ok(matches)
    }

    /// Return up to `limit` messages with ts < `before`, the most-recent such
    /// (chronological order). Reads newest-first and stops once `limit` matching
    /// lines are collected, instead of materializing the whole history (#12).
    pub async fn read_logs_before(&self, username: &str, conn_id: &str, target: &str, before: i64, limit: usize) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let safe_limit = limit.min(MAX_DECRYPT_LINES);
        self.read_tail_before(username, conn_id, target, before, safe_limit).await
    }

    /// Resolve the on-disk directories for a target's logs. Returns EVERY dir that
    /// exists — both the new disambiguating encoding (what we write today) AND the
    /// legacy lossy scheme (pre-#52 history) when they differ and both exist.
    ///
    /// P2 fix (#52): the prior version preferred the new dir and only fell back to
    /// legacy when the new dir was ABSENT. For channel targets the two encodings
    /// differ (`#rust` → `_23rust` vs `rust`), so the first post-upgrade append
    /// created the new dir and orphaned ALL legacy history. Returning both dirs and
    /// merging their date-named files (day_files) keeps pre-upgrade history visible.
    /// This is symmetric with delete_target, which already removes both dirs.
    async fn resolve_read_dirs(&self, conn_id: &str, target: &str) -> Result<Vec<PathBuf>> {
        let logs_root = PathBuf::from(&self.data_dir).join("logs");
        let mut dirs: Vec<PathBuf> = Vec::new();
        // New scheme (what we write today).
        let new_dir = logs_root
            .join(encode_path_component(conn_id)?)
            .join(encode_path_component(target)?);
        if tokio::fs::metadata(&new_dir).await.is_ok() {
            dirs.push(new_dir.clone());
        }
        // Legacy dir (pre-#52, sanitize_lossy). Include it whenever it exists and
        // differs from the new dir, so history written before the encoding change
        // is still read (#52). The legacy sanitizer can reject some inputs (e.g.
        // "#.."); in that case there simply is no addressable legacy dir.
        if let (Ok(lc), Ok(lt)) = (sanitize_path_component(conn_id), sanitize_path_component(target)) {
            let legacy_dir = logs_root.join(lc).join(lt);
            if legacy_dir != new_dir && tokio::fs::metadata(&legacy_dir).await.is_ok() {
                dirs.push(legacy_dir);
            }
        }
        Ok(dirs)
    }

    /// Collect the sorted (chronological) list of `*.log` day files for a target,
    /// merged across the new and legacy dirs (#52). Files are sorted by their
    /// date-based FILE NAME (not full path) so records from the two dirs interleave
    /// chronologically rather than grouping by directory.
    async fn day_files(&self, conn_id: &str, target: &str) -> Result<Vec<PathBuf>> {
        let dirs = self.resolve_read_dirs(conn_id, target).await?;
        if dirs.is_empty() { return Ok(Vec::new()); }
        let mut day_files: Vec<PathBuf> = Vec::new();
        for dir in &dirs {
            if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    let p = e.path();
                    if p.extension().map(|x| x == "log").unwrap_or(false) {
                        day_files.push(p);
                    }
                }
            }
        }
        // Sort by the date-named FILE NAME so files from the new and legacy dirs
        // interleave chronologically (lexicographic == chronological for "YYYY-MM-DD.log").
        // A stable tiebreak keeps same-date files from the two dirs adjacent and ordered.
        day_files.sort_by(|a, b| {
            let an = a.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            let bn = b.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            an.cmp(&bn).then_with(|| a.cmp(b))
        });
        Ok(day_files)
    }

    /// Parse a single decrypted JSON record into a LogLine.
    fn parse_line(plain: &[u8]) -> Option<LogLine> {
        let v = serde_json::from_slice::<serde_json::Value>(plain).ok()?;
        Some(LogLine {
            id:   v["id"].as_u64().unwrap_or(0),
            ts:   v["ts"].as_i64().unwrap_or(0),
            from: v["from"].as_str().unwrap_or("").to_string(),
            text: v["text"].as_str().unwrap_or("").to_string(),
            kind: v["kind"].as_str().unwrap_or("privmsg").to_string(),
        })
    }

    /// Read the most-recent `limit` log lines for a target, newest-first, and
    /// return them in chronological order. Stops decrypting once `limit` lines
    /// are collected, so a tail read never touches the whole history (#12).
    ///
    /// If `filter_query` is Some, only lines whose text contains the (already
    /// lowercased) query and whose `from != "*"` count toward the limit (used by
    /// search). Decryption is also hard-capped at `max_scan` lines scanned.
    async fn read_tail(
        &self, username: &str, conn_id: &str, target: &str,
        limit: usize, max_scan: usize, filter_query: Option<&str>,
    ) -> Result<Vec<LogLine>> {
        if limit == 0 { return Ok(Vec::new()); }
        let day_files = self.day_files(conn_id, target).await?;

        let mut collected: Vec<LogLine> = Vec::new();
        let mut scanned: usize = 0;
        // Iterate day files newest-first.
        'outer: for path in day_files.iter().rev() {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                // Within a file, iterate lines newest-first too.
                for enc_line in content.lines().rev() {
                    if enc_line.is_empty() { continue; }
                    if scanned >= max_scan { break 'outer; }
                    scanned += 1;
                    match self.crypto.decrypt(username, enc_line).await {
                        Ok(plain) => {
                            if let Some(line) = Self::parse_line(&plain) {
                                if let Some(q) = filter_query {
                                    if line.from == "*" || !line.text.to_lowercase().contains(q) {
                                        continue;
                                    }
                                }
                                collected.push(line);
                                if collected.len() >= limit { break 'outer; }
                            }
                        }
                        Err(e) => tracing::warn!("Log decrypt failed: {}", e),
                    }
                }
            }
        }
        // collected is newest-first; reverse to chronological order.
        collected.reverse();
        Ok(collected)
    }

    /// Read up to `limit` most-recent lines with ts < `before`, newest-first,
    /// returned chronologically. Stops once `limit` matches are collected (#12).
    async fn read_tail_before(
        &self, username: &str, conn_id: &str, target: &str,
        before: i64, limit: usize,
    ) -> Result<Vec<LogLine>> {
        if limit == 0 { return Ok(Vec::new()); }
        let day_files = self.day_files(conn_id, target).await?;

        let mut collected: Vec<LogLine> = Vec::new();
        let mut scanned: usize = 0;
        'outer: for path in day_files.iter().rev() {
            if let Ok(content) = tokio::fs::read_to_string(path).await {
                for enc_line in content.lines().rev() {
                    if enc_line.is_empty() { continue; }
                    if scanned >= MAX_DECRYPT_LINES { break 'outer; }
                    scanned += 1;
                    match self.crypto.decrypt(username, enc_line).await {
                        Ok(plain) => {
                            if let Some(line) = Self::parse_line(&plain) {
                                if line.ts < before {
                                    collected.push(line);
                                    if collected.len() >= limit { break 'outer; }
                                }
                            }
                        }
                        Err(e) => tracing::warn!("Log decrypt failed: {}", e),
                    }
                }
            }
        }
        collected.reverse();
        Ok(collected)
    }

    /// Permanently delete all logs for a target (channel or query). Returns
    /// Ok(true) if a directory existed and was removed, Ok(false) if there was
    /// nothing to delete. The per-user sequence counter is intentionally NOT
    /// reset — new messages keep getting monotonically larger ids so any
    /// in-flight sync from another session can't resurrect deleted records.
    ///
    /// Deletes both the new-scheme dir and the legacy lossy dir if present, so
    /// "clear history" doesn't leave old-scheme records behind (#52).
    pub async fn delete_target(&self, username: &str, conn_id: &str, target: &str) -> Result<bool> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let logs_root = PathBuf::from(&self.data_dir).join("logs");
        let new_dir = logs_root
            .join(encode_path_component(conn_id)?)
            .join(encode_path_component(target)?);

        let mut removed = false;
        if tokio::fs::metadata(&new_dir).await.is_ok() {
            tokio::fs::remove_dir_all(&new_dir).await?;
            removed = true;
        }
        // Also remove any legacy (pre-#52) dir so "clear history" doesn't leave
        // old-scheme records behind. The legacy sanitizer may reject the input;
        // if so there's no legacy dir to clear. Skip if it resolves to new_dir.
        if let (Ok(lc), Ok(lt)) = (sanitize_path_component(conn_id), sanitize_path_component(target)) {
            let legacy_dir = logs_root.join(lc).join(lt);
            if legacy_dir != new_dir && tokio::fs::metadata(&legacy_dir).await.is_ok() {
                tokio::fs::remove_dir_all(&legacy_dir).await?;
                removed = true;
            }
        }
        Ok(removed)
    }

    fn log_path(&self, conn_id: &str, target: &str, ts: i64) -> PathBuf {
        // Write with the disambiguating encoding so distinct targets/conn_ids
        // never collide onto the same directory (#52). encode_path_component is
        // validated in append() before we get here.
        let safe_conn   = encode_path_component(conn_id).unwrap_or_else(|_| "_".to_string());
        let safe_target = encode_path_component(target).unwrap_or_else(|_| "_".to_string());
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

/// Atomically write `bytes` to `path` (write to a sibling tmp file, then
/// rename over the target). Prevents a torn/partial `.seq` file if the process
/// dies mid-write — a partial write is exactly what produces the corrupt-counter
/// case in #50.
async fn atomic_write(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = match path.file_name() {
        Some(name) => {
            let mut t = name.to_os_string();
            t.push(".tmp");
            path.with_file_name(t)
        }
        None => path.with_extension("tmp"),
    };
    {
        let mut f = tokio::fs::File::create(&tmp).await?;
        f.write_all(bytes).await?;
        f.flush().await?;
        f.sync_all().await?;
    }
    tokio::fs::rename(&tmp, path).await?;
    Ok(())
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

/// Reversible, collision-free path-component encoding used for WRITING log dirs
/// (#52). Unlike sanitize_lossy — which maps many distinct inputs (e.g. "#chan"
/// vs "chan", "a.b" vs "a_b") onto the same directory and so mixes unrelated
/// channel/query history — this preserves a 1:1 mapping: every distinct input
/// yields a distinct, filesystem-safe output.
///
/// Scheme: characters in the safe set [A-Za-z0-9-] pass through unchanged;
/// a literal '_' is escaped (since '_' is also our escape lead-in). Any
/// other byte (including '#', '.', '/', unicode, etc.) is encoded as `_<HH>`
/// where HH is its uppercase hex. Because every produced component is non-empty
/// for any non-empty input, can never be "." / ".." (those would be encoded),
/// and never starts with a bare '.', it is also path-traversal safe.
///
/// Errors only on an empty input (nothing addressable to write).
fn encode_path_component(s: &str) -> Result<String> {
    if s.is_empty() { anyhow::bail!("Empty path component"); }
    let mut out = String::with_capacity(s.len() + 4);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' => out.push(b as char),
            // '_' is our escape character, so encode it explicitly to keep the
            // mapping unambiguous/reversible.
            _ => {
                out.push('_');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    Ok(out)
}

/// Per-user path key for the .seq counter. Uses the SAME non-trimming,
/// collision-preserving sanitizer as the per-user vault/e2e dirs
/// (crypto::sanitize_username / e2e::user_dir): filter to the registered
/// username charset ([alphanumeric] | '_' | '-') and DROP everything else,
/// without trimming. Unlike sanitize_lossy (which trim_matches('_')), this
/// keeps distinct registered usernames distinct (e.g. "_alice" vs "alice"),
/// preventing two users from sharing one .seq file and corrupting msg_ids.
/// Identity for all valid usernames (auth::is_safe_username enforces the
/// same charset), so behavior is unchanged for normal inputs.
fn sanitize_username(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-').collect()
}

/// Legacy lossy sanitizer. Retained ONLY for READ fallback (resolve_read_dir)
/// and traversal validation (sanitize_path_component) against pre-#52 logs;
/// new writes use encode_path_component. Lossy: many inputs collapse together.
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
