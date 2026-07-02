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
    /// De-dupe set for undecryptable-line warnings (#F22). A permanently-corrupt
    /// line (e.g. a NUL-filled tail after an unclean shutdown → "Invalid symbol
    /// 0") would otherwise log a warning on EVERY read of that target. We key by
    /// a hash of the ciphertext so each distinct bad line warns at most once; the
    /// line is still skipped regardless. Capped so a flood of distinct corrupt
    /// lines can't grow it without bound.
    warned_bad_lines: Mutex<std::collections::HashSet<u64>>,
}

impl EncryptedLogger {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self {
            data_dir: data_dir.to_string(),
            crypto,
            seq_locks: Mutex::new(HashMap::new()),
            warned_bad_lines: Mutex::new(std::collections::HashSet::new()),
        }
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

    /// Scan the caller's OWN existing logs and return the maximum msg_id seen
    /// (0 if there are none). Used to recover the sequence counter when the
    /// `.seq` file is missing or corrupt (#50). L10: this recovers the max *logged*
    /// id — an id that was issued (via next_id) but whose append FAILED before any
    /// line was written leaves no on-disk record, so it can be re-issued. That is
    /// harmless (no on-disk row exists to collide with); the guarantee is only that
    /// we never re-issue an id that actually made it to disk.
    ///
    /// #10: the logs tree is namespaced only by conn_id (a UUID), never by
    /// username, so a blind walk of `logs/` would read and attempt to AES-GCM
    /// decrypt EVERY tenant's history — an unbounded cross-tenant decrypt sweep
    /// (DoS) and a timing oracle for the whole corpus size. Recovery is therefore
    /// scoped to THIS user's own conn_ids (their saved networks live at
    /// `networks/<user>/<conn_id>.json`) and capped at MAX_DECRYPT_LINES decrypt
    /// attempts, scanning newest-first so the highest (most recent) id is seen
    /// before the cap can cut the scan short. Reachable history all lives under a
    /// current network, so scoping never lowers the recovered max for data the
    /// client can still request; only unreachable logs of deleted networks are
    /// skipped, and re-issuing their ids is harmless (nothing reachable collides).
    async fn recover_max_id(&self, username: &str) -> u64 {
        let logs_root    = PathBuf::from(&self.data_dir).join("logs");
        // Raw username matches how networks/<user>/ is created in main.rs; it is
        // validated (is_safe_username) at the auth boundary before reaching here.
        let networks_dir = PathBuf::from(&self.data_dir).join("networks").join(username);

        // Gather the day files of ONLY this user's own conn_ids.
        let mut day_files: Vec<PathBuf> = Vec::new();
        let mut nets = match tokio::fs::read_dir(&networks_dir).await {
            Ok(rd) => rd,
            Err(_) => return 0,
        };
        while let Ok(Some(net_entry)) = nets.next_entry().await {
            let net_path = net_entry.path();
            // Only "<conn_id>.json" config files name a conn_id (skip .tmp etc).
            if !net_path.extension().map(|x| x == "json").unwrap_or(false) { continue; }
            let conn_id = match net_path.file_stem().and_then(|s| s.to_str()) {
                Some(s) => s.to_string(),
                None => continue,
            };
            // Resolve the exact dir append() writes to for this conn_id. For a UUID
            // this is an identity mapping; a non-UUID stem simply encodes to a dir
            // that doesn't exist, so it can never escape logs/.
            let conn_dir = match encode_path_component(&conn_id) {
                Ok(enc) => logs_root.join(enc),
                Err(_) => continue,
            };
            let mut targets = match tokio::fs::read_dir(&conn_dir).await {
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
                        day_files.push(p);
                    }
                }
            }
        }

        // Newest date first: file names are "YYYY-MM-DD.log", so lexicographic
        // order == chronological order. ids are monotonic per user, so the newest
        // file holds the highest id — scanning newest-first guarantees the max is
        // seen before the MAX_DECRYPT_LINES cap can stop the scan short.
        day_files.sort_by(|a, b| {
            let an = a.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            let bn = b.file_name().map(|n| n.to_os_string()).unwrap_or_default();
            an.cmp(&bn)
        });

        let mut max_id: u64 = 0;
        let mut scanned: usize = 0;
        'outer: for p in day_files.iter().rev() {
            // #11: reconstruct the AAD from the on-disk directory names (the
            // encoded conn/target that append() bound the line to) plus the
            // date-named file, so AAD-bound lines decrypt and count toward
            // max_id; pre-#11 lines fall back to a plain decrypt.
            let date       = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let enc_target = p.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let enc_conn   = p.parent().and_then(|d| d.parent()).and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let aad        = log_aad(enc_conn, enc_target, date);
            // #F21: bounded streaming read of the newest lines instead of
            // read_to_string materializing the whole day file.
            let enc_lines = read_recent_lines(p, MAX_DECRYPT_LINES).await;
            for enc_line in enc_lines.iter().rev() {
                if scanned >= MAX_DECRYPT_LINES { break 'outer; }
                scanned += 1;
                if let Ok(plain) = self.decrypt_log_line(username, enc_line, &aad).await {
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&plain) {
                        let id = v["id"].as_u64().unwrap_or(0);
                        if id > max_id { max_id = id; }
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
        let path = self.log_path(conn_id, target, ts);
        // Bind the ciphertext to conn/target/date so it can't be relocated
        // between log files and still decrypt (#11). Encoded components + the
        // date-named file match exactly what the reader reconstructs.
        let enc_conn   = encode_path_component(conn_id).unwrap_or_else(|_| "_".to_string());
        let enc_target = encode_path_component(target).unwrap_or_else(|_| "_".to_string());
        let date       = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        let aad        = log_aad(&enc_conn, &enc_target, date);
        let enc = match self.crypto.encrypt_aad(username, plaintext.as_bytes(), &aad).await {
            Ok(enc) => enc,
            Err(e) => {
                tracing::error!("Log encrypt failed for {}: {}", username, e);
                return 0;
            }
        };
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

    /// Return un-synced messages (id > after_id) for a target, OLDEST-first in
    /// the result, bounded to MAX_DECRYPT_LINES decrypt/parse ops per call (for
    /// sync).
    ///
    /// #F3: the prior version iterated EVERY day file and decrypted+JSON-parsed
    /// EVERY line on each Sync — only the heap SIZE was capped (bounding memory,
    /// not the decrypt/parse/read work). A client sending after_id=0 skipped
    /// nothing, forcing an unbounded per-request decrypt sweep (CPU/disk DoS).
    /// We now scan NEWEST-first and stop after MAX_DECRYPT_LINES scanned lines,
    /// returning the most-recent bounded window of un-synced (id > after_id)
    /// lines regardless of after_id, sorted oldest→newest — the ordering main.rs
    /// Sync (~3432) and the frontend appendSyncLines expect.
    ///
    /// For a normal sync (the client advances after_id to the largest id it has,
    /// so the gap is small) the newest-first scan reaches the file(s) holding the
    /// un-synced tail and skips fully-synced older files via a one-line probe,
    /// so the ENTIRE gap is returned with no hole. A backlog exceeding
    /// MAX_DECRYPT_LINES un-synced lines returns the newest cap-sized window; the
    /// remaining older tail is not delivered in that single response (the price
    /// of bounding per-request work — see caveat in #F3).
    pub async fn read_logs_since(&self, username: &str, conn_id: &str, target: &str, after_id: u64) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }

        let day_files = self.day_files(conn_id, target).await?;

        let mut collected: Vec<LogLine> = Vec::new();
        let mut scanned: usize = 0;
        // Iterate day files newest-first so the bounded window is the most-recent
        // un-synced tail.
        'outer: for path in day_files.iter().rev() {
            // #11/#F7: derive the AAD from the file's ACTUAL parent (target) and
            // grandparent (conn) directory names — NOT the re-encoded target — so
            // lines under BOTH the new-scheme dir (encode_path_component) and the
            // legacy dir (sanitize_lossy) decrypt. Re-encoding here builds the
            // wrong AAD for legacy-dir files and silently drops them; recover_max_id
            // already derives AAD this way.
            let date       = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let enc_target = path.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let enc_conn   = path.parent().and_then(|d| d.parent()).and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let aad        = log_aad(enc_conn, enc_target, date);

            // #F21: stream the file's most-recent lines with a bounded buffer
            // instead of read_to_string materializing a whole (possibly huge)
            // day file in RAM.
            let enc_lines = read_recent_lines(path, MAX_DECRYPT_LINES).await;

            // Skip a fully-synced file (max id <= after_id) after a cheap probe. NOTE: append()
            // serializes id issuance but NOT the encrypt+write, so under concurrent same-target
            // appends the highest id can be written a few lines before the physical end — the
            // last line is NOT reliably the file's max id. Trusting only the last line could skip
            // a file that still holds an un-synced higher id, permanently dropping it. So take the
            // max id over the last few lines (well above realistic reorder depth, which is bounded
            // by same-target append concurrency) and skip only if THAT max is <= after_id. On
            // decrypt/parse failure fall through to a full scan (correctness over speed). #F3-regression.
            let probe_n = enc_lines.len().min(32);
            let mut probe_max: Option<u64> = None;
            for enc in enc_lines.iter().rev().take(probe_n) {
                if let Ok(plain) = self.decrypt_log_line(username, enc, &aad).await {
                    if let Some(line) = Self::parse_line(&plain) {
                        probe_max = Some(probe_max.map_or(line.id, |m| m.max(line.id)));
                    }
                }
            }
            if let Some(m) = probe_max {
                if m <= after_id { continue; }
            }

            // Scan this file newest-first; stop at the global scan cap (#F3).
            for enc_line in enc_lines.iter().rev() {
                if scanned >= MAX_DECRYPT_LINES { break 'outer; }
                scanned += 1;
                match self.decrypt_log_line(username, enc_line, &aad).await {
                    Ok(plain) => {
                        if let Some(line) = Self::parse_line(&plain) {
                            if line.id > after_id {
                                collected.push(line);
                            }
                        }
                    }
                    Err(e) => self.warn_decrypt_failure(enc_line, &e).await,
                }
            }
        }

        // collected is newest-first; emit chronologically (ascending id).
        collected.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(collected)
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

    /// Decrypt a stored log line. Lines written since #11 are AAD-bound to
    /// conn/target/date; pre-#11 lines had no AAD, so fall back to a plain
    /// decrypt to keep existing history readable.
    async fn decrypt_log_line(&self, username: &str, enc_line: &str, aad: &[u8]) -> Result<Vec<u8>> {
        match self.crypto.decrypt_aad(username, enc_line, aad).await {
            Ok(pt) => Ok(pt),
            Err(_) => self.crypto.decrypt(username, enc_line).await,
        }
    }

    /// Warn about an undecryptable log line AT MOST ONCE per distinct line (#F22).
    /// A permanently-corrupt line (e.g. a NUL-filled tail after an unclean
    /// shutdown → "Invalid symbol 0") would otherwise emit a `warn` on every
    /// subsequent read of that target. Keyed by a hash of the ciphertext so the
    /// first occurrence is still surfaced for diagnosis; repeats are suppressed.
    /// The line is skipped either way — only the log volume changes.
    async fn warn_decrypt_failure(&self, enc_line: &str, err: &anyhow::Error) {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        enc_line.hash(&mut h);
        let key = h.finish();
        {
            let mut seen = self.warned_bad_lines.lock().await;
            if seen.contains(&key) { return; }
            // Bound the set so a flood of distinct corrupt lines can't grow it
            // without limit; once full we simply stop emitting (line still skipped).
            if seen.len() >= 4096 { return; }
            seen.insert(key);
        }
        tracing::warn!("Log decrypt failed (repeats for this line suppressed): {}", err);
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
            // #11/#F7: derive the AAD from the file's ACTUAL parent/grandparent
            // dir names (as recover_max_id does) so both new-scheme and legacy-dir
            // lines decrypt; re-encoding the target would mis-derive the AAD for
            // legacy files and silently drop them.
            let date       = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let enc_target = path.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let enc_conn   = path.parent().and_then(|d| d.parent()).and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let aad        = log_aad(enc_conn, enc_target, date);
            // #F21: stream the newest lines with a bounded buffer instead of
            // read_to_string materializing the whole day file.
            let enc_lines = read_recent_lines(path, max_scan).await;
            // Within a file, iterate lines newest-first too.
            for enc_line in enc_lines.iter().rev() {
                if scanned >= max_scan { break 'outer; }
                scanned += 1;
                match self.decrypt_log_line(username, enc_line, &aad).await {
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
                    Err(e) => self.warn_decrypt_failure(enc_line, &e).await,
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
            // #11/#F7: per-file AAD from the file's ACTUAL parent/grandparent dir
            // names (as recover_max_id does) so both new-scheme and legacy-dir
            // lines decrypt.
            let date       = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let enc_target = path.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let enc_conn   = path.parent().and_then(|d| d.parent()).and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
            let aad        = log_aad(enc_conn, enc_target, date);
            // #F21: bounded streaming read instead of read_to_string.
            let enc_lines = read_recent_lines(path, MAX_DECRYPT_LINES).await;
            for enc_line in enc_lines.iter().rev() {
                if scanned >= MAX_DECRYPT_LINES { break 'outer; }
                scanned += 1;
                match self.decrypt_log_line(username, enc_line, &aad).await {
                    Ok(plain) => {
                        if let Some(line) = Self::parse_line(&plain) {
                            if line.ts < before {
                                collected.push(line);
                                if collected.len() >= limit { break 'outer; }
                            }
                        }
                    }
                    Err(e) => self.warn_decrypt_failure(enc_line, &e).await,
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

/// Stream a day file forward with a buffered reader, retaining at most `cap` of
/// the most-recent NON-EMPTY lines (#F21). read_to_string materialized the whole
/// (possibly huge) day file before `.lines()`, so peak memory per read equaled
/// the largest day-file size. This bounds peak memory to `cap` encrypted lines
/// while streaming the file line-by-line. Returned in file order (oldest→newest);
/// callers iterate `.rev()` for the newest-first scans. The read paths only ever
/// consume the newest `cap` lines of any file, so dropping older lines here is
/// behavior-preserving.
async fn read_recent_lines(path: &std::path::Path, cap: usize) -> Vec<String> {
    use tokio::io::AsyncBufReadExt;
    let file = match tokio::fs::File::open(path).await {
        Ok(f) => f,
        Err(_) => return Vec::new(),
    };
    let mut reader = tokio::io::BufReader::new(file);
    let mut buf: std::collections::VecDeque<String> = std::collections::VecDeque::new();
    let mut raw: Vec<u8> = Vec::new();
    loop {
        raw.clear();
        // Byte-oriented read + lossy decode instead of .lines(): .lines() returns Err on the
        // FIRST invalid-UTF-8 line and `while let Ok(..)` would then truncate the scan, silently
        // dropping every NEWER line after a corrupt one (exactly the lines the tail/sync paths
        // want). read_until never errors on bad bytes, so a corrupt line just becomes a
        // decrypt-failure (skipped + warned later) without hiding the lines past it. #F21-regression.
        match reader.read_until(b'\n', &mut raw).await {
            Ok(0) => break,   // EOF
            Ok(_) => {}
            Err(_) => break,  // genuine I/O error — stop
        }
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) { raw.pop(); }
        if raw.is_empty() { continue; }
        buf.push_back(String::from_utf8_lossy(&raw).into_owned());
        if cap > 0 && buf.len() > cap { buf.pop_front(); }
    }
    buf.into()
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

/// Build the AEAD additional-authenticated-data that binds a log line to its
/// logical location (#11): length-prefixed (encoded conn_id, encoded target,
/// date "YYYY-MM-DD"). Prevents relocating/pasting a ciphertext line between
/// conn/target/date files and having it still decrypt. Length prefixes make the
/// concatenation unambiguous.
fn log_aad(enc_conn: &str, enc_target: &str, date: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(12 + enc_conn.len() + enc_target.len() + date.len());
    for part in [enc_conn, enc_target, date] {
        aad.extend_from_slice(&(part.len() as u32).to_be_bytes());
        aad.extend_from_slice(part.as_bytes());
    }
    aad
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
