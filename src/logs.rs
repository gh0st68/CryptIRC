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

/// r3 C1-3: byte ceilings beside the line ceilings. A logged line can be ~90 KB (a
/// ~64 KiB Send body, JSON-wrapped, encrypted, base64), so "50,000 lines" alone allowed
/// multi-GB buffers. MAX_READ_BYTES bounds the ENCRYPTED lines one day-file read keeps
/// (normal ~300-byte lines: the full 50,000 still fit, so ordinary history reads are
/// unchanged); MAX_REPLY_BYTES bounds the DECRYPTED text one GetLogs / Sync / Search
/// reply carries (≈10,000 ordinary lines — more than any client keeps; every reply still
/// holds at least one line, and paging/sync continue from where it stopped).
const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_REPLY_BYTES: usize = 2 * 1024 * 1024;
/// Boundary-second lines (ts == cursor, no id cursor) of a "load older" page get at most
/// this much, so they can never crowd the older lines out of a page (no paging stall).
const MAX_REPLY_BOUNDARY_BYTES: usize = MAX_REPLY_BYTES / 2;
/// Byte size of one chunk the big-file paging fallback reads at a time.
const BIG_FILE_CHUNK_BYTES: u64 = 4 * 1024 * 1024;

/// Default and absolute caps for search result counts.
const SEARCH_DEFAULT_LIMIT: usize = 500;
const SEARCH_MAX_LIMIT: usize = 1000;

/// Minimum query length for search_logs (shorter queries return empty).
const SEARCH_MIN_QUERY_LEN: usize = 2;

/// "Load older" paging (read_tail_before): every line that shares the cursor's
/// second is returned alongside the older page, because the client's cursor is
/// a whole-second timestamp and the lines of that second it has NOT shown yet
/// would otherwise be skipped forever (clients dedup by msg id). Capped so one
/// pathological second can't produce an unbounded response.
const BOUNDARY_SECOND_CAP: usize = 1000;

/// Linear-scan lines in the boundary day file that are past the binary-search
/// boundary but still checked (newest-first), to tolerate small ts reordering
/// (concurrent appends) when the big-file fallback is used.
const BIG_FILE_MARGIN_LINES: usize = 512;

/// Decrypt budget for lines the big-file fallback scans that do NOT qualify.
const BIG_FILE_SKIP_BUDGET: usize = 4096;

/// r4 C1-6: a Sync stops scanning a day file after this many consecutive already-synced
/// lines (far above the append reorder depth, which is the number of concurrent appends
/// to one target).
const SYNC_SYNCED_RUN: usize = 1024;

/// Largest single path component we ever create. ext4/xfs/btrfs NAME_MAX is 255
/// bytes; a longer component makes create_dir_all fail and the line is silently
/// never logged.
const MAX_COMPONENT_BYTES: usize = 255;

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
    /// F2 (rust-ws2): conn-id dirs under logs/ whose name is a NON-canonical
    /// (upper/mixed-case) spelling of a network UUID, keyed by the canonical
    /// lower-case id. Before ids were canonicalised, a re-cased id could be used
    /// as a live conn_id and its history went to `logs/<Variant>/`. Those dirs are
    /// read-merged (and deleted) together with the canonical dir so no history is
    /// orphaned. Scanned once, lazily; nothing creates new variants any more
    /// (append canonicalises), so the cache only ever shrinks.
    variant_conn_dirs: tokio::sync::OnceCell<std::sync::Mutex<HashMap<String, Vec<String>>>>,
    /// r4 C1-6: history reads (GetLogs / Sync / Search / load-older) in flight, process-wide
    /// and per account. Each read is bounded (MAX_READ_BYTES per file, read backward;
    /// MAX_REPLY_BYTES per reply), but nothing bounded how many ran at once: one account
    /// with many sockets could keep the disk and the decrypt work saturated for everyone.
    read_slots: Arc<tokio::sync::Semaphore>,
    user_read_slots: dashmap::DashMap<String, Arc<tokio::sync::Semaphore>>,
}

/// r4 C1-6: concurrent history reads, process-wide and per account (a socket handles its
/// commands one at a time, so the per-account cap is what bounds a many-socket account).
const LOG_READS_MAX_CONCURRENT: usize = 4;
const LOG_READS_PER_USER: usize = 2;

/// r4 C1-6: a held history-read slot (released on drop).
struct ReadSlot {
    _user: Option<tokio::sync::OwnedSemaphorePermit>,
    _global: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl EncryptedLogger {
    pub fn new(data_dir: &str, crypto: Arc<CryptoManager>) -> Self {
        Self {
            data_dir: data_dir.to_string(),
            crypto,
            seq_locks: Mutex::new(HashMap::new()),
            warned_bad_lines: Mutex::new(std::collections::HashSet::new()),
            variant_conn_dirs: tokio::sync::OnceCell::new(),
            read_slots: Arc::new(tokio::sync::Semaphore::new(LOG_READS_MAX_CONCURRENT)),
            user_read_slots: dashmap::DashMap::new(),
        }
    }

    /// r4 C1-6: wait for a per-account, then a process-wide history-read slot (always in
    /// that order, so no two readers can hold them crosswise).
    async fn read_slot(&self, username: &str) -> ReadSlot {
        let user_sem = self.user_read_slots.entry(username.to_string())
            .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(LOG_READS_PER_USER)))
            .clone();
        let user = user_sem.acquire_owned().await.ok();
        let global = self.read_slots.clone().acquire_owned().await.ok();
        ReadSlot { _user: user, _global: global }
    }

    /// The (lazily scanned) map of non-canonical conn dirs, see `variant_conn_dirs`.
    async fn variant_map(&self) -> &std::sync::Mutex<HashMap<String, Vec<String>>> {
        self.variant_conn_dirs.get_or_init(|| async {
            let mut map: HashMap<String, Vec<String>> = HashMap::new();
            let root = PathBuf::from(&self.data_dir).join("logs");
            if let Ok(mut rd) = tokio::fs::read_dir(&root).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
                    if !e.file_type().await.map(|t| t.is_dir()).unwrap_or(false) { continue; }
                    if let Some(canon) = crate::auth::validate_uuid(&name) {
                        if canon != name { map.entry(canon).or_default().push(name); }
                    }
                }
            }
            std::sync::Mutex::new(map)
        }).await
    }

    /// Every on-disk conn dir name that holds history for `conn_id`: the encoded id
    /// itself, its canonical lower-case spelling (if `conn_id` is a UUID), and any
    /// legacy re-cased variants (F2). For a canonical id with no variants this is
    /// exactly `[encode_path_component(conn_id)]`, i.e. unchanged behaviour.
    async fn conn_dir_names(&self, conn_id: &str) -> Result<Vec<String>> {
        let primary = encode_path_component(conn_id)?;
        let mut out = vec![primary];
        if let Some(canon) = crate::auth::validate_uuid(conn_id) {
            if !out.contains(&canon) { out.push(canon.clone()); }
            let variants = self.variant_map().await.lock()
                .map(|m| m.get(&canon).cloned().unwrap_or_default())
                .unwrap_or_default();
            for v in variants {
                if !out.contains(&v) { out.push(v); }
            }
        }
        Ok(out)
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
            // F2: include legacy re-cased variant dirs of this conn_id, so ids that
            // live only there still count toward the recovered high-water mark.
            let conn_names = match self.conn_dir_names(&conn_id).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            for conn_name in conn_names {
                let conn_dir = logs_root.join(conn_name);
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
        // F2: a network UUID is always logged under its canonical (lower-case)
        // spelling, so no new re-cased `logs/<Variant>/` dir can ever be created.
        // Identity for every id the server generates (they are already lower-case).
        let canon_conn = crate::auth::validate_uuid(conn_id);
        let conn_id: &str = canon_conn.as_deref().unwrap_or(conn_id);
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
        self.read_logs_view(username, conn_id, target, limit, None).await
    }

    /// read_logs, optionally keeping only one side of the shared "status" log (see
    /// StatusView). None = every line, as before.
    pub async fn read_logs_view(&self, username: &str, conn_id: &str, target: &str, limit: usize, view: Option<StatusView>) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let _slot = self.read_slot(username).await; // r4 C1-6
        // Tail read: only the most-recent `limit` lines are wanted, so read
        // newest-first and stop early instead of decrypting the full history (#12).
        let safe_limit = limit.min(MAX_DECRYPT_LINES);
        self.read_tail(username, conn_id, target, safe_limit, MAX_DECRYPT_LINES, None, view).await
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
        self.read_logs_since_view(username, conn_id, target, after_id, None).await
    }

    /// read_logs_since with an optional StatusView filter.
    pub async fn read_logs_since_view(&self, username: &str, conn_id: &str, target: &str, after_id: u64, view: Option<StatusView>) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let _slot = self.read_slot(username).await; // r4 C1-6

        let day_files = self.day_files(conn_id, target).await?;

        let mut collected: Vec<LogLine> = Vec::new();
        let mut scanned: usize = 0;
        let mut reply_bytes: usize = 0;
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
            // r4 C1-6: read backward and lazily — first only the probe window below, the
            // rest only if this file holds un-synced lines (every Sync probes every older
            // day file, which used to read each of them from start to end).
            let mut lines = BudgetLines::open(path, MAX_DECRYPT_LINES, MAX_READ_BYTES).await;
            let mut enc_lines: Vec<String> = Vec::new();   // newest first
            while enc_lines.len() < 32 {
                match lines.next().await { Some(l) => enc_lines.push(l), None => break }
            }

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
            for enc in enc_lines.iter().take(probe_n) {
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
            // (The probed lines first, then the rest of the file, still backward.)
            // r4 C1-6: and stop this file once SYNC_SYNCED_RUN consecutive lines are
            // already synced (id <= after_id): ids are issued in order and the write
            // reorder depth is the number of concurrent appends to one target (see the
            // probe note above), so nothing un-synced lies further back — the scan used to
            // continue through the whole 50,000-line / 16 MiB window on every Sync.
            let mut probed = enc_lines.into_iter();
            let mut synced_run = 0usize;
            loop {
                let Some(enc_line) = (match probed.next() { Some(l) => Some(l), None => lines.next().await }) else { break };
                let enc_line = &enc_line;
                if scanned >= MAX_DECRYPT_LINES { break 'outer; }
                scanned += 1;
                match self.decrypt_log_line(username, enc_line, &aad).await {
                    Ok(plain) => {
                        if let Some(line) = Self::parse_line(&plain) {
                            if line.id > after_id {
                                synced_run = 0;
                            } else {
                                synced_run += 1;
                                if synced_run >= SYNC_SYNCED_RUN { break; }
                            }
                            if line.id > after_id && view.map_or(true, |v| v.keeps(&line)) {
                                // r3 C1-3: newest-first, so the byte cut keeps the newest
                                // un-synced lines (same shape as the scan cap above).
                                reply_bytes += line_cost(&line);
                                collected.push(line);
                                if reply_bytes >= MAX_REPLY_BYTES { break 'outer; }
                            }
                        }
                    }
                    Err(e) => self.warn_decrypt_failure(enc_line, &e).await,
                }
            }
        }

        // collected is newest-first; emit chronologically (ascending id). Reversed first
        // so id-less (pre-v0.3.0) lines, which all compare equal, keep file order.
        collected.reverse();
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
        let _slot = self.read_slot(username).await; // r4 C1-6
        // Clamp the effective result limit: 0 is NOT unbounded.
        let eff_limit = if limit == 0 { SEARCH_DEFAULT_LIMIT } else { limit };
        let eff_limit = eff_limit.min(SEARCH_MAX_LIMIT);

        // Scan at most the most-recent MAX_SEARCH_SCAN_LINES lines, newest-first,
        // collecting matches until we have eff_limit of them.
        let matches = self
            .read_tail(username, conn_id, target, eff_limit, MAX_SEARCH_SCAN_LINES, Some(&q), None)
            .await?;
        Ok(matches)
    }

    /// Return up to `limit` messages with ts < `before`, the most-recent such, plus
    /// the lines of the `before` second itself (see read_tail_before), in
    /// chronological order. Reads newest-first and stops once `limit` matching
    /// lines are collected, instead of materializing the whole history (#12).
    pub async fn read_logs_before(&self, username: &str, conn_id: &str, target: &str, before: i64, limit: usize) -> Result<Vec<LogLine>> {
        self.read_logs_before_id(username, conn_id, target, before, None, limit).await
    }

    /// read_logs_before with an optional exact cursor: `before_id` = the id of the
    /// oldest line the client already shows (its ts is `before`). Lines of the cursor's
    /// own second then page by id (`id < before_id`), so a second holding more than
    /// BOUNDARY_SECOND_CAP lines no longer leaves a permanent hole. None = the whole-
    /// second behaviour every existing client relies on.
    pub async fn read_logs_before_id(&self, username: &str, conn_id: &str, target: &str, before: i64, before_id: Option<u64>, limit: usize) -> Result<Vec<LogLine>> {
        self.read_logs_before_view(username, conn_id, target, before, before_id, limit, None).await
    }

    /// read_logs_before_id with an optional StatusView filter.
    #[allow(clippy::too_many_arguments)]
    pub async fn read_logs_before_view(&self, username: &str, conn_id: &str, target: &str, before: i64, before_id: Option<u64>, limit: usize, view: Option<StatusView>) -> Result<Vec<LogLine>> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        let _slot = self.read_slot(username).await; // r4 C1-6
        let safe_limit = limit.min(MAX_DECRYPT_LINES);
        self.read_tail_before(username, conn_id, target, before, before_id.filter(|&i| i > 0), safe_limit, view).await
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
    ///
    /// r6 (codex P1 logs.rs:645): the legacy dir can ALSO be the current dir of another
    /// target — `#alice`'s legacy `alice` is where the DM with Alice is written today —
    /// and AAD can't tell them apart (lines are bound to the dir they are in). Such an
    /// ambiguous legacy dir (is_current_encoding) is read only for its day files dated
    /// before the network's switch to the current scheme (legacy_cutover: nothing after
    /// it was written there for this target, only for the other one), and it is NEVER
    /// deleted for this target (`deletable: false`). A legacy name that can't be any
    /// current dir (unicode, a bare '_' …) is read and deleted as before.
    async fn resolve_read_dirs(&self, conn_id: &str, target: &str) -> Result<Vec<TargetDir>> {
        let logs_root = PathBuf::from(&self.data_dir).join("logs");
        let mut dirs: Vec<TargetDir> = Vec::new();
        let has = |dirs: &Vec<TargetDir>, p: &PathBuf| dirs.iter().any(|d| d.path == *p);
        let enc_target = encode_path_component(target)?;
        // F2: the canonical conn dir first, then any legacy re-cased variants of the
        // same network id (empty for every normal install → unchanged behaviour).
        let conn_names = self.conn_dir_names(conn_id).await?;
        for (idx, enc_conn) in conn_names.iter().enumerate() {
            let conn_dir   = logs_root.join(enc_conn);
            // New scheme (what we write today).
            let new_dir = conn_dir.join(&enc_target);
            if tokio::fs::metadata(&new_dir).await.is_ok() && !has(&dirs, &new_dir) {
                dirs.push(TargetDir::own(new_dir.clone()));
            }
            // Legacy dir (pre-#52, sanitize_lossy). Include it whenever it exists and
            // differs from the new dir, so history written before the encoding change
            // is still read (#52). The legacy sanitizer can reject some inputs (e.g.
            // "#.."); in that case there simply is no addressable legacy dir.
            // (idx 0 is `conn_id` itself — keep its legacy conn component exactly as
            // before; variant dirs are UUIDs, for which sanitize_lossy is the identity.)
            let legacy_conn = if idx == 0 { sanitize_path_component(conn_id) } else { sanitize_path_component(enc_conn) };
            if let (Ok(lc), Ok(lt)) = (legacy_conn, sanitize_path_component(target)) {
                let legacy_dir = logs_root.join(&lc).join(&lt);
                if legacy_dir != new_dir && tokio::fs::metadata(&legacy_dir).await.is_ok() && !has(&dirs, &legacy_dir) {
                    if is_current_encoding(&lt) {
                        // r6: also another target's current dir — see the doc comment.
                        let before = legacy_cutover(&logs_root.join(&lc)).await;
                        dirs.push(TargetDir { path: legacy_dir, before, deletable: false });
                    } else {
                        dirs.push(TargetDir::own(legacy_dir));
                    }
                }
            }
            // LOW (logs.rs encode_path_component): an over-long target is now written
            // under a NAME_MAX-safe hashed name. On a filesystem whose NAME_MAX is larger
            // than 255 the full-length encoding may already exist — keep reading it.
            let full = encode_path_component_unbounded(target);
            if full != enc_target {
                let full_dir = conn_dir.join(&full);
                if tokio::fs::metadata(&full_dir).await.is_ok() && !has(&dirs, &full_dir) {
                    dirs.push(TargetDir::own(full_dir));
                }
            }
            // Case-insensitive sibling dirs. IRC channel AND nick names are case-insensitive,
            // but historically we wrote the display-case dir — so one channel's history can be
            // split across e.g. `_23Channel` (canonical, holds PRIVMSGs echoed by the server)
            // and `_23channel` (holds JOIN/QUIT logged under the as-joined case), and one
            // query across `Bob`/`bob`. Merge every sibling whose encoded name is a case
            // variant of the target's. Safe because case variants of the SAME IRC entity share
            // identical special-char escapes (only letters differ), so an ASCII-case-insensitive
            // compare of the encoded names matches exactly the same-entity dirs. Per-file AAD
            // (see read_tail, derived from each file's ACTUAL dir) decrypts each dir correctly,
            // so this is purely additive — it never renames/moves data.
            if let Ok(mut rd) = tokio::fs::read_dir(&conn_dir).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    let name = e.file_name();
                    let Some(name_s) = name.to_str() else { continue };
                    if name_s.eq_ignore_ascii_case(&enc_target) && name_s != enc_target {
                        if e.file_type().await.map(|t| t.is_dir()).unwrap_or(false) {
                            let p = e.path();
                            if !has(&dirs, &p) { dirs.push(TargetDir::own(p)); }
                        }
                    }
                }
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
            if let Ok(mut rd) = tokio::fs::read_dir(&dir.path).await {
                while let Ok(Some(e)) = rd.next_entry().await {
                    let p = e.path();
                    if p.extension().map(|x| x == "log").unwrap_or(false) {
                        // r6: an ambiguous legacy dir only up to the scheme switch.
                        if let Some(before) = &dir.before {
                            let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                            if stem >= before.as_str() { continue; }
                        }
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
    #[allow(clippy::too_many_arguments)]
    async fn read_tail(
        &self, username: &str, conn_id: &str, target: &str,
        limit: usize, max_scan: usize, filter_query: Option<&str>, view: Option<StatusView>,
    ) -> Result<Vec<LogLine>> {
        if limit == 0 { return Ok(Vec::new()); }
        let day_files = self.day_files(conn_id, target).await?;

        let mut collected: Vec<LogLine> = Vec::new();
        let mut scanned: usize = 0;
        let mut reply_bytes: usize = 0;
        // Iterate DATES newest-first. A date can have several files when a channel's
        // lines are merged from case-variant / legacy sibling dirs (`_23chan` and
        // `_23Chan` both holding today's file). Those files must be merged by id BEFORE
        // the limit applies: reading one whole file first used to fill `limit` from an
        // older variant and never look at a sibling holding the newest lines (codex P1
        // logs.rs:692). A k-way merge newest-first keeps the decrypt budget spent on
        // the newest lines across all of that date's files.
        for group in same_date_groups(&day_files).into_iter().rev() {
            let mut heads: Vec<MergeHead> = Vec::with_capacity(group.len());
            for path in &group {
                // #11/#F7: derive the AAD from the file's ACTUAL parent/grandparent
                // dir names (as recover_max_id does) so both new-scheme and legacy-dir
                // lines decrypt; re-encoding the target would mis-derive the AAD for
                // legacy files and silently drop them.
                let aad = file_aad(path);
                // #F21 / r3 C1-3: at most `max_scan` lines and MAX_READ_BYTES of this file.
                // r4 C1-6: read lazily from the END of the file, so a request costs the
                // lines it consumes, not a scan of the whole day file.
                let lines = BudgetLines::open(path, max_scan, MAX_READ_BYTES).await;
                heads.push(MergeHead { lines, aad, head: None });
            }
            loop {
                // Refill every empty head (newest not-yet-taken parsable line of its file).
                for h in heads.iter_mut() {
                    while h.head.is_none() {
                        if scanned >= max_scan { break; }
                        let Some(enc_line) = h.lines.next().await else { break };
                        scanned += 1;
                        match self.decrypt_log_line(username, &enc_line, &h.aad).await {
                            Ok(plain) => { h.head = Self::parse_line(&plain); }
                            Err(e) => self.warn_decrypt_failure(&enc_line, &e).await,
                        }
                    }
                }
                // Take the newest head across the date's files (id, then ts).
                let Some(best) = heads.iter().enumerate()
                    .filter_map(|(i, h)| h.head.as_ref().map(|l| (i, l.id, l.ts)))
                    .max_by(|a, b| (a.1, a.2).cmp(&(b.1, b.2)))
                    .map(|(i, _, _)| i) else { break };
                let line = heads[best].head.take().expect("head present");
                if let Some(q) = filter_query {
                    if line.from == "*" || !line.text.to_lowercase().contains(q) {
                        continue;
                    }
                }
                if let Some(v) = view { if !v.keeps(&line) { continue; } }
                reply_bytes += line_cost(&line);
                collected.push(line);
                if collected.len() >= limit || reply_bytes >= MAX_REPLY_BYTES { break; }
            }
            if collected.len() >= limit || scanned >= max_scan || reply_bytes >= MAX_REPLY_BYTES { break; }
        }
        // Order by the monotonic per-message id (ts tiebreak). A plain reverse() was
        // only correct when every line came from one dir in file order; now that a
        // channel's lines can be MERGED from case-variant/legacy sibling dirs whose
        // files share the same date, same-day lines must be interleaved by id, not
        // grouped by directory. ids are per-user monotonic, so this is chronological.
        // `collected` is newest-first: reverse it first so lines that compare equal —
        // id-less (pre-v0.3.0) lines of one second — keep their file (= time) order
        // through the stable sort instead of coming back reversed.
        collected.reverse();
        collected.sort_by(|a, b| a.id.cmp(&b.id).then(a.ts.cmp(&b.ts)));
        Ok(collected)
    }

    /// "Load older" page: up to `limit` most-recent lines with ts < `before`, PLUS
    /// every line whose ts == `before` (up to BOUNDARY_SECOND_CAP), returned
    /// chronologically (by id).
    ///
    /// MEDIUM (rust-core-auth, logs.rs:614-655):
    /// (a) Clients page with `before = oldest_shown.ts` (a whole second). The old
    ///     strict `ts < before` skipped every not-yet-shown line of that same second
    ///     — a silent hole on any same-second burst. Returning the whole boundary
    ///     second fixes that for every existing client (web, TUI, stale cached
    ///     app.js): they all dedup by msg id, so lines they already show are
    ///     dropped client-side and only the missing ones are added.
    /// (b) The 50k decrypt budget used to be spent on lines NEWER than the cursor,
    ///     so history more than ~50k lines back was unreachable. Day files only ever
    ///     hold lines of their own UTC date (log_path), so files that start after
    ///     `before` are now skipped without decrypting, and only the not-qualifying
    ///     lines of the cursor's own day count against the budget. If that one day
    ///     alone has more than MAX_DECRYPT_LINES lines after the cursor, the cursor
    ///     is located inside the file by binary search (tail_before_big_file)
    ///     instead of giving up. Per-request work stays bounded.
    #[allow(clippy::too_many_arguments)]
    async fn read_tail_before(
        &self, username: &str, conn_id: &str, target: &str,
        before: i64, before_id: Option<u64>, limit: usize, view: Option<StatusView>,
    ) -> Result<Vec<LogLine>> {
        if limit == 0 { return Ok(Vec::new()); }
        let day_files = self.day_files(conn_id, target).await?;

        let mut older: Vec<LogLine> = Vec::new();     // qualifying (counts toward limit)
        let mut boundary: Vec<LogLine> = Vec::new();  // ts == before, no usable id cursor
        let mut skipped: usize = 0;                   // decrypted/failed lines that didn't qualify
        // r3 C1-3: the reply's byte allowance (older lines; boundary lines separately, so
        // they can never take a page's whole allowance and stall "load older").
        let mut left = PageBytes { older: MAX_REPLY_BYTES, boundary: MAX_REPLY_BOUNDARY_BYTES };
        // Dates newest-first; a date's files from case-variant / legacy sibling dirs are
        // each read for the full remaining need and then merged by id, so the page is the
        // newest qualifying lines across ALL of them (codex P1 logs.rs:692 — reading one
        // variant to the limit first skipped a sibling's newer lines).
        for group in same_date_groups(&day_files).into_iter().rev() {
            // A day file only holds lines of its own UTC date, so one that starts
            // after the cursor cannot contain a qualifying line — skip it unread.
            let date = group[0].file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let day_start = day_start_ts(date);
            if let Some(s) = day_start { if s > before { continue; } }
            let need = limit - older.len();
            let room = BOUNDARY_SECOND_CAP.saturating_sub(boundary.len());
            let mut g_older: Vec<LogLine> = Vec::new();
            let mut g_boundary: Vec<LogLine> = Vec::new();
            let mut stop = false;
            for path in &group {
                let (o, bnd, st) = self.tail_before_one_file(
                    username, path, day_start.is_some(), before, before_id, need, room, left, &mut skipped, view,
                ).await;
                g_older.extend(o);
                g_boundary.extend(bnd);
                if st { stop = true; break; }
            }
            if group.len() > 1 {
                // Keep only the newest `need` / `room` across the merged files.
                g_older.sort_by(|a, b| (b.id, b.ts).cmp(&(a.id, a.ts)));
                g_older.truncate(need);
                g_boundary.sort_by(|a, b| (b.id, b.ts).cmp(&(a.id, a.ts)));
                g_boundary.truncate(room);
            }
            // r3 C1-3: ...and within what is left of the byte allowance (newest first).
            keep_within(&mut g_older, &mut left.older);
            keep_within(&mut g_boundary, &mut left.boundary);
            older.extend(g_older);
            boundary.extend(g_boundary);
            if stop || older.len() >= limit || left.older == 0 { break; }
        }
        // Chronological by id (ts tiebreak) — merged case-variant/legacy sibling dirs
        // can interleave same-date lines, so file order isn't chronological. See read_tail.
        // Both lists are newest-first and the boundary lines are the newest: chain them
        // newest-first and reverse, so equal keys (id-less lines of one second) keep file
        // order through the stable sort (TUI report: they came back reversed per second).
        let mut collected = boundary;
        collected.extend(older);
        collected.reverse();
        collected.sort_by(|a, b| a.id.cmp(&b.id).then(a.ts.cmp(&b.ts)));
        // The big-file fallback can revisit lines the linear pass already took.
        collected.dedup_by(|a, b| a.id != 0 && a.id == b.id);
        Ok(collected)
    }

    /// One day file of read_tail_before: newest-first, collect up to `need` qualifying
    /// lines and up to `room` boundary lines (see classify_before). `skipped` is the
    /// shared budget of decrypted-but-not-qualifying lines; when the cursor's own day has
    /// more of those than MAX_DECRYPT_LINES, the cursor is located by binary search
    /// (tail_before_big_file). Returns (qualifying, boundary, stop-everything).
    #[allow(clippy::too_many_arguments)]
    async fn tail_before_one_file(
        &self, username: &str, path: &std::path::Path, dated: bool,
        before: i64, before_id: Option<u64>, need: usize, room: usize, left: PageBytes,
        skipped: &mut usize, view: Option<StatusView>,
    ) -> (Vec<LogLine>, Vec<LogLine>, bool) {
        let mut older: Vec<LogLine> = Vec::new();
        let mut boundary: Vec<LogLine> = Vec::new();
        if need == 0 || left.older == 0 { return (older, boundary, false); }
        // r3 C1-3: bytes taken from this reply's allowance by this file.
        let (mut ob, mut bb) = (0usize, 0usize);
        // #11/#F7: per-file AAD from the file's ACTUAL parent/grandparent dir
        // names (as recover_max_id does) so both new-scheme and legacy-dir
        // lines decrypt.
        let aad = file_aad(path);
        let per_file_cap = MAX_DECRYPT_LINES + need + BOUNDARY_SECOND_CAP;
        // #F21: bounded streaming read instead of read_to_string (r3 C1-3: and bounded
        // in bytes; `truncated` = older lines of this file were not kept).
        // r4 C1-6: read backward and lazily — only what this page consumes.
        let mut lines = BudgetLines::open(path, per_file_cap, MAX_READ_BYTES).await;
        while let Some(enc_line) = lines.next().await {
            let enc_line = &enc_line;
            match self.decrypt_log_line(username, enc_line, &aad).await {
                Ok(plain) => {
                    if let Some(line) = Self::parse_line(&plain).filter(|l| view.map_or(true, |v| v.keeps(l))) {
                        match classify_before(&line, before, before_id) {
                            BeforeClass::Qualifies => {
                                ob += line_cost(&line);
                                older.push(line);
                                if older.len() >= need || ob >= left.older { return (older, boundary, false); }
                                continue;
                            }
                            BeforeClass::Boundary if boundary.len() < room && bb < left.boundary => {
                                bb += line_cost(&line);
                                boundary.push(line);
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => self.warn_decrypt_failure(enc_line, &e).await,
            }
            *skipped += 1;
            if *skipped >= MAX_DECRYPT_LINES {
                // The cursor's own day has more newer lines than the budget. Every
                // OLDER day file qualifies in full, so find the cursor inside this
                // file by position and carry on with the older files.
                if dated {
                    let rest = PageBytes { older: left.older.saturating_sub(ob), boundary: left.boundary.saturating_sub(bb) };
                    let (o, b) = self.tail_before_big_file(
                        username, path, &aad, before, before_id,
                        need - older.len(), room.saturating_sub(boundary.len()), rest, view,
                    ).await;
                    older.extend(o);
                    boundary.extend(b);
                    *skipped = 0;
                    return (older, boundary, false);
                }
                return (older, boundary, true);
            }
        }
        // r3 C1-3: the byte-bounded read ran out before reaching the cursor's position in
        // this file (the day holds more than MAX_READ_BYTES of lines newer than it). Locate
        // the cursor by position exactly like the line-budget case above, instead of moving
        // on to the older days and leaving the rest of this one as a paging hole.
        if lines.truncated && older.len() < need {
            if dated {
                let rest = PageBytes { older: left.older.saturating_sub(ob), boundary: left.boundary.saturating_sub(bb) };
                let (o, b) = self.tail_before_big_file(
                    username, path, &aad, before, before_id,
                    need - older.len(), room.saturating_sub(boundary.len()), rest, view,
                ).await;
                older.extend(o);
                boundary.extend(b);
                *skipped = 0;
                return (older, boundary, false);
            }
            return (older, boundary, true);
        }
        (older, boundary, false)
    }

    /// Big-file fallback for read_tail_before: `path` (the cursor's own day) has more
    /// lines newer than `before` than the decrypt budget allows. Lines are appended in
    /// time order, so binary-search the cursor's position (O(log n) decrypts), then scan
    /// newest-first from a small margin past it. Returns (older-than-before,
    /// equal-to-before) lines.
    /// r4 C1-6: the search runs over BYTE positions (each probe reads the first line that
    /// starts at or after a position) and the scan reads backward from a byte offset, so
    /// no whole-file line-offset index is built per request any more (it read the entire
    /// file and kept 8 bytes per line outside every byte budget).
    #[allow(clippy::too_many_arguments)]
    async fn tail_before_big_file(
        &self, username: &str, path: &std::path::Path, aad: &[u8],
        before: i64, before_id: Option<u64>, need_older: usize, boundary_room: usize,
        left: PageBytes, view: Option<StatusView>,
    ) -> (Vec<LogLine>, Vec<LogLine>) {
        let mut older = Vec::new();
        let mut boundary = Vec::new();
        if need_older == 0 || left.older == 0 { return (older, boundary); }
        let file_len = tokio::fs::metadata(path).await.map(|m| m.len()).unwrap_or(0);
        if file_len == 0 { return (older, boundary); }
        let (mut ob, mut bb) = (0usize, 0usize);
        // Start (byte offset) of the first line whose ts > before, assuming non-decreasing
        // ts in file order. A probe that can't decrypt/parse tries up to 8 following lines.
        let (mut lo, mut hi) = (0u64, file_len);
        let mut probes = 0usize;
        while lo < hi && probes < 256 {
            let mid = lo + (hi - lo) / 2;
            let mut found: Option<(u64, i64)> = None;   // (end offset of the line, its ts)
            let mut at = mid;
            for _ in 0..8 {
                probes += 1;
                let Some((end, enc)) = line_at_or_after(path, at, hi).await else { break };
                if let Ok(plain) = self.decrypt_log_line(username, &enc, aad).await {
                    if let Some(line) = Self::parse_line(&plain) { found = Some((end, line.ts)); break; }
                }
                at = end;
            }
            match found {
                Some((end, ts)) if ts <= before => lo = end,
                _ => hi = mid,
            }
        }
        // Scan newest-first from up to BIG_FILE_MARGIN_LINES lines (and at most
        // BIG_FILE_CHUNK_BYTES) past that position.
        let scan_end = forward_end(path, lo, BIG_FILE_MARGIN_LINES, BIG_FILE_CHUNK_BYTES).await.unwrap_or(file_len);
        let Some(mut rev) = RevLines::open(path, Some(scan_end)).await else { return (older, boundary) };
        let mut skipped = 0usize;
        while let Some(enc) = rev.next_line().await {
            match self.decrypt_log_line(username, &enc, aad).await {
                Ok(plain) => {
                    if let Some(line) = Self::parse_line(&plain).filter(|l| view.map_or(true, |v| v.keeps(l))) {
                        match classify_before(&line, before, before_id) {
                            BeforeClass::Qualifies => {
                                ob += line_cost(&line);
                                older.push(line);
                                if older.len() >= need_older || ob >= left.older { break; }
                                continue;
                            }
                            BeforeClass::Boundary if boundary.len() < boundary_room && bb < left.boundary => {
                                bb += line_cost(&line);
                                boundary.push(line);
                                continue;
                            }
                            _ => {}
                        }
                    }
                }
                Err(e) => self.warn_decrypt_failure(&enc, &e).await,
            }
            skipped += 1;
            if skipped >= BIG_FILE_SKIP_BUDGET { break; }
        }
        (older, boundary)
    }

    /// Permanently delete all logs for a target (channel or query). Returns
    /// Ok(true) if a directory existed and was removed, Ok(false) if there was
    /// nothing to delete. The per-user sequence counter is intentionally NOT
    /// reset — new messages keep getting monotonically larger ids so any
    /// in-flight sync from another session can't resurrect deleted records.
    ///
    /// Deletes EVERY dir the read side merges for this target (resolve_read_dirs):
    /// the new-scheme dir, the legacy lossy dir (#52), ASCII-case sibling dirs of
    /// the same channel/nick, and legacy re-cased conn-id dirs (F2). Previously the
    /// case-sibling and variant dirs survived a "clear history" and their lines
    /// came straight back on the next load.
    pub async fn delete_target(&self, username: &str, conn_id: &str, target: &str) -> Result<bool> {
        if !self.crypto.is_unlocked(username).await { anyhow::bail!("Vault locked"); }
        encode_path_component(conn_id)?;
        encode_path_component(target)?;
        // r6: remember the scheme-switch date before any current-scheme dir goes (see
        // legacy_cutover) — it is what keeps an ambiguous legacy dir's later days out.
        let logs_root = PathBuf::from(&self.data_dir).join("logs");
        for enc_conn in self.conn_dir_names(conn_id).await? {
            let _ = legacy_cutover(&logs_root.join(enc_conn)).await;
        }
        let mut removed = false;
        for dir in self.resolve_read_dirs(conn_id, target).await? {
            // r6 (codex P1 logs.rs:645): never through an ambiguous legacy dir — it is also
            // another target's current dir (`alice` for `#alice`: the DM with Alice).
            if !dir.deletable { continue; }
            if tokio::fs::metadata(&dir.path).await.is_ok() {
                tokio::fs::remove_dir_all(&dir.path).await?;
                removed = true;
            }
        }
        Ok(removed)
    }

    /// F16: remove ALL history of one network (RemoveNetwork / Clear All Data): the
    /// canonical `logs/<id>/` dir plus any legacy re-cased variant dirs (F2). Only
    /// network UUIDs are accepted (callers have already checked ownership). Returns
    /// how many conn dirs were removed.
    pub async fn delete_conn_logs(&self, conn_id: &str) -> usize {
        let Some(canon) = crate::auth::validate_uuid(conn_id) else { return 0 };
        let root = PathBuf::from(&self.data_dir).join("logs");
        let names = match self.conn_dir_names(&canon).await { Ok(v) => v, Err(_) => return 0 };
        let mut n = 0usize;
        for name in names {
            let d = root.join(&name);
            if tokio::fs::metadata(&d).await.map(|m| m.is_dir()).unwrap_or(false) {
                match tokio::fs::remove_dir_all(&d).await {
                    Ok(()) => n += 1,
                    Err(e) => tracing::warn!("Log dir delete failed ({:?}): {}", d, e),
                }
            }
        }
        if let Ok(mut m) = self.variant_map().await.lock() { m.remove(&canon); }
        n
    }

    /// F16: "Clear All Data" must also erase history of networks the user REMOVED
    /// earlier (and legacy re-cased F2 dirs) — those `logs/<id>/` dirs have no config
    /// any more, so nothing names them. logs/ is not keyed by username, so ownership
    /// is PROVEN cryptographically: a conn dir is deleted only if one of its lines
    /// AES-GCM-decrypts under THIS user's vault key (an authenticated decrypt cannot
    /// succeed with another user's key). `keep` = lower-cased ids of every network
    /// that still has a config (any user); those dirs are never touched here. Needs
    /// the vault unlocked (returns 0 otherwise). Returns the number of dirs removed.
    pub async fn delete_unowned_user_logs(&self, username: &str, keep: &std::collections::HashSet<String>) -> usize {
        if !self.crypto.is_unlocked(username).await { return 0; }
        let root = PathBuf::from(&self.data_dir).join("logs");
        let mut candidates: Vec<(String, PathBuf)> = Vec::new();
        if let Ok(mut rd) = tokio::fs::read_dir(&root).await {
            while let Ok(Some(e)) = rd.next_entry().await {
                let Some(name) = e.file_name().to_str().map(str::to_string) else { continue };
                if name.starts_with('.') { continue; }
                if keep.contains(&name.to_ascii_lowercase()) { continue; }
                if !e.file_type().await.map(|t| t.is_dir()).unwrap_or(false) { continue; }
                candidates.push((name, e.path()));
            }
        }
        let mut n = 0usize;
        for (name, dir) in candidates {
            if self.conn_dir_owned_by(username, &name, &dir).await {
                match tokio::fs::remove_dir_all(&dir).await {
                    Ok(()) => n += 1,
                    Err(e) => tracing::warn!("Log dir delete failed ({:?}): {}", dir, e),
                }
            }
        }
        if n > 0 {
            if let Ok(mut m) = self.variant_map().await.lock() {
                m.retain(|_, v| { v.retain(|name| root.join(name).exists()); !v.is_empty() });
            }
        }
        n
    }

    /// True if some line in the conn dir `dir` (named `enc_conn`) decrypts under
    /// `username`'s key. Probes up to 3 lines of 2 files in 8 targets — the owner's
    /// first line normally decrypts at once; a foreign dir costs <= 48 failed AEAD
    /// checks, so the scan stays cheap without ever decrypting history.
    async fn conn_dir_owned_by(&self, username: &str, enc_conn: &str, dir: &std::path::Path) -> bool {
        let Ok(mut targets) = tokio::fs::read_dir(dir).await else { return false };
        let mut tdirs = 0usize;
        while let Ok(Some(t)) = targets.next_entry().await {
            if tdirs >= 8 { break; }
            if !t.file_type().await.map(|ft| ft.is_dir()).unwrap_or(false) { continue; }
            tdirs += 1;
            let Some(enc_target) = t.file_name().to_str().map(str::to_string) else { continue };
            let Ok(mut days) = tokio::fs::read_dir(t.path()).await else { continue };
            let mut files = 0usize;
            while let Ok(Some(d)) = days.next_entry().await {
                let p = d.path();
                if !p.extension().map(|x| x == "log").unwrap_or(false) { continue; }
                if files >= 2 { break; }
                files += 1;
                let date = p.file_stem().and_then(|s| s.to_str()).unwrap_or("").to_string();
                let aad = log_aad(enc_conn, &enc_target, &date);
                for line in read_first_lines(&p, 3).await {
                    if self.decrypt_log_line(username, &line, &aad).await.is_ok() { return true; }
                }
            }
        }
        false
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

/// Per-file AAD from the file's ACTUAL date stem and parent/grandparent dir names
/// (#11/#F7), so lines under both the new-scheme and the legacy dir decrypt.
fn file_aad(path: &std::path::Path) -> Vec<u8> {
    let date       = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let enc_target = path.parent().and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
    let enc_conn   = path.parent().and_then(|d| d.parent()).and_then(|d| d.file_name()).and_then(|s| s.to_str()).unwrap_or("");
    log_aad(enc_conn, enc_target, date)
}

/// Split day_files' output (sorted by file name, i.e. by date) into runs of files
/// that share one date — several when a target's history is merged from case-variant
/// or legacy sibling dirs. Oldest date first.
fn same_date_groups(files: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    let mut out: Vec<Vec<PathBuf>> = Vec::new();
    for f in files {
        let same = out.last().and_then(|g| g.first())
            .map_or(false, |first| first.file_name() == f.file_name());
        if same { out.last_mut().expect("non-empty").push(f.clone()); }
        else { out.push(vec![f.clone()]); }
    }
    out
}

/// One file's cursor in read_tail's newest-first k-way merge of same-date files.
/// r4 C1-6: reads its file lazily, backward (BudgetLines), instead of holding the
/// newest MAX_READ_BYTES of it up front.
struct MergeHead {
    lines: BudgetLines,
    aad: Vec<u8>,
    /// Decrypted newest not-yet-taken line, if any.
    head: Option<LogLine>,
}

/// One side of the shared "status" log (agy-clients LOW: a real user whose nick is
/// `status` lands in the same log as the server's own output). Selected by the optional
/// GetLogs / Sync field `status_view`; without it every line is returned, as before.
///  - Query: that user's conversation — PRIVMSG/ACTION lines (theirs and ours to them),
///    and NOTICEs whose sender is `status`.
///  - Server: everything else (numerics, server notices, off-channel QUIT/NICK/AWAY,
///    user-mode changes, manual WHO output).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusView { Server, Query }

impl StatusView {
    pub fn parse(s: &str) -> Option<Self> {
        match s { "server" => Some(StatusView::Server), "query" => Some(StatusView::Query), _ => None }
    }
    pub fn keeps(self, l: &LogLine) -> bool {
        let query = matches!(l.kind.as_str(), "privmsg" | "action")
            || (l.kind == "notice" && l.from.eq_ignore_ascii_case("status"));
        match self { StatusView::Query => query, StatusView::Server => !query }
    }
}

enum BeforeClass { Qualifies, Boundary, Neither }

/// read_tail_before's cursor test. Without an id cursor: ts < before qualifies and
/// ts == before is a boundary line (whole-second cursor, see BOUNDARY_SECOND_CAP).
/// With `before_id`, a line of the cursor's second that has an id qualifies exactly
/// when its id is older than the cursor; id-less (pre-v0.3.0) lines of that second
/// keep the boundary treatment, since they can't be compared.
fn classify_before(line: &LogLine, before: i64, before_id: Option<u64>) -> BeforeClass {
    if line.ts < before { return BeforeClass::Qualifies; }
    if line.ts != before { return BeforeClass::Neither; }
    match before_id {
        Some(bid) if line.id != 0 => if line.id < bid { BeforeClass::Qualifies } else { BeforeClass::Neither },
        _ => BeforeClass::Boundary,
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
    read_recent_lines_budget(path, cap, MAX_READ_BYTES).await.0
}

/// read_recent_lines with an explicit byte ceiling (r3 C1-3): keeps the newest lines
/// whose total size stays within `max_bytes` as well as `cap` (always at least the newest
/// line). The bool is true when older lines of the file were dropped by either limit.
/// r4 C1-6: reads the file BACKWARD from its end (RevLines), so the work is what is
/// returned, not the whole file (it used to stream every day file from its first byte).
async fn read_recent_lines_budget(path: &std::path::Path, cap: usize, max_bytes: usize) -> (Vec<String>, bool) {
    let mut lines = BudgetLines::open(path, cap, max_bytes).await;
    let mut out = Vec::new();
    while let Some(l) = lines.next().await { out.push(l); }
    out.reverse();
    (out, lines.truncated)
}

#[cfg(test)]
thread_local! {
    /// r4 C1-6: bytes the log readers read, per thread, in tests (a `#[tokio::test]` runs its
    /// futures on the test's own thread, so concurrent tests don't disturb each other).
    static TEST_READ_BYTES: std::cell::Cell<u64> = std::cell::Cell::new(0);
}
#[cfg(test)]
fn test_count_read(n: usize) { TEST_READ_BYTES.with(|c| c.set(c.get() + n as u64)); }
#[cfg(not(test))]
#[inline]
fn test_count_read(_n: usize) {}

/// r4 C1-6: block size of the backward line reader.
const REV_BLOCK_BYTES: usize = 64 * 1024;
/// r4 C1-6: longest log line the readers keep. A logged line is at most ~120 KB (a 64 KiB
/// body, JSON-wrapped, encrypted, base64); a longer "line" (e.g. a NUL-filled tail after an
/// unclean shutdown) is skipped instead of buffered.
const MAX_LOG_LINE_BYTES: usize = 4 * 1024 * 1024;

/// r4 C1-6: a log file's lines read BACKWARD from a byte offset (newest first), one
/// REV_BLOCK_BYTES block at a time. Same line rules as the old forward reader: split on
/// '\n', trailing '\r's stripped, empty lines skipped, lossy UTF-8 (a corrupt line just
/// fails to decrypt later). Memory: one block of lines + the line being assembled.
struct RevLines {
    file: tokio::fs::File,
    /// File bytes [0, pos) have not been read yet.
    pos: u64,
    /// The start of the line that continues past the blocks already read, as pieces in
    /// REVERSE file order (each newly read, earlier piece is pushed last).
    carry: Vec<Vec<u8>>,
    carry_len: usize,
    /// The line being assembled is longer than MAX_LOG_LINE_BYTES: drop it.
    carry_overflow: bool,
    /// Complete lines of the last block read, newest first.
    ready: std::collections::VecDeque<Vec<u8>>,
    done: bool,
}

impl RevLines {
    /// Read backward from `end` (None = the end of the file).
    async fn open(path: &std::path::Path, end: Option<u64>) -> Option<Self> {
        let file = tokio::fs::File::open(path).await.ok()?;
        let len = file.metadata().await.ok()?.len();
        Some(Self {
            file, pos: end.map_or(len, |e| e.min(len)),
            carry: Vec::new(), carry_len: 0, carry_overflow: false,
            ready: std::collections::VecDeque::new(), done: false,
        })
    }

    /// `head` (the earlier bytes) + the carried pieces as one line; None when it is too long.
    fn take_carry(&mut self, head: &[u8]) -> Option<Vec<u8>> {
        let overflow = self.carry_overflow || head.len() + self.carry_len > MAX_LOG_LINE_BYTES;
        let mut line = Vec::new();
        if !overflow {
            line.reserve(head.len() + self.carry_len);
            line.extend_from_slice(head);
            for piece in self.carry.iter().rev() { line.extend_from_slice(piece); }
        }
        self.carry.clear();
        self.carry_len = 0;
        self.carry_overflow = false;
        if overflow { None } else { Some(line) }
    }

    /// The next older non-empty line, or None at the start of the range / on an I/O error.
    async fn next_line(&mut self) -> Option<String> {
        loop {
            if let Some(mut raw) = self.ready.pop_front() {
                while raw.last() == Some(&b'\r') { raw.pop(); }
                if raw.is_empty() { continue; }
                return Some(String::from_utf8_lossy(&raw).into_owned());
            }
            if self.done { return None; }
            if self.pos == 0 {
                self.done = true;
                if let Some(first) = self.take_carry(&[]) { self.ready.push_back(first); }
                continue;
            }
            if self.read_block().await.is_err() { self.done = true; return None; }
        }
    }

    async fn read_block(&mut self) -> std::io::Result<()> {
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        let n = self.pos.min(REV_BLOCK_BYTES as u64) as usize;
        let start = self.pos - n as u64;
        let mut block = vec![0u8; n];
        self.file.seek(std::io::SeekFrom::Start(start)).await?;
        self.file.read_exact(&mut block).await?;
        test_count_read(n);
        self.pos = start;
        let mut seg_end = n;
        for i in (0..n).rev() {
            if block[i] != b'\n' { continue; }
            if seg_end == n {
                // The newest segment of this block continues with the carried bytes.
                if let Some(line) = self.take_carry(&block[i + 1..n]) { self.ready.push_back(line); }
            } else {
                self.ready.push_back(block[i + 1..seg_end].to_vec());
            }
            seg_end = i;
        }
        if seg_end == n {
            // No newline in this block: all of it belongs to the line being assembled.
            if !self.carry_overflow {
                if self.carry_len + n > MAX_LOG_LINE_BYTES {
                    self.carry.clear();
                    self.carry_len = 0;
                    self.carry_overflow = true;
                } else {
                    self.carry_len += n;
                    self.carry.push(block);
                }
            }
        } else {
            // block[..seg_end] starts the next (older) line; the old carry was consumed.
            block.truncate(seg_end);
            self.carry_len = block.len();
            self.carry.push(block);
        }
        Ok(())
    }
}

/// r4 C1-6: RevLines from the end of a file with the per-file budget the readers always
/// applied: at most `cap` lines (0 = no cap) and `max_bytes` of them (always at least the
/// newest line). `truncated` = an older line exists that the budget left out.
struct BudgetLines {
    rev: Option<RevLines>,
    cap: usize,
    max_bytes: usize,
    lines: usize,
    bytes: usize,
    truncated: bool,
}

impl BudgetLines {
    async fn open(path: &std::path::Path, cap: usize, max_bytes: usize) -> Self {
        Self { rev: RevLines::open(path, None).await, cap, max_bytes, lines: 0, bytes: 0, truncated: false }
    }

    async fn next(&mut self) -> Option<String> {
        let rev = self.rev.as_mut()?;
        let Some(l) = rev.next_line().await else { self.rev = None; return None };
        if (self.cap > 0 && self.lines >= self.cap) || (self.lines > 0 && self.bytes + l.len() > self.max_bytes) {
            self.truncated = true;
            self.rev = None;
            return None;
        }
        self.lines += 1;
        self.bytes += l.len();
        Some(l)
    }
}

/// r4 C1-6: one line read forward: consumes through the next '\n' (or EOF), keeping at
/// most `keep` bytes of it in `buf` (without the '\n'); gives up after MAX_LOG_LINE_BYTES
/// without a newline (an overlong / corrupt region).
struct FwdLine { consumed: u64, newline: bool, fits: bool }

async fn read_line_bounded<R: tokio::io::AsyncBufRead + Unpin>(r: &mut R, buf: &mut Vec<u8>, keep: usize) -> std::io::Result<FwdLine> {
    use tokio::io::AsyncBufReadExt;
    buf.clear();
    let mut consumed: u64 = 0;
    let mut fits = true;
    loop {
        let (take, newline) = {
            let avail = r.fill_buf().await?;
            if avail.is_empty() { return Ok(FwdLine { consumed, newline: false, fits }); }
            let (take, newline) = match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (i + 1, true),
                None => (avail.len(), false),
            };
            let content = &avail[..if newline { take - 1 } else { take }];
            if fits {
                if buf.len() + content.len() > keep { fits = false; buf.clear(); }
                else { buf.extend_from_slice(content); }
            }
            (take, newline)
        };
        r.consume(take);
        test_count_read(take);
        consumed += take as u64;
        if newline { return Ok(FwdLine { consumed, newline: true, fits }); }
        if consumed > MAX_LOG_LINE_BYTES as u64 { return Ok(FwdLine { consumed, newline: false, fits: false }); }
    }
}

/// r4 C1-6: the first non-empty line that STARTS at or after byte `at` and before `hi`:
/// (its end offset = the next line's start, the line). For tail_before_big_file's search.
async fn line_at_or_after(path: &std::path::Path, at: u64, hi: u64) -> Option<(u64, String)> {
    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::File::open(path).await.ok()?;
    let seek_to = at.saturating_sub(1);
    file.seek(std::io::SeekFrom::Start(seek_to)).await.ok()?;
    let mut r = tokio::io::BufReader::with_capacity(REV_BLOCK_BYTES, file);
    let mut buf: Vec<u8> = Vec::new();
    let mut start = at;
    if at > 0 {
        // Finish the line byte at-1 belongs to (just its '\n' when `at` is a line start).
        let l = read_line_bounded(&mut r, &mut buf, 0).await.ok()?;
        if !l.newline { return None; }
        start = seek_to + l.consumed;
    }
    loop {
        if start >= hi { return None; }
        let l = read_line_bounded(&mut r, &mut buf, MAX_LOG_LINE_BYTES).await.ok()?;
        if l.consumed == 0 { return None; }
        let end = start + l.consumed;
        while buf.last() == Some(&b'\r') { buf.pop(); }
        if l.fits && !buf.is_empty() { return Some((end, String::from_utf8_lossy(&buf).into_owned())); }
        if !l.newline { return None; }
        start = end;
    }
}

/// r4 C1-6: the byte offset just past up to `max_lines` lines (at most ~`max_bytes`)
/// that follow byte `from` (a line start).
async fn forward_end(path: &std::path::Path, from: u64, max_lines: usize, max_bytes: u64) -> Option<u64> {
    use tokio::io::AsyncSeekExt;
    let mut file = tokio::fs::File::open(path).await.ok()?;
    file.seek(std::io::SeekFrom::Start(from)).await.ok()?;
    let mut r = tokio::io::BufReader::with_capacity(REV_BLOCK_BYTES, file);
    let mut buf: Vec<u8> = Vec::new();
    let mut pos = from;
    let mut lines = 0usize;
    while lines < max_lines && pos - from < max_bytes {
        let l = read_line_bounded(&mut r, &mut buf, 0).await.ok()?;
        if l.consumed == 0 { break; }
        pos += l.consumed;
        if !l.newline { break; }
        lines += 1;
    }
    Some(pos)
}

/// r3 C1-3: approximate size one line adds to a reply (its strings + JSON/field overhead).
fn line_cost(l: &LogLine) -> usize {
    l.text.len() + l.from.len() + l.kind.len() + 64
}

/// r3 C1-3: what is left of one "load older" reply's byte allowance.
#[derive(Clone, Copy, Debug)]
struct PageBytes { older: usize, boundary: usize }

/// r3 C1-3: keep the leading (newest-first) lines of `v` while allowance is left,
/// charging each kept line to `left` (a line that overshoots is still kept, so a page
/// with any allowance left always makes progress).
fn keep_within(v: &mut Vec<LogLine>, left: &mut usize) {
    let mut keep = 0usize;
    for l in v.iter() {
        if *left == 0 { break; }
        *left = left.saturating_sub(line_cost(l));
        keep += 1;
    }
    v.truncate(keep);
}

/// Unix timestamp of 00:00:00 UTC of a "YYYY-MM-DD" day-file stem (None if the
/// name isn't a date). log_path has always named day files by the line's UTC date.
fn day_start_ts(date: &str) -> Option<i64> {
    let d = chrono::NaiveDate::parse_from_str(date, "%Y-%m-%d").ok()?;
    Some(d.and_hms_opt(0, 0, 0)?.and_utc().timestamp())
}

/// Read `count` non-empty lines starting at line index `from` of `offsets` (byte offsets
/// of line starts; read_first_lines passes `[0]`). Lossy UTF-8, like
/// read_recent_lines, so a corrupt line just fails to decrypt later.
async fn read_lines_at(path: &std::path::Path, offsets: &[u64], from: usize, count: usize) -> Vec<String> {
    use tokio::io::{AsyncBufReadExt, AsyncSeekExt};
    let mut out = Vec::new();
    if from >= offsets.len() || count == 0 { return out; }
    let Ok(mut file) = tokio::fs::File::open(path).await else { return out };
    if file.seek(std::io::SeekFrom::Start(offsets[from])).await.is_err() { return out; }
    let mut reader = tokio::io::BufReader::new(file);
    let mut raw: Vec<u8> = Vec::new();
    while out.len() < count {
        raw.clear();
        match reader.read_until(b'\n', &mut raw).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        while matches!(raw.last(), Some(b'\n') | Some(b'\r')) { raw.pop(); }
        if raw.is_empty() { continue; }
        out.push(String::from_utf8_lossy(&raw).into_owned());
    }
    out
}

/// The first `count` non-empty lines of a file (ownership probe for F16).
async fn read_first_lines(path: &std::path::Path, count: usize) -> Vec<String> {
    read_lines_at(path, &[0], 0, count).await
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

/// r6: one directory a target's history is read from (resolve_read_dirs).
#[derive(Debug, Clone)]
struct TargetDir {
    path: PathBuf,
    /// Some(date) = only day files dated before it belong to this target (an ambiguous
    /// legacy dir, see resolve_read_dirs).
    before: Option<String>,
    /// May delete_target remove it for this target?
    deletable: bool,
}

impl TargetDir {
    fn own(path: PathBuf) -> Self { TargetDir { path, before: None, deletable: true } }
}

/// r6: is `name` what encode_path_component writes today for SOME target — i.e. the
/// current dir of that target? (Plain [A-Za-z0-9-] names are their own encoding; `_HH`
/// escapes must decode to a byte that is escaped today, giving valid UTF-8.)
fn is_current_encoding(name: &str) -> bool {
    let b = name.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if is_plain_byte(c) { out.push(c); i += 1; continue; }
        if c != b'_' { return false; }
        let hex = |x: u8| match x { b'0'..=b'9' => Some(x - b'0'), b'A'..=b'F' => Some(x - b'A' + 10), _ => None };
        let (Some(h), Some(l)) = (b.get(i + 1).and_then(|&x| hex(x)), b.get(i + 2).and_then(|&x| hex(x))) else { return false };
        let byte = h * 16 + l;
        if is_plain_byte(byte) { return false; }   // never escaped today
        out.push(byte);
        i += 3;
    }
    match String::from_utf8(out) {
        Ok(s) => !s.is_empty() && encode_path_component_unbounded(&s) == name,
        Err(_) => false,
    }
}

/// r6: the date this network's logs switched to the current encoding: the oldest day file
/// in any dir that only the current scheme can have written (a name starting with an
/// escape, e.g. every channel's `_23…`). Remembered in `<conn dir>/.legacy_cutover` so
/// clearing those dirs later can't lose it. None = no post-switch history at all (then
/// an ambiguous legacy dir is read whole, as before the switch).
async fn legacy_cutover(conn_dir: &std::path::Path) -> Option<String> {
    let marker = conn_dir.join(".legacy_cutover");
    let remembered = tokio::fs::read_to_string(&marker).await.ok()
        .map(|s| s.trim().to_string())
        .filter(|s| is_day_stem(s));
    let scanned = scan_legacy_cutover(conn_dir).await;
    let best = match (&remembered, &scanned) {
        (Some(a), Some(b)) => Some(if a <= b { a.clone() } else { b.clone() }),
        (a, b) => a.clone().or_else(|| b.clone()),
    };
    if best.is_some() && best != remembered {
        let _ = atomic_write(&marker, best.as_deref().unwrap_or("").as_bytes()).await;
    }
    best
}

/// r7: is `s` exactly a day-file stem as log_path writes it ("YYYY-MM-DD", a real date)?
fn is_day_stem(s: &str) -> bool {
    s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-'
        && chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d").is_ok()
}

async fn scan_legacy_cutover(conn_dir: &std::path::Path) -> Option<String> {
    let mut min: Option<String> = None;
    let mut rd = tokio::fs::read_dir(conn_dir).await.ok()?;
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name();
        let Some(n) = name.to_str() else { continue };
        if !n.starts_with('_') || !is_current_encoding(n) { continue; }
        if !e.file_type().await.map(|t| t.is_dir()).unwrap_or(false) { continue; }
        let Ok(mut days) = tokio::fs::read_dir(e.path()).await else { continue };
        while let Ok(Some(d)) = days.next_entry().await {
            let p = d.path();
            if p.extension().map_or(true, |x| x != "log") { continue; }
            let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else { continue };
            // r7 (agy P1 logs.rs:1750): only a real day file counts — a stray `audit.log`
            // (or `0.log`) must not become the cutover and hide legacy history.
            if !is_day_stem(stem) { continue; }
            if min.as_deref().map_or(true, |m| stem < m) { min = Some(stem.to_string()); }
        }
    }
    min
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
///
/// LOW (rust-core-auth, logs.rs:805-820): the 3x escape had no length cap, so a long
/// non-ASCII/special target (e.g. a 44-char Cyrillic channel → 261 bytes) exceeded
/// NAME_MAX (255): create_dir_all failed and the line was silently never logged.
/// Every encoding that fits in MAX_COMPONENT_BYTES is returned UNCHANGED (so all
/// existing log dirs keep their exact names and AAD); only an over-long one — which
/// could never have been created on disk — becomes `<readable prefix>_z<sha256 hex>`.
/// `_z` cannot occur in a normal encoding ('_' is always followed by two uppercase
/// hex digits), so a hashed name never collides with a normal one. The hash is over
/// the ASCII-lower-cased input so ASCII-case variants of one channel/nick still match
/// resolve_read_dirs's case-insensitive sibling merge.
pub(crate) fn encode_path_component(s: &str) -> Result<String> {
    if s.is_empty() { anyhow::bail!("Empty path component"); }
    let out = encode_path_component_unbounded(s);
    if out.len() <= MAX_COMPONENT_BYTES { return Ok(out); }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.to_ascii_lowercase().as_bytes());
    let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
    let keep = MAX_COMPONENT_BYTES - 2 - hex.len();
    // Readable prefix made of whole tokens (never splits an `_HH` escape).
    let mut prefix = String::with_capacity(keep);
    for b in s.bytes() {
        let tok_len = if is_plain_byte(b) { 1 } else { 3 };
        if prefix.len() + tok_len > keep { break; }
        push_encoded_byte(&mut prefix, b);
    }
    Ok(format!("{}_z{}", prefix, hex))
}

/// The raw 1:1 encoding (see encode_path_component), with no length cap.
fn encode_path_component_unbounded(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 4);
    for b in s.bytes() {
        push_encoded_byte(&mut out, b);
    }
    out
}

fn is_plain_byte(b: u8) -> bool {
    matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-')
}

fn push_encoded_byte(out: &mut String, b: u8) {
    if is_plain_byte(b) {
        out.push(b as char);
    } else {
        // '_' is our escape character, so it is encoded too, keeping the
        // mapping unambiguous/reversible.
        out.push('_');
        out.push_str(&format!("{:02X}", b));
    }
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

#[cfg(test)]
mod ws_fix_tests {
    use super::*;
    use crate::crypto::CryptoManager;

    async fn setup(tag: &str, users: &[&str]) -> (EncryptedLogger, String) {
        let dir = std::env::temp_dir().join(format!("cryptirc-logs-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let crypto = Arc::new(CryptoManager::new(&dir).unwrap());
        for u in users { crypto.unlock(u, &format!("vault pass for {u}")).await.unwrap(); }
        (EncryptedLogger::new(&dir, crypto), dir)
    }

    const CONN: &str = "11111111-2222-3333-4444-555555555555";

    /// Write a day file directly (fast fixture for big histories), AAD-bound exactly
    /// like append() does. Returns the next id.
    fn write_day(lg: &EncryptedLogger, user: &str, conn_dir: &str, target: &str, date: &str,
                 ts0: i64, n: usize, mut id: u64) -> u64 {
        let enc_tgt = encode_path_component(target).unwrap();
        let base = PathBuf::from(&lg.data_dir).join("logs").join(conn_dir).join(&enc_tgt);
        std::fs::create_dir_all(&base).unwrap();
        let aad = log_aad(conn_dir, &enc_tgt, date);
        let mut out = String::new();
        for k in 0..n {
            id += 1;
            let rec = serde_json::json!({"id": id, "ts": ts0 + k as i64, "from": "bob", "text": format!("m{id}"), "kind": "privmsg"}).to_string();
            let crypto = lg.crypto.clone();
            let (rec2, aad2, u) = (rec.clone(), aad.clone(), user.to_string());
            let enc = tokio::task::block_in_place(|| tokio::runtime::Handle::current()
                .block_on(crypto.encrypt_aad(&u, rec2.as_bytes(), &aad2))).unwrap();
            out.push_str(&enc);
            out.push('\n');
        }
        std::fs::write(base.join(format!("{date}.log")), out).unwrap();
        id
    }

    // MEDIUM (a): page boundary inside a same-second burst. Was: page2=0, 100 lines lost.
    #[tokio::test]
    async fn paging_returns_same_second_lines() {
        let (lg, dir) = setup("page", &["alice"]).await;
        for i in 0..300i64 {
            let ts = if i < 150 { 1_700_000_000 } else { 1_700_000_001 };
            assert!(lg.append("alice", CONN, "#chan", ts, "bob", &format!("m{}", i), "privmsg").await > 0);
        }
        let first = lg.read_logs("alice", CONN, "#chan", 10000).await.unwrap();
        let page1: Vec<_> = first[first.len() - 200..].to_vec();
        let oldest_ts = page1[0].ts;
        let page2 = lg.read_logs_before("alice", CONN, "#chan", oldest_ts, 200).await.unwrap();
        // Client-side dedup by id, as app.js prependLogs / the TUI do.
        let mut seen: std::collections::HashSet<u64> = page1.iter().map(|l| l.id).collect();
        for l in &page2 { seen.insert(l.id); }
        println!("WSFIX paging: page1={} page2={} distinct_seen={} of 300", page1.len(), page2.len(), seen.len());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(seen.len(), 300, "every line must be reachable");
        assert!(page2.windows(2).all(|w| w[0].id < w[1].id), "chronological, no dups");
    }

    // MEDIUM (b): history behind more than 50k newer lines (spread over days).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn paging_reaches_past_50k_newer_lines_across_days() {
        let (lg, dir) = setup("deep", &["alice"]).await;
        let mut id = 0;
        id = write_day(&lg, "alice", CONN, "#chan", "2026-01-01", 1_767_225_600, 10, id);
        id = write_day(&lg, "alice", CONN, "#chan", "2026-01-02", 1_767_312_000, 30_000, id);
        let _ = write_day(&lg, "alice", CONN, "#chan", "2026-01-03", 1_767_398_400, 30_000, id);
        // Cursor: 2nd line of 01-02 → everything of 01-01 plus line 1 of 01-02 qualify.
        let got = lg.read_logs_before("alice", CONN, "#chan", 1_767_312_001, 200).await.unwrap();
        println!("WSFIX deep paging (days): returned={}", got.len());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got.len(), 12, "10 old-day lines + line ts==before-1 + the boundary line");
        assert_eq!(got.iter().filter(|l| l.ts < 1_767_225_600 + 86_400).count(), 10);
    }

    // MEDIUM (b), the auditor's exact shape: the cursor's own day holds > 50k newer lines.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn paging_reaches_past_50k_newer_lines_in_one_day() {
        let (lg, dir) = setup("deep1", &["alice"]).await;
        let mut id = 0;
        id = write_day(&lg, "alice", CONN, "#chan", "2026-01-01", 1_767_225_600, 10, id);
        let _ = write_day(&lg, "alice", CONN, "#chan", "2026-01-02", 1_767_312_000, MAX_DECRYPT_LINES + 10, id);
        let before = 1_767_312_000;
        let got = lg.read_logs_before("alice", CONN, "#chan", before, 200).await.unwrap();
        println!("WSFIX deep paging (one day): old-day available=10, returned_older={}", got.iter().filter(|l| l.ts < before).count());
        // And a cursor in the middle of the big day pages correctly too.
        let mid = lg.read_logs_before("alice", CONN, "#chan", before + 20_000, 200).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(got.iter().filter(|l| l.ts < before).count(), 10);
        assert_eq!(mid.iter().filter(|l| l.ts < before + 20_000).count(), 200);
        assert_eq!(mid.last().unwrap().ts, before + 20_000, "boundary-second line included");
        assert_eq!(mid.iter().filter(|l| l.ts < before + 20_000).last().unwrap().ts, before + 19_999);
    }

    // LOW: long non-ASCII target was silently not logged (append_id=0).
    #[tokio::test]
    async fn long_unicode_target_is_logged_readable_and_deletable() {
        let (lg, dir) = setup("long", &["alice"]).await;
        let tgt = format!("#{}", "\u{0436}".repeat(43));
        let enc = encode_path_component(&tgt).unwrap();
        assert!(enc.len() <= 255, "encoded len {}", enc.len());
        let id = lg.append("alice", CONN, &tgt, 1_700_000_000, "bob", "hi", "privmsg").await;
        println!("WSFIX long target: encoded_len={} unbounded_len={} append_id={}", enc.len(), encode_path_component_unbounded(&tgt).len(), id);
        assert!(id > 0);
        let lines = lg.read_logs("alice", CONN, &tgt, 50).await.unwrap();
        assert_eq!(lines.len(), 1);
        // ASCII-case variant of a long target merges (case-insensitive sibling logic).
        let tgt_up = format!("#ABC{}", "\u{0436}".repeat(43));
        let tgt_lo = format!("#abc{}", "\u{0436}".repeat(43));
        assert!(lg.append("alice", CONN, &tgt_up, 1_700_000_001, "bob", "a", "privmsg").await > 0);
        assert!(lg.append("alice", CONN, &tgt_lo, 1_700_000_002, "bob", "b", "privmsg").await > 0);
        assert_eq!(lg.read_logs("alice", CONN, &tgt_lo, 50).await.unwrap().len(), 2);
        assert!(lg.delete_target("alice", CONN, &tgt).await.unwrap());
        assert!(lg.read_logs("alice", CONN, &tgt, 50).await.unwrap().is_empty());
        // Distinct long targets never share a dir.
        let other = format!("#{}x", "\u{0436}".repeat(43));
        assert_ne!(encode_path_component(&other).unwrap(), enc);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Existing on-disk names must not change (AAD + dir names of all current logs).
    #[test]
    fn short_encodings_are_unchanged() {
        assert_eq!(encode_path_component("#rust").unwrap(), "_23rust");
        assert_eq!(encode_path_component("a_b.c").unwrap(), "a_5Fb_2Ec");
        assert_eq!(encode_path_component(CONN).unwrap(), CONN);
        assert_eq!(encode_path_component("status").unwrap(), "status");
        let max_ok = "x".repeat(255);
        assert_eq!(encode_path_component(&max_ok).unwrap(), max_ok);
        let over = "x".repeat(256);
        let h = encode_path_component(&over).unwrap();
        assert!(h.len() <= 255 && h.contains("_z"));
        assert!(encode_path_component("").is_err());
    }

    // F2: history written under a re-cased conn id dir stays readable via the canonical
    // id, appends are canonicalised, and the network delete removes every variant.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recased_conn_dirs_are_merged_and_deleted() {
        let (lg, dir) = setup("variant", &["alice"]).await;
        let canon = "abcdef12-2222-3333-4444-555555555555";
        let var1 = "ABCDEF12-2222-3333-4444-555555555555";
        let var2 = "AbCdEf12-2222-3333-4444-555555555555";
        let mut id = 0;
        id = write_day(&lg, "alice", var1, "#chan", "2026-01-01", 1_767_225_600, 3, id);
        let _ = write_day(&lg, "alice", var2, "#chan", "2026-01-02", 1_767_312_000, 2, id);
        assert!(lg.append("alice", var2, "#chan", 1_767_398_400, "bob", "new", "privmsg").await > 0);
        let root = PathBuf::from(&dir).join("logs");
        assert!(root.join(canon).is_dir(), "append with a re-cased id goes to the canonical dir");
        let all = lg.read_logs("alice", canon, "#chan", 100).await.unwrap();
        assert_eq!(all.len(), 6, "canonical + both variant dirs are read");
        assert_eq!(lg.delete_conn_logs(canon).await, 3);
        assert!(!root.join(canon).exists() && !root.join(var1).exists() && !root.join(var2).exists());
        assert!(lg.read_logs("alice", canon, "#chan", 100).await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // F16: Clear All Data removes the user's orphaned (removed-network) logs only.
    #[tokio::test]
    async fn orphan_logs_deleted_only_for_their_owner() {
        let (lg, dir) = setup("orphan", &["alice", "bob"]).await;
        let alice_live = "aaaaaaaa-0000-0000-0000-000000000001";
        let alice_gone = "aaaaaaaa-0000-0000-0000-000000000002";
        let bob_gone   = "bbbbbbbb-0000-0000-0000-000000000002";
        assert!(lg.append("alice", alice_live, "#a", 1_700_000_000, "x", "1", "privmsg").await > 0);
        assert!(lg.append("alice", alice_gone, "#a", 1_700_000_000, "x", "2", "privmsg").await > 0);
        assert!(lg.append("bob", bob_gone, "#b", 1_700_000_000, "x", "3", "privmsg").await > 0);
        let root = PathBuf::from(&dir).join("logs");
        let mut keep = std::collections::HashSet::new();
        keep.insert(alice_live.to_string());
        assert_eq!(lg.delete_unowned_user_logs("alice", &keep).await, 1);
        assert!(root.join(alice_live).is_dir(), "configured network untouched");
        assert!(!root.join(alice_gone).exists(), "alice's removed network cleared");
        assert!(root.join(bob_gone).is_dir(), "another user's orphan is never touched");
        assert!(root.join(".seq_alice").exists(), "seq counters untouched");
        // Locked vault → nothing is deleted.
        lg.crypto.lock("bob").await;
        assert_eq!(lg.delete_unowned_user_logs("bob", &keep).await, 0);
        assert!(root.join(bob_gone).is_dir());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // delete_target now clears ASCII-case sibling dirs too (they are read-merged).
    #[tokio::test]
    async fn delete_target_clears_case_siblings() {
        let (lg, dir) = setup("sib", &["alice"]).await;
        assert!(lg.append("alice", CONN, "#Chan", 1_700_000_000, "x", "1", "privmsg").await > 0);
        assert!(lg.append("alice", CONN, "#chan", 1_700_000_001, "x", "2", "join").await > 0);
        assert_eq!(lg.read_logs("alice", CONN, "#chan", 10).await.unwrap().len(), 2);
        assert!(lg.delete_target("alice", CONN, "#chan").await.unwrap());
        assert!(lg.read_logs("alice", CONN, "#Chan", 10).await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // codex P1 logs.rs:692: same-date files of case-variant dirs are merged by id BEFORE
    // the limit. Was: `_23chan` (older lines) filled the limit, `_23Chan`'s newest lines
    // (after a case change) never showed in the initial load or in "load older".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn same_day_case_variants_merge_before_limit() {
        let (lg, dir) = setup("casemerge", &["alice"]).await;
        let t0 = 1_767_225_600; // 2026-01-01
        let id = write_day(&lg, "alice", CONN, "#chan", "2026-01-01", t0, 1000, 0);        // ids 1..=1000
        let _ = write_day(&lg, "alice", CONN, "#Chan", "2026-01-01", t0 + 5000, 50, id);  // ids 1001..=1050
        let tail = lg.read_logs("alice", CONN, "#chan", 200).await.unwrap();
        let page = lg.read_logs_before("alice", CONN, "#chan", t0 + 5010, 100).await.unwrap();
        let hits = lg.search_logs("alice", CONN, "#chan", "m10", 5).await.unwrap();
        println!("R2 casemerge: tail {}..{} ({}), page {}..{} ({})",
            tail.first().map_or(0, |l| l.id), tail.last().map_or(0, |l| l.id), tail.len(),
            page.first().map_or(0, |l| l.id), page.last().map_or(0, |l| l.id), page.len());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(tail.len(), 200);
        assert_eq!((tail[0].id, tail[199].id), (851, 1050), "newest 200 across both dirs");
        assert!(tail.windows(2).all(|w| w[0].id < w[1].id));
        // ts < t0+5010 → ids 911..=1010 (100), plus the boundary-second line id 1011.
        assert_eq!(page.len(), 101);
        assert_eq!((page[0].id, page[100].id), (911, 1011));
        // search is newest-first across both dirs too ("m10.." hits: 1050..1000 newest).
        assert_eq!(hits.len(), 5);
        assert_eq!(hits.last().unwrap().id, 1050);
    }

    // INFO (v-srv-b NEW 6): more than BOUNDARY_SECOND_CAP lines in one second left a
    // permanent hole when paging by whole-second cursor. The optional id cursor pages
    // through them exactly; the whole-second form is unchanged for existing clients.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn id_cursor_pages_through_a_huge_second() {
        let (lg, dir) = setup("bigsec", &["alice"]).await;
        let s0 = 1_700_000_000i64;
        for i in 0..10 { assert!(lg.append("alice", CONN, "#c", s0 - 1, "bob", &format!("old{i}"), "privmsg").await > 0); }
        for i in 0..1500 { assert!(lg.append("alice", CONN, "#c", s0, "bob", &format!("burst{i}"), "privmsg").await > 0); }
        let mut shown: Vec<LogLine> = lg.read_logs("alice", CONN, "#c", 200).await.unwrap();
        let mut ids: std::collections::HashSet<u64> = shown.iter().map(|l| l.id).collect();
        for _ in 0..50 {
            let oldest = shown.iter().min_by_key(|l| (l.ts, l.id)).unwrap().clone();
            let page = lg.read_logs_before_id("alice", CONN, "#c", oldest.ts, Some(oldest.id), 200).await.unwrap();
            let before = ids.len();
            for l in &page { ids.insert(l.id); }
            shown.extend(page);
            if ids.len() == before { break; }
        }
        // Whole-second cursor (old clients): unchanged shape — 10 older + 1000 boundary.
        let legacy = lg.read_logs_before("alice", CONN, "#c", s0, 200).await.unwrap();
        println!("R2 bigsec: reached {} of 1510 with the id cursor; legacy page {}", ids.len(), legacy.len());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(ids.len(), 1510, "every line reachable with the id cursor");
        assert_eq!(legacy.len(), 10 + BOUNDARY_SECOND_CAP);
    }

    /// Write id-less (pre-v0.3.0 shape) records, AAD-bound like append().
    fn write_legacy_day(lg: &EncryptedLogger, user: &str, target: &str, date: &str, recs: &[(i64, &str)]) {
        let enc_tgt = encode_path_component(target).unwrap();
        let base = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join(&enc_tgt);
        std::fs::create_dir_all(&base).unwrap();
        let aad = log_aad(CONN, &enc_tgt, date);
        let mut out = String::new();
        for (ts, text) in recs {
            let rec = serde_json::json!({"ts": ts, "from": "bob", "text": text, "kind": "privmsg"}).to_string();
            let crypto = lg.crypto.clone();
            let (aad2, u) = (aad.clone(), user.to_string());
            let enc = tokio::task::block_in_place(|| tokio::runtime::Handle::current()
                .block_on(crypto.encrypt_aad(&u, rec.as_bytes(), &aad2))).unwrap();
            out.push_str(&enc); out.push('\n');
        }
        std::fs::write(base.join(format!("{date}.log")), out).unwrap();
    }

    // TUI report (round 2): id-less lines came back reversed within each second.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn idless_lines_keep_time_order_within_a_second() {
        let (lg, dir) = setup("idless", &["alice"]).await;
        let s0 = 1_700_000_000i64; // 2023-11-14
        let recs: Vec<(i64, String)> = (0..6).map(|i| (s0 + i / 3, format!("old{i}"))).collect();
        let r: Vec<(i64, &str)> = recs.iter().map(|(t, x)| (*t, x.as_str())).collect();
        write_legacy_day(&lg, "alice", "#c", "2023-11-14", &r);
        let tail: Vec<String> = lg.read_logs("alice", CONN, "#c", 50).await.unwrap().into_iter().map(|l| l.text).collect();
        let page: Vec<String> = lg.read_logs_before("alice", CONN, "#c", s0 + 1, 50).await.unwrap().into_iter().map(|l| l.text).collect();
        println!("R2 idless: tail {:?} page {:?}", tail, page);
        let _ = std::fs::remove_dir_all(&dir);
        let all: Vec<String> = (0..6).map(|i| format!("old{i}")).collect();
        assert_eq!(tail, all);
        assert_eq!(page, all, "older second + the whole boundary second, in time order");
    }

    // clients LOW: a user nicked `status` shares the "status" log with the server output.
    #[tokio::test]
    async fn status_view_splits_server_output_from_status_dms() {
        let (lg, dir) = setup("statusv", &["alice"]).await;
        let t = 1_700_000_000i64;
        for (from, text, kind) in [("*", "Welcome to the network", "notice"), ("status", "hi, I am a user called status", "privmsg"),
                                   ("me", "hello status", "privmsg"), ("joe", "⊗ joe quit", "quit"),
                                   ("status", "a notice from status", "notice"), ("irc.example", "server notice", "notice")] {
            assert!(lg.append("alice", CONN, "status", t, from, text, kind).await > 0);
        }
        let texts = |v: Vec<LogLine>| v.into_iter().map(|l| l.text).collect::<Vec<_>>();
        let all = texts(lg.read_logs("alice", CONN, "status", 50).await.unwrap());
        let srv = texts(lg.read_logs_view("alice", CONN, "status", 50, Some(StatusView::Server)).await.unwrap());
        let q = texts(lg.read_logs_view("alice", CONN, "status", 50, Some(StatusView::Query)).await.unwrap());
        let qb = texts(lg.read_logs_before_view("alice", CONN, "status", t + 1, None, 50, Some(StatusView::Query)).await.unwrap());
        let qs = texts(lg.read_logs_since_view("alice", CONN, "status", 0, Some(StatusView::Query)).await.unwrap());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(all.len(), 6, "no field = everything, as before");
        assert_eq!(srv, vec!["Welcome to the network", "⊗ joe quit", "server notice"]);
        assert_eq!(q, vec!["hi, I am a user called status", "hello status", "a notice from status"]);
        assert_eq!(qb, q);
        assert_eq!(qs, q);
    }
}

#[cfg(test)]
mod srv_b_r3_budget_tests {
    //! r3 C1-3: byte budgets on log reads and replies, with paging still complete.
    use super::*;
    use crate::crypto::CryptoManager;

    const CONN: &str = "99999999-2222-3333-4444-555555555555";
    const USER: &str = "alice";

    async fn setup(tag: &str) -> (EncryptedLogger, String) {
        let dir = std::env::temp_dir().join(format!("cryptirc-logbudget-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let crypto = Arc::new(CryptoManager::new(&dir).unwrap());
        crypto.unlock(USER, "vault pass for alice").await.unwrap();
        (EncryptedLogger::new(&dir, crypto), dir)
    }

    /// One day file of `n` lines of `text_len` bytes each, ids from `id0+1`, one second
    /// apart (or all in one second with `same_second`), AAD-bound like append().
    async fn write_big_day(lg: &EncryptedLogger, target: &str, date: &str, ts0: i64, n: usize,
                           text_len: usize, id0: u64, same_second: bool) -> u64 {
        let enc_tgt = encode_path_component(target).unwrap();
        let base = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join(&enc_tgt);
        std::fs::create_dir_all(&base).unwrap();
        let aad = log_aad(CONN, &enc_tgt, date);
        let mut out = String::new();
        let mut id = id0;
        for k in 0..n {
            id += 1;
            let body: String = std::iter::repeat('x').take(text_len.saturating_sub(12)).collect();
            let ts = if same_second { ts0 } else { ts0 + k as i64 };
            let rec = serde_json::json!({"id": id, "ts": ts, "from": "bob", "text": format!("{:010}:{}", id, body), "kind": "privmsg"}).to_string();
            out.push_str(&lg.crypto.encrypt_aad(USER, rec.as_bytes(), &aad).await.unwrap());
            out.push('\n');
        }
        std::fs::write(base.join(format!("{date}.log")), out).unwrap();
        id
    }

    fn reply_bytes(lines: &[LogLine]) -> usize { lines.iter().map(line_cost).sum() }

    const DATE: &str = "2026-01-05";
    fn day0() -> i64 { day_start_ts(DATE).unwrap() }

    #[tokio::test]
    async fn line_reader_keeps_the_newest_lines_within_the_byte_budget() {
        let dir = std::env::temp_dir().join(format!("cryptirc-rrl-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("f.log");
        let lines: Vec<String> = (0..100).map(|i| format!("{:03}{}", i, "y".repeat(997))).collect();
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        let (got, cut) = read_recent_lines_budget(&p, 50_000, 10_000).await;
        assert!(cut);
        assert_eq!(got.len(), 10);
        assert!(got.last().unwrap().starts_with("099") && got.first().unwrap().starts_with("090"));
        let (got, cut) = read_recent_lines_budget(&p, 50_000, 1).await;
        assert!(cut && got.len() == 1, "always keeps the newest line");
        let (got, cut) = read_recent_lines_budget(&p, 50_000, 1 << 30).await;
        assert!(!cut && got.len() == 100);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Sync of a backlog of ~60 KB lines: 0d3570d returned all of them (12 MB here, up
    /// to 50,000 lines in general); now at most MAX_REPLY_BYTES, newest lines, in order.
    #[tokio::test]
    async fn sync_reply_is_byte_bounded_and_keeps_the_newest() {
        let (lg, dir) = setup("sync").await;
        let last = write_big_day(&lg, "#big", DATE, day0() + 100, 200, 60_000, 0, false).await;
        let got = lg.read_logs_since(USER, CONN, "#big", 0).await.unwrap();
        let bytes = reply_bytes(&got);
        assert!(bytes <= MAX_REPLY_BYTES + 61_000, "sync reply {} bytes", bytes);
        assert!(!got.is_empty() && got.len() < 200);
        assert_eq!(got.last().unwrap().id, last, "newest line included");
        assert!(got.windows(2).all(|w| w[0].id + 1 == w[1].id), "contiguous newest window, ascending");
        // A normal-size backlog is unaffected.
        let (lg2, dir2) = setup("sync-small").await;
        write_big_day(&lg2, "#small", DATE, day0() + 100, 3000, 120, 0, false).await;
        assert_eq!(lg2.read_logs_since(USER, CONN, "#small", 0).await.unwrap().len(), 3000);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    #[tokio::test]
    async fn initial_load_and_search_are_byte_bounded() {
        let (lg, dir) = setup("tail").await;
        let last = write_big_day(&lg, "#big", DATE, day0() + 100, 200, 60_000, 0, false).await;
        let got = lg.read_logs(USER, CONN, "#big", 500).await.unwrap();
        assert!(reply_bytes(&got) <= MAX_REPLY_BYTES + 61_000, "{}", reply_bytes(&got));
        assert_eq!(got.last().unwrap().id, last);
        let hits = lg.search_logs(USER, CONN, "#big", "xxxx", 1000).await.unwrap();
        assert!(!hits.is_empty() && reply_bytes(&hits) <= MAX_REPLY_BYTES + 61_000);
        // normal lines: the full 500 come back
        let (lg2, dir2) = setup("tail-small").await;
        write_big_day(&lg2, "#small", DATE, day0() + 100, 3000, 120, 0, false).await;
        assert_eq!(lg2.read_logs(USER, CONN, "#small", 500).await.unwrap().len(), 500);
        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    /// Page a day whose encrypted size (~32 MB) exceeds MAX_READ_BYTES, newest to oldest,
    /// like the app / TUI do: every line is returned exactly once, no page is empty
    /// before the start, every page is byte-bounded. With and without before_id.
    async fn page_everything(with_id: bool) {
        let (lg, dir) = setup(if with_id { "page-id" } else { "page-ts" }).await;
        let n = 400usize;
        write_big_day(&lg, "#big", DATE, day0() + 100, n, 60_000, 0, false).await;
        let mut seen = std::collections::BTreeSet::new();
        let mut page = lg.read_logs(USER, CONN, "#big", 200).await.unwrap();
        let mut rounds = 0;
        loop {
            assert!(reply_bytes(&page) <= MAX_REPLY_BYTES + MAX_REPLY_BOUNDARY_BYTES + 130_000, "page {} bytes", reply_bytes(&page));
            let before_len = seen.len();
            for l in &page { seen.insert(l.id); }
            let oldest = page.first().cloned();
            let Some(oldest) = oldest else { break };
            if oldest.id == 1 { break; }
            assert!(seen.len() > before_len, "paging made progress");
            page = lg.read_logs_before_id(USER, CONN, "#big", oldest.ts, if with_id { Some(oldest.id) } else { None }, 200).await.unwrap();
            rounds += 1;
            assert!(rounds < 200, "paging did not terminate");
        }
        assert_eq!(seen.len(), n, "every line reached exactly once (no hole)");
        assert_eq!(*seen.iter().next().unwrap(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn paging_a_byte_heavy_day_has_no_hole_with_before_id() { page_everything(true).await; }

    #[tokio::test]
    async fn paging_a_byte_heavy_day_has_no_hole_with_ts_cursor() { page_everything(false).await; }

    /// A same-second burst bigger than the boundary allowance can't stall ts-only paging:
    /// older lines always get into the page.
    #[tokio::test]
    async fn heavy_boundary_second_does_not_stall_ts_paging() {
        let (lg, dir) = setup("boundary").await;
        let mut id = write_big_day(&lg, "#b", "2026-01-04", day_start_ts("2026-01-04").unwrap() + 10, 20, 100, 0, false).await;
        id = write_big_day(&lg, "#b", DATE, day0() + 500, 120, 60_000, id, true).await; // 7 MB in ONE second
        let page = lg.read_logs_before_id(USER, CONN, "#b", day0() + 500, None, 200).await.unwrap();
        assert!(page.iter().any(|l| l.ts < day0() + 500), "older lines present despite the heavy boundary second");
        assert!(reply_bytes(&page) <= MAX_REPLY_BYTES + MAX_REPLY_BOUNDARY_BYTES + 130_000);
        let _ = id;
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod srv_b_r4_reader_tests {
    //! r4 C1-6: backward log reading (work bounded by what is returned), no whole-file
    //! offset index, Sync stops at the synced boundary, history-read slots.
    use super::*;
    use crate::crypto::CryptoManager;

    const CONN: &str = "88888888-2222-3333-4444-555555555555";
    const USER: &str = "alice";
    const DATE: &str = "2026-01-05";
    fn day0() -> i64 { day_start_ts(DATE).unwrap() }

    async fn setup(tag: &str) -> (EncryptedLogger, String) {
        let dir = std::env::temp_dir().join(format!("cryptirc-r4rd-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let crypto = Arc::new(CryptoManager::new(&dir).unwrap());
        crypto.unlock(USER, "vault pass for alice").await.unwrap();
        (EncryptedLogger::new(&dir, crypto), dir)
    }

    fn reset_reads() { TEST_READ_BYTES.with(|c| c.set(0)); }
    fn reads() -> u64 { TEST_READ_BYTES.with(|c| c.get()) }

    /// The r3 forward reader, verbatim, as the reference the backward one must match.
    async fn forward_ref(path: &std::path::Path, cap: usize, max_bytes: usize) -> (Vec<String>, bool) {
        use tokio::io::AsyncBufReadExt;
        let file = match tokio::fs::File::open(path).await { Ok(f) => f, Err(_) => return (Vec::new(), false) };
        let mut reader = tokio::io::BufReader::new(file);
        let mut buf: std::collections::VecDeque<String> = std::collections::VecDeque::new();
        let mut bytes: usize = 0;
        let mut truncated = false;
        let mut raw: Vec<u8> = Vec::new();
        loop {
            raw.clear();
            match reader.read_until(b'\n', &mut raw).await { Ok(0) => break, Ok(_) => {}, Err(_) => break }
            while matches!(raw.last(), Some(b'\n') | Some(b'\r')) { raw.pop(); }
            if raw.is_empty() { continue; }
            let line = String::from_utf8_lossy(&raw).into_owned();
            bytes += line.len();
            buf.push_back(line);
            while (cap > 0 && buf.len() > cap) || (bytes > max_bytes && buf.len() > 1) {
                if let Some(old) = buf.pop_front() { bytes -= old.len(); }
                truncated = true;
            }
        }
        (buf.into(), truncated)
    }

    #[tokio::test]
    async fn backward_reader_matches_the_forward_reader() {
        let dir = std::env::temp_dir().join(format!("cryptirc-r4rev-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"\n\n\n".to_vec(),
            b"only".to_vec(),
            b"a\nb\nc\n".to_vec(),
            b"a\r\n\r\nb\r\r\n\nc".to_vec(),
            b"x\xff\xfey\nok\n\xc3\n".to_vec(),
        ];
        // Lines straddling the 64 KiB blocks, some longer than a block, no final newline.
        let mut big = Vec::new();
        for (i, len) in [10usize, 70_000, 3, 65_535, 65_536, 200_000, 1, 131_072, 5].iter().enumerate() {
            big.extend(std::iter::repeat(b'a' + i as u8).take(*len));
            big.extend_from_slice(if i % 3 == 0 { b"\r\n" } else { b"\n" });
            if i % 4 == 0 { big.extend_from_slice(b"\n\n"); }
        }
        big.extend_from_slice(b"tail-without-newline");
        cases.push(big);
        let many: Vec<u8> = (0..20_000).flat_map(|i| format!("line-{i:05}-{}\n", "z".repeat(i % 97)).into_bytes()).collect();
        cases.push(many);
        for (n, content) in cases.iter().enumerate() {
            let p = dir.join(format!("c{n}.log"));
            std::fs::write(&p, content).unwrap();
            for cap in [0usize, 1, 2, 3, 7, 50_000] {
                for budget in [1usize, 100, 70_000, 300_000, 1 << 30] {
                    let a = read_recent_lines_budget(&p, cap, budget).await;
                    let b = forward_ref(&p, cap, budget).await;
                    assert_eq!(a, b, "case {n} cap {cap} budget {budget}");
                }
            }
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A NUL-filled region with no newline (unclean shutdown) is skipped, not buffered,
    /// and the lines on both sides of it are still read.
    #[tokio::test]
    async fn backward_reader_skips_an_overlong_region() {
        let dir = std::env::temp_dir().join(format!("cryptirc-r4nul-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("nul.log");
        let mut c = b"old1\nold2\n".to_vec();
        c.extend(std::iter::repeat(0u8).take(MAX_LOG_LINE_BYTES + 100_000));
        c.extend_from_slice(b"\nnew1\nnew2\n");
        std::fs::write(&p, &c).unwrap();
        let mut r = RevLines::open(&p, None).await.unwrap();
        let mut got = Vec::new();
        while let Some(l) = r.next_line().await { got.push(l); }
        assert_eq!(got, vec!["new2", "new1", "old2", "old1"]);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn positional_helpers_find_line_starts() {
        let dir = std::env::temp_dir().join(format!("cryptirc-r4pos-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("pos.log");
        std::fs::write(&p, b"aaa\nbb\n\ncccc\nd").unwrap();   // starts: 0, 4, 7(blank), 8, 13
        let len = 14u64;
        assert_eq!(line_at_or_after(&p, 0, len).await, Some((4, "aaa".into())));
        assert_eq!(line_at_or_after(&p, 1, len).await, Some((7, "bb".into())));
        assert_eq!(line_at_or_after(&p, 4, len).await, Some((7, "bb".into())));
        assert_eq!(line_at_or_after(&p, 5, len).await, Some((13, "cccc".into())), "skips the blank line");
        assert_eq!(line_at_or_after(&p, 9, len).await, Some((14, "d".into())), "final unterminated line");
        assert_eq!(line_at_or_after(&p, 5, 8).await, None, "no line starts before hi");
        assert_eq!(line_at_or_after(&p, 14, len).await, None);
        assert_eq!(forward_end(&p, 0, 2, 1 << 20).await, Some(7));
        assert_eq!(forward_end(&p, 4, 100, 1 << 20).await, Some(14));
        assert_eq!(forward_end(&p, 0, 100, 1).await, Some(4), "byte cap stops after the first line");
        let mut r = RevLines::open(&p, Some(8)).await.unwrap();
        assert_eq!(r.next_line().await.as_deref(), Some("bb"));
        assert_eq!(r.next_line().await.as_deref(), Some("aaa"));
        assert_eq!(r.next_line().await, None);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// 40 MiB of older (undecryptable) lines, then 2,000 real lines: a tail read, a
    /// search-free Sync of the last ids, and a page of older lines read a few hundred KB,
    /// not the file (the r3 reader streamed all 40 MiB on every request).
    #[tokio::test]
    async fn tail_reads_cost_what_they_return_not_the_file_size() {
        let (lg, dir) = setup("cost").await;
        let enc_tgt = encode_path_component("#cost").unwrap();
        let base = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join(&enc_tgt);
        std::fs::create_dir_all(&base).unwrap();
        let aad = log_aad(CONN, &enc_tgt, DATE);
        let mut f = String::with_capacity(42 << 20);
        let junk = "j".repeat(1023);
        for _ in 0..(40 * 1024) { f.push_str(&junk); f.push('\n'); }
        for id in 1..=2000u64 {
            let rec = serde_json::json!({"id": id, "ts": day0() + id as i64, "from": "bob", "text": format!("line {id}"), "kind": "privmsg"}).to_string();
            f.push_str(&lg.crypto.encrypt_aad(USER, rec.as_bytes(), &aad).await.unwrap());
            f.push('\n');
        }
        std::fs::write(base.join(format!("{DATE}.log")), f).unwrap();

        reset_reads();
        let got = lg.read_logs(USER, CONN, "#cost", 50).await.unwrap();
        assert_eq!((got.len(), got[0].id, got[49].id), (50, 1951, 2000));
        assert!(reads() < 256 * 1024, "initial load read {} bytes", reads());

        reset_reads();
        let got = lg.read_logs_since(USER, CONN, "#cost", 1990).await.unwrap();
        assert_eq!(got.iter().map(|l| l.id).collect::<Vec<_>>(), (1991..=2000).collect::<Vec<_>>());
        assert!(reads() < 1024 * 1024, "sync read {} bytes", reads());

        reset_reads();
        let got = lg.read_logs_before(USER, CONN, "#cost", day0() + 1500, 100).await.unwrap();
        assert_eq!(got.first().map(|l| l.id), Some(1400));
        assert_eq!(got.last().map(|l| l.id), Some(1500), "boundary second included");
        assert!(reads() < 1024 * 1024, "load-older read {} bytes", reads());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Fully-synced older day files are probed from their END only.
    #[tokio::test]
    async fn sync_probes_older_days_from_their_end() {
        let (lg, dir) = setup("probe").await;
        let enc_tgt = encode_path_component("#days").unwrap();
        let base = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join(&enc_tgt);
        std::fs::create_dir_all(&base).unwrap();
        let mut id = 0u64;
        for d in 1..=20u32 {
            let date = format!("2026-02-{d:02}");
            let aad = log_aad(CONN, &enc_tgt, &date);
            let mut f = String::new();
            for _ in 0..4000 {
                id += 1;
                let rec = serde_json::json!({"id": id, "ts": day_start_ts(&date).unwrap() + 60, "from": "bob", "text": "x".repeat(200), "kind": "privmsg"}).to_string();
                f.push_str(&lg.crypto.encrypt_aad(USER, rec.as_bytes(), &aad).await.unwrap());
                f.push('\n');
            }
            std::fs::write(base.join(format!("{date}.log")), f).unwrap();
        }
        let total: u64 = std::fs::read_dir(&base).unwrap().map(|e| e.unwrap().metadata().unwrap().len()).sum();
        reset_reads();
        let got = lg.read_logs_since(USER, CONN, "#days", id - 5).await.unwrap();
        assert_eq!(got.len(), 5);
        assert!(reads() < total / 4, "sync read {} of {} bytes", reads(), total);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// At most LOG_READS_PER_USER reads of one account run at once, and at most
    /// LOG_READS_MAX_CONCURRENT overall; slots are released.
    #[tokio::test]
    async fn read_slots_are_bounded_per_account_and_overall() {
        let (lg, dir) = setup("slots").await;
        let a1 = lg.read_slot("alice").await;
        let a2 = lg.read_slot("alice").await;
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), lg.read_slot("alice")).await.is_err(), "third alice read waits");
        let b1 = lg.read_slot("bob").await;
        let b2 = lg.read_slot("bob").await;
        assert!(tokio::time::timeout(std::time::Duration::from_millis(100), lg.read_slot("carol")).await.is_err(), "global cap reached");
        drop(a1);
        let c1 = tokio::time::timeout(std::time::Duration::from_millis(500), lg.read_slot("carol")).await.expect("slot freed");
        drop((a2, b1, b2, c1));
        let _x = tokio::time::timeout(std::time::Duration::from_millis(500), lg.read_slot("alice")).await.expect("all free");
        let _ = std::fs::remove_dir_all(dir);
    }
}

#[cfg(test)]
mod srv_b_r6_legacy_tests {
    //! r6 (codex P1 logs.rs:645): `#alice`'s legacy (pre-#52) dir `alice` is the CURRENT dir
    //! of the DM with Alice — the channel must neither show nor delete the DM's history, in
    //! either direction, while pre-#52 channel history stays readable.
    use super::*;
    use crate::crypto::CryptoManager;
    const CONN: &str = "77777777-2222-3333-4444-555555555555";
    const U: &str = "alice";

    async fn setup(tag: &str) -> (EncryptedLogger, String) {
        let dir = std::env::temp_dir().join(format!("cryptirc-r6leg-{}-{}", tag, uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = dir.to_string_lossy().to_string();
        let crypto = Arc::new(CryptoManager::new(&dir).unwrap());
        crypto.unlock(U, "vault pass for alice").await.unwrap();
        (EncryptedLogger::new(&dir, crypto), dir)
    }
    fn ts(date: &str) -> i64 { day_start_ts(date).unwrap() + 3600 }
    async fn texts(lg: &EncryptedLogger, target: &str) -> Vec<String> {
        lg.read_logs(U, CONN, target, 500).await.unwrap().into_iter().map(|l| l.text).collect()
    }

    async fn seed(lg: &EncryptedLogger) {
        // pre-#52 era: the lossy scheme wrote `#alice` into `alice` (mixed with the DM)
        lg.append(U, CONN, "alice", ts("2025-12-01"), "bob", "legacy-chan-line", "privmsg").await;
        // the current scheme: channel in `_23alice`, the DM in `alice`
        lg.append(U, CONN, "#alice", ts("2026-01-10"), "carol", "chan-new", "privmsg").await;
        lg.append(U, CONN, "alice", ts("2026-01-12"), "alice", "dm-new", "privmsg").await;
    }

    #[tokio::test]
    async fn channel_view_does_not_include_the_dms_current_history() {
        let (lg, dir) = setup("read").await;
        seed(&lg).await;
        let chan = texts(&lg, "#alice").await;
        assert!(chan.contains(&"chan-new".to_string()));
        assert!(chan.contains(&"legacy-chan-line".to_string()), "pre-#52 channel history still readable (#52)");
        assert!(!chan.contains(&"dm-new".to_string()), "the DM's current history is not mixed in: {chan:?}");
        let dm = texts(&lg, "alice").await;
        assert!(dm.contains(&"dm-new".to_string()) && !dm.contains(&"chan-new".to_string()), "{dm:?}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn clearing_the_channel_keeps_the_dm_and_vice_versa() {
        let (lg, dir) = setup("del").await;
        seed(&lg).await;
        assert!(lg.delete_target(U, CONN, "#alice").await.unwrap());
        assert!(texts(&lg, "alice").await.contains(&"dm-new".to_string()), "clearing #alice kept the DM");
        assert!(!texts(&lg, "#alice").await.contains(&"chan-new".to_string()));
        // the other direction
        lg.append(U, CONN, "#alice", ts("2026-01-15"), "carol", "chan-again", "privmsg").await;
        assert!(lg.delete_target(U, CONN, "alice").await.unwrap());
        assert!(texts(&lg, "#alice").await.contains(&"chan-again".to_string()), "clearing the DM kept #alice");
        assert!(texts(&lg, "alice").await.is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A legacy name that can't be any target's current dir (here `#a.b` → `a_b`) is read
    /// and cleared with its channel as before.
    #[tokio::test]
    async fn an_unambiguous_legacy_dir_is_still_read_and_cleared() {
        let (lg, dir) = setup("unamb").await;
        let legacy = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join("a_b");
        std::fs::create_dir_all(&legacy).unwrap();
        let date = "2025-11-01";
        let rec = serde_json::json!({"id": 1, "ts": ts(date), "from": "bob", "text": "old-ab", "kind": "privmsg"}).to_string();
        let enc = lg.crypto.encrypt_aad(U, rec.as_bytes(), &log_aad(CONN, "a_b", date)).await.unwrap();
        std::fs::write(legacy.join(format!("{date}.log")), enc + "\n").unwrap();
        lg.append(U, CONN, "#a.b", ts("2026-01-10"), "carol", "new-ab", "privmsg").await;
        let got = texts(&lg, "#a.b").await;
        assert!(got.contains(&"old-ab".to_string()) && got.contains(&"new-ab".to_string()), "{got:?}");
        assert!(lg.delete_target(U, CONN, "#a.b").await.unwrap());
        assert!(!legacy.exists(), "unambiguous legacy dir cleared with its channel");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// r7 (agy P1 logs.rs:1750): a non-date `*.log` in a current-scheme dir is not a cutover.
    #[tokio::test]
    async fn stray_log_files_do_not_become_the_cutover() {
        let (lg, dir) = setup("stray").await;
        seed(&lg).await;
        let chan_dir = PathBuf::from(&lg.data_dir).join("logs").join(CONN).join("_23alice");
        for stray in ["audit.log", "0.log", "2026-1-5.log", "2026-13-01.log"] {
            std::fs::write(chan_dir.join(stray), "junk\n").unwrap();
        }
        let conn_dir = PathBuf::from(&lg.data_dir).join("logs").join(CONN);
        assert_eq!(legacy_cutover(&conn_dir).await.as_deref(), Some("2026-01-10"));
        let chan = texts(&lg, "#alice").await;
        assert!(chan.contains(&"legacy-chan-line".to_string()), "legacy history still visible: {chan:?}");
        assert!(!chan.contains(&"dm-new".to_string()));
        // a corrupt remembered marker is ignored and rewritten
        std::fs::write(conn_dir.join(".legacy_cutover"), "audit").unwrap();
        assert_eq!(legacy_cutover(&conn_dir).await.as_deref(), Some("2026-01-10"));
        assert!(is_day_stem("2026-01-10") && !is_day_stem("2026-1-10") && !is_day_stem("audit") && !is_day_stem("2026-02-30"));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn current_encoding_detection() {
        for n in ["alice", "Bob-1", "_23alice", "_5Bbob_5D", "x_23y", "_C3_A9"] { assert!(is_current_encoding(n), "{n}"); }
        for n in ["a_b", "über", "_41", "a_2", "", "a_zz", "_FF"] { assert!(!is_current_encoding(n), "{n}"); }
    }
}
