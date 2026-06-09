/// upload.rs — Multipart file upload handler
///
/// Fixes applied:
///   C8  — size enforced via axum DefaultBodyLimit (set in main.rs); note: the
///         /upload (non-chunked) path still buffers the field in RAM before the
///         per-app size check — the real per-request ceiling is the axum
///         DefaultBodyLimit / nginx client_max_body_size set in main.rs / nginx.
///   H4  — SVG served as application/octet-stream to prevent JS execution
///   M2  — blocklist of dangerous extensions
///   M6  — require non-empty extension after sanitize
///   #16/#38 — per-user storage quota (total bytes + file count) and a cap on
///         concurrent in-progress chunked uploads, enforced before accepting
///         any new upload or chunk.
///   #21 — every mutation of a user's records JSON is serialized behind a
///         per-user async mutex and persisted via temp-file + atomic rename, so
///         concurrent uploads/chunks can no longer clobber each other.
///   #30 — A/V metadata stripping (ffmpeg) is wrapped in a timeout, gated by a
///         global concurrency semaphore, bounded to a fixed thread count, and
///         REJECTS (rather than silently stores the un-stripped original) on
///         failure.
///   #39 — formats needing no metadata stripping are moved (rename) into the
///         upload dir instead of being re-buffered + rewritten.
///   #88 — malformed images are rejected rather than stored with metadata intact.

use anyhow::Result;
use axum::extract::Multipart;
use dashmap::DashMap;
use serde::Serialize;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;

/// Default max upload size — overridden at runtime by admin setting.
const DEFAULT_MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;

// ─── Resource caps (#16 / #38 / #30) ─────────────────────────────────────────

/// Per-user cap on cumulative stored bytes across all of a user's uploads
/// (completed + in-flight). Rejects new uploads/chunks once exceeded so a
/// single authenticated account cannot fill the data volume.
const PER_USER_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024 * 1024; // 2 GiB

/// Per-user cap on the number of upload records (completed + in-flight).
const PER_USER_MAX_FILES: usize = 2000;

/// Per-user cap on simultaneously in-progress (Uploading) chunked uploads.
const PER_USER_MAX_INPROGRESS: usize = 16;

/// Global cap on concurrent ffmpeg metadata-strip jobs (CPU bound).
const AV_STRIP_MAX_CONCURRENT: usize = 2;

/// Wall-clock timeout for a single ffmpeg metadata-strip job.
const AV_STRIP_TIMEOUT: Duration = Duration::from_secs(60);

/// Global semaphore bounding concurrent ffmpeg invocations so a burst of A/V
/// uploads cannot spawn unbounded CPU-heavy processes.
fn av_strip_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(AV_STRIP_MAX_CONCURRENT))
}

// ─── Per-user records-file serialization (#21) ───────────────────────────────

/// One async mutex per username, guarding the read-modify-write of that user's
/// `uploads/{username}.json`. Mirrors the e2e otpk_locks pattern. File-local so
/// it does not touch AppState.
fn record_locks() -> &'static DashMap<String, Arc<Mutex<()>>> {
    static LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
    LOCKS.get_or_init(DashMap::new)
}

/// Acquire (creating if needed) the per-user records lock.
fn user_record_lock(username: &str) -> Arc<Mutex<()>> {
    record_locks()
        .entry(username.to_string())
        .or_insert_with(|| Arc::new(Mutex::new(())))
        .clone()
}

/// Set of (extensions) that strip_metadata leaves byte-for-byte identical, so
/// finalize can move the temp file instead of re-reading + rewriting (#39).
fn ext_needs_strip(ext: &str) -> bool {
    matches!(
        ext,
        "jpg" | "jpeg" | "png" | "mp4" | "webm" | "mp3" | "ogg" | "wav" | "flac"
    )
}

/// Extensions whose MIME types could execute code in a browser.
/// These are blocked entirely rather than served with a wrong type.
const BLOCKED_EXTENSIONS: &[&str] = &[
    "html", "htm", "xhtml", "xml",
    "js",   "mjs", "cjs",   "ts",
    "php",  "php3","php4",  "php5", "phtml",
    "asp",  "aspx","jsp",   "jspx",
    "sh",   "bash","zsh",   "fish",
    "py",   "rb",  "pl",    "lua",
    "exe",  "dll", "so",    "dylib",
    "bat",  "cmd", "ps1",   "vbs",
    "svg",  // SVG can embed JS — block by default
    "htaccess", "htpasswd",
];

#[derive(Debug, Serialize)]
pub struct UploadResult {
    pub url:           String,
    pub filename:      String,
    pub original_name: String,
    pub size:          usize,
    pub content_type:  String,
    pub is_image:      bool,
}

pub async fn handle_upload(upload_dir: &str, mut multipart: Multipart, max_bytes: usize) -> Result<UploadResult> {
    let limit = if max_bytes > 0 { max_bytes } else { DEFAULT_MAX_UPLOAD_BYTES };
    while let Some(field) = multipart.next_field().await? {
        let original_name = field.file_name().unwrap_or("upload").to_string();
        // Clamp original_name length
        let original_name: String = original_name.chars().take(255).collect();

        let data = field.bytes().await?;
        if data.len() > limit {
            let limit_mb = limit / (1024 * 1024);
            anyhow::bail!("File too large (max {} MB)", limit_mb);
        }
        if data.is_empty() {
            anyhow::bail!("Empty file");
        }

        let raw_ext = original_name
            .rsplit('.')
            .next()
            .unwrap_or("bin")
            .to_lowercase();
        let ext = sanitize_ext(&raw_ext);

        // M6: require a non-empty extension
        if ext.is_empty() {
            anyhow::bail!("Missing or invalid file extension");
        }

        // M2: block dangerous extensions
        if BLOCKED_EXTENSIONS.contains(&ext.as_str()) {
            anyhow::bail!("File type not permitted");
        }

        // Strip image metadata (EXIF, GPS, camera info, etc.) for privacy.
        // #88/#30: rejects (does not store) malformed images or A/V files that
        // cannot be stripped, rather than silently keeping their metadata.
        let data = strip_metadata(&data, &ext).await?;

        let filename = format!("{}.{}", Uuid::new_v4(), ext);
        std::fs::create_dir_all(upload_dir)?;
        let path = PathBuf::from(upload_dir).join(&filename);
        tokio::fs::write(&path, &data).await?;

        let content_type = safe_content_type(&ext);
        let is_image     = content_type.starts_with("image/");

        return Ok(UploadResult {
            url: format!("{}/files/{}", std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into()), filename),
            filename,
            original_name,
            size: data.len(),
            content_type: content_type.to_string(),
            is_image,
        });
    }
    anyhow::bail!("No file in request")
}

fn sanitize_ext(ext: &str) -> String {
    ext.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(10)
        .collect::<String>()
        .to_lowercase()
}

/// H4: Return a safe, allowlisted content type.
/// Anything not on the allowlist gets application/octet-stream.
/// SVG is intentionally absent — blocked before reaching here.
pub fn safe_content_type(ext: &str) -> &'static str {
    match ext {
        "jpg" | "jpeg" => "image/jpeg",
        "png"          => "image/png",
        "gif"          => "image/gif",
        "webp"         => "image/webp",
        "avif"         => "image/avif",
        "ico"          => "image/x-icon",
        "mp4"          => "video/mp4",
        "webm"         => "video/webm",
        "mp3"          => "audio/mpeg",
        "ogg"          => "audio/ogg",
        "wav"          => "audio/wav",
        "flac"         => "audio/flac",
        "pdf"          => "application/pdf",
        "zip"          => "application/zip",
        "gz"           => "application/gzip",
        "tar"          => "application/x-tar",
        "7z"           => "application/x-7z-compressed",
        "txt"          => "text/plain; charset=utf-8",
        "log"          => "text/plain; charset=utf-8",
        "md"           => "text/plain; charset=utf-8",
        _              => "application/octet-stream",
    }
}

/// Used by the file-serving route.
pub fn content_type_for(filename: &str) -> &'static str {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    safe_content_type(&ext)
}

// ─── Per-user upload tracking ────────────────────────────────────────────────

/// Status of a single upload row visible in the user's Uploads channel.
#[derive(Debug, Serialize, serde::Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UploadStatus {
    Uploading,
    Done,
    Error,
    Canceled,
}

#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct UploadRecord {
    /// Stable id chosen by the client, used across HTTP + WS for this upload.
    /// Defaults to filename for legacy completed records (which had no id).
    #[serde(default)]
    pub id: String,
    pub filename: String,
    pub original_name: String,
    pub size: usize,
    pub content_type: String,
    pub url: String,
    pub uploaded_at: i64,
    #[serde(default = "default_done_status")]
    pub status: UploadStatus,
    #[serde(default)]
    pub progress_bytes: usize,
    #[serde(default)]
    pub started_at: i64,
    #[serde(default)]
    pub completed_at: i64,
    #[serde(default)]
    pub error: String,
    /// Where the originating device intended this upload to go (for the
    /// "Insert into chat" UX). Optional — purely a display hint.
    #[serde(default)]
    pub source_conn_id: String,
    #[serde(default)]
    pub source_target: String,
}

fn default_done_status() -> UploadStatus { UploadStatus::Done }

fn user_uploads_path(data_dir: &str, username: &str) -> PathBuf {
    PathBuf::from(data_dir).join("uploads").join(format!("{}.json", username))
}

pub async fn record_upload(data_dir: &str, username: &str, result: &UploadResult) -> Result<()> {
    // #21: serialize the read-modify-write behind the per-user records lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;

    let path = user_uploads_path(data_dir, username);
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let mut records = load_user_records(&path).await;
    // #16: reject if this completed upload would push the user over quota.
    check_quota(&records, None, result.size)?;
    let now = chrono::Utc::now().timestamp();
    records.push(UploadRecord {
        id: result.filename.clone(), // legacy direct uploads use filename as id
        filename: result.filename.clone(),
        original_name: result.original_name.clone(),
        size: result.size,
        content_type: result.content_type.clone(),
        url: result.url.clone(),
        uploaded_at: now,
        status: UploadStatus::Done,
        progress_bytes: result.size,
        started_at: now,
        completed_at: now,
        error: String::new(),
        source_conn_id: String::new(),
        source_target: String::new(),
    });
    write_records_atomic(&path, &records).await;
    Ok(())
}

// ─── Chunked / resumable upload management ───────────────────────────────────

/// Filesystem-safe id used in temp paths. Same alphabet as filename sanitizer.
fn safe_id(id: &str) -> String {
    id.chars()
        .filter(|c| c.is_alphanumeric() || *c == '-' || *c == '_')
        .take(64)
        .collect()
}

fn safe_user(username: &str) -> String {
    username.chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect()
}

/// Temp directory for in-flight chunks for one upload.
/// Layout: {data_dir}/uploads/_inprogress/{username}/{id}/{ data, meta.json }
fn inprogress_dir(data_dir: &str, username: &str, id: &str) -> Option<PathBuf> {
    let u = safe_user(username);
    let i = safe_id(id);
    if u.is_empty() || i.is_empty() { return None; }
    Some(PathBuf::from(data_dir).join("uploads").join("_inprogress").join(u).join(i))
}

/// #31: Sweep abandoned in-progress chunked uploads. Walks
/// `{data_dir}/uploads/_inprogress/<user>/<id>` and deletes any upload dir
/// whose `data` file has not been modified within `ttl`. Intended to be called
/// from the hourly background task and once at startup. Returns the number of
/// stale upload dirs removed.
///
/// NOTE: this only reclaims disk. Flipping the matching "Uploading" record to
/// Error would require per-user iteration of records files; callers that want
/// that can follow up via [`error_chunked_upload`].
pub async fn sweep_stale_inprogress(data_dir: &str, ttl: Duration) -> usize {
    let root = PathBuf::from(data_dir).join("uploads").join("_inprogress");
    let now = std::time::SystemTime::now();
    let mut removed = 0usize;

    let mut users = match tokio::fs::read_dir(&root).await {
        Ok(d) => d,
        Err(_) => return 0, // no in-progress dir yet
    };
    while let Ok(Some(user_entry)) = users.next_entry().await {
        let user_path = user_entry.path();
        if !user_path.is_dir() { continue; }
        let mut uploads = match tokio::fs::read_dir(&user_path).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut any_left = false;
        while let Ok(Some(up_entry)) = uploads.next_entry().await {
            let up_path = up_entry.path();
            if !up_path.is_dir() { continue; }
            // Use the mtime of the data file (or the dir) to judge staleness.
            let stamp = tokio::fs::metadata(up_path.join("data")).await
                .or(tokio::fs::metadata(&up_path).await)
                .ok()
                .and_then(|m| m.modified().ok());
            let stale = match stamp {
                Some(t) => now.duration_since(t).map(|age| age > ttl).unwrap_or(false),
                None => false,
            };
            if stale {
                if tokio::fs::remove_dir_all(&up_path).await.is_ok() {
                    removed += 1;
                }
            } else {
                any_left = true;
            }
        }
        // Best-effort: drop now-empty per-user dirs.
        if !any_left {
            let _ = tokio::fs::remove_dir(&user_path).await;
        }
    }
    removed
}

/// Read/write the per-user persistent record list. Mutations are serialized by
/// callers behind the per-user records lock (see [`user_record_lock`]) and
/// persisted via [`write_records_atomic`].
async fn load_records(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    let mut records = load_user_records(&user_uploads_path(data_dir, username)).await;
    // Migration: pre-chunked records have empty id. Backfill from filename
    // so every row has a unique stable key for in-memory maps and remove().
    for r in &mut records {
        if r.id.is_empty() {
            r.id = if r.filename.is_empty() { Uuid::new_v4().to_string() } else { r.filename.clone() };
        }
        if r.progress_bytes == 0 && r.status == UploadStatus::Done { r.progress_bytes = r.size; }
        if r.started_at == 0  { r.started_at  = r.uploaded_at; }
        if r.completed_at == 0 && r.status == UploadStatus::Done { r.completed_at = r.uploaded_at; }
    }
    records
}

async fn save_records(data_dir: &str, username: &str, records: &[UploadRecord]) {
    let path = user_uploads_path(data_dir, username);
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    write_records_atomic(&path, records).await;
}

/// Persist the records list via temp-file + atomic rename (#21) so a crash
/// mid-write cannot truncate the list and a concurrent reader never observes a
/// partial file.
async fn write_records_atomic(path: &PathBuf, records: &[UploadRecord]) {
    let json = serde_json::to_string(records).unwrap_or_default();
    let tmp = path.with_extension("json.tmp");
    if tokio::fs::write(&tmp, &json).await.is_ok() {
        if tokio::fs::rename(&tmp, path).await.is_err() {
            // Rename can fail across some filesystems; fall back to direct write.
            let _ = tokio::fs::write(path, &json).await;
            let _ = tokio::fs::remove_file(&tmp).await;
        }
    }
}

/// Aggregate stored bytes + counts for a user. Used to enforce the per-user
/// quota (#16 / #38) before accepting a new upload or chunk. Counts both
/// finalized and in-flight bytes (progress_bytes is the on-disk size for
/// in-progress chunked uploads).
struct UserUsage {
    total_bytes: usize,
    file_count:  usize,
    inprogress:  usize,
}

fn compute_usage(records: &[UploadRecord], exclude_id: Option<&str>) -> UserUsage {
    let mut total_bytes = 0usize;
    let mut file_count  = 0usize;
    let mut inprogress  = 0usize;
    for r in records {
        if exclude_id == Some(r.id.as_str()) { continue; }
        file_count += 1;
        // For completed uploads `size` is the stored size; for in-flight ones
        // `progress_bytes` reflects bytes already written to disk.
        total_bytes = total_bytes.saturating_add(r.size.max(r.progress_bytes));
        if r.status == UploadStatus::Uploading { inprogress += 1; }
    }
    UserUsage { total_bytes, file_count, inprogress }
}

/// Reject if adding `incoming_bytes` (an upload not already counted under
/// `exclude_id`) would exceed the per-user storage quota or file-count cap.
fn check_quota(records: &[UploadRecord], exclude_id: Option<&str>, incoming_bytes: usize) -> Result<()> {
    let usage = compute_usage(records, exclude_id);
    // Only count a brand-new file toward the file cap.
    if exclude_id.map_or(true, |id| !records.iter().any(|r| r.id == id))
        && usage.file_count >= PER_USER_MAX_FILES
    {
        anyhow::bail!("Upload limit reached (max {} files)", PER_USER_MAX_FILES);
    }
    if usage.total_bytes.saturating_add(incoming_bytes) > PER_USER_MAX_TOTAL_BYTES {
        anyhow::bail!(
            "Storage quota exceeded (max {} MB per account)",
            PER_USER_MAX_TOTAL_BYTES / (1024 * 1024)
        );
    }
    Ok(())
}

/// Find-or-insert by id; apply mutation; persist. Returns the new record.
///
/// #21: the whole load→mutate→save runs while holding the per-user records
/// lock so concurrent uploads/chunks for the same user serialize instead of
/// clobbering each other.
async fn upsert_record<F: FnOnce(&mut UploadRecord)>(
    data_dir: &str, username: &str, id: &str,
    blank: UploadRecord, mutate: F,
) -> UploadRecord {
    // Infallible path: validator always succeeds.
    upsert_record_validated(data_dir, username, id, blank, |_| Ok(()), mutate)
        .await
        .expect("upsert_record_validated with Ok validator cannot fail")
}

/// Like [`upsert_record`] but runs `validate` against the current record list
/// (under the lock, before mutating) so quota/concurrency checks see a
/// consistent snapshot and cannot race a concurrent writer (#16 / #21 / #38).
async fn upsert_record_validated<V, F>(
    data_dir: &str, username: &str, id: &str,
    blank: UploadRecord, validate: V, mutate: F,
) -> Result<UploadRecord>
where
    V: FnOnce(&[UploadRecord]) -> Result<()>,
    F: FnOnce(&mut UploadRecord),
{
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;

    let mut records = load_records(data_dir, username).await;
    validate(&records)?;
    let pos = records.iter().position(|r| r.id == id);
    let record = match pos {
        Some(p) => { mutate(&mut records[p]); records[p].clone() }
        None    => {
            let mut r = blank;
            mutate(&mut r);
            records.push(r.clone());
            r
        }
    };
    save_records(data_dir, username, &records).await;
    Ok(record)
}

pub async fn get_record(data_dir: &str, username: &str, id: &str) -> Option<UploadRecord> {
    load_records(data_dir, username).await.into_iter().find(|r| r.id == id)
}

/// Begin a chunked upload. Creates the temp directory and a new record in
/// `Uploading` state with progress_bytes=0. Idempotent on retry — if a
/// record with this id already exists in `Uploading`, returns it unchanged.
pub async fn init_chunked_upload(
    data_dir: &str, username: &str, id: &str,
    original_name: &str, size: usize,
    source_conn_id: &str, source_target: &str,
) -> Result<UploadRecord> {
    let id = safe_id(id);
    if id.is_empty() { anyhow::bail!("Invalid upload id"); }
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    tokio::fs::create_dir_all(&dir).await?;
    // Resume case: if data file already has bytes, keep them.
    let existing_bytes = match tokio::fs::metadata(dir.join("data")).await {
        Ok(m) => m.len() as usize,
        Err(_) => 0,
    };

    let original_name: String = original_name.chars().take(255).collect();
    let now = chrono::Utc::now().timestamp();
    let blank = UploadRecord {
        id: id.clone(),
        filename: String::new(),
        original_name: original_name.clone(),
        size,
        content_type: String::new(),
        url: String::new(),
        uploaded_at: 0,
        status: UploadStatus::Uploading,
        progress_bytes: existing_bytes,
        started_at: now,
        completed_at: 0,
        error: String::new(),
        source_conn_id: source_conn_id.to_string(),
        source_target: source_target.to_string(),
    };
    let id_for_check = id.clone();
    let rec = upsert_record_validated(data_dir, username, &id, blank,
        |records| {
            // #38: cap simultaneously in-progress chunked uploads. A revive of an
            // already-Uploading record with this id does not add a new one.
            let already_uploading = records.iter()
                .any(|r| r.id == id_for_check && r.status == UploadStatus::Uploading);
            if !already_uploading {
                let inprogress = compute_usage(records, None).inprogress;
                if inprogress >= PER_USER_MAX_INPROGRESS {
                    anyhow::bail!(
                        "Too many uploads in progress (max {})",
                        PER_USER_MAX_INPROGRESS
                    );
                }
            }
            // #16: reject if the declared full size would push the user over quota
            // (exclude this id's existing row, which is being (re)started).
            check_quota(records, Some(&id_for_check), size)
        },
        |r| {
            // If reviving a non-Uploading record, reset to Uploading. This
            // covers the "I canceled then tried again with the same id" case.
            if r.status != UploadStatus::Uploading {
                r.status = UploadStatus::Uploading;
                r.error = String::new();
                r.url = String::new();
                r.filename = String::new();
                r.completed_at = 0;
                r.uploaded_at = 0;
            }
            r.progress_bytes = existing_bytes;
            r.size = size;
            r.original_name = original_name.clone();
            if !source_conn_id.is_empty() { r.source_conn_id = source_conn_id.to_string(); }
            if !source_target.is_empty() { r.source_target = source_target.to_string(); }
        }).await?;
    Ok(rec)
}

/// Append a chunk at the given absolute offset. Validates that offset matches
/// the current file size (no out-of-order writes). Returns the new
/// progress_bytes after appending. Caller is responsible for honoring any
/// max-upload limit before calling.
pub async fn append_chunk(
    data_dir: &str, username: &str, id: &str,
    offset: usize, chunk: &[u8],
) -> Result<UploadRecord> {
    use tokio::io::AsyncWriteExt;
    let id = safe_id(id);
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    let data_path = dir.join("data");
    let current = match tokio::fs::metadata(&data_path).await {
        Ok(m) => m.len() as usize,
        Err(_) => 0,
    };
    if offset != current {
        anyhow::bail!("Offset mismatch (have {}, got {})", current, offset);
    }
    let new_total = current + chunk.len();
    // #16: reject the chunk BEFORE writing it to disk if the resulting on-disk
    // size for this upload would push the user over quota. We exclude this id's
    // current row (its already-counted progress) and re-add new_total.
    {
        let lock = user_record_lock(username);
        let _guard = lock.lock().await;
        let records = load_records(data_dir, username).await;
        check_quota(&records, Some(&id), new_total)?;
    }
    let mut file = tokio::fs::OpenOptions::new()
        .create(true).append(true).open(&data_path).await?;
    file.write_all(chunk).await?;
    file.flush().await?;
    let rec = upsert_record(data_dir, username, &id,
        UploadRecord {
            id: id.clone(), filename: String::new(), original_name: String::new(),
            size: 0, content_type: String::new(), url: String::new(),
            uploaded_at: 0, status: UploadStatus::Uploading,
            progress_bytes: new_total, started_at: chrono::Utc::now().timestamp(),
            completed_at: 0, error: String::new(),
            source_conn_id: String::new(), source_target: String::new(),
        },
        |r| { r.progress_bytes = new_total; r.status = UploadStatus::Uploading; },
    ).await;
    Ok(rec)
}

/// Finalize: validate the assembled temp file, strip metadata, move into
/// the public upload dir, mark record as Done. Returns the final record.
pub async fn finalize_chunked_upload(
    data_dir: &str, upload_dir: &str, username: &str, id: &str,
) -> Result<UploadRecord> {
    let id = safe_id(id);
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    let data_path = dir.join("data");
    let on_disk_len = tokio::fs::metadata(&data_path).await
        .map(|m| m.len() as usize)
        .map_err(|_| anyhow::anyhow!("No data uploaded"))?;
    if on_disk_len == 0 { anyhow::bail!("Empty file"); }

    let existing = get_record(data_dir, username, &id).await
        .ok_or_else(|| anyhow::anyhow!("Unknown upload id"))?;
    let original_name = existing.original_name.clone();
    if existing.size > 0 && on_disk_len != existing.size {
        anyhow::bail!("Size mismatch (declared {} got {})", existing.size, on_disk_len);
    }

    let raw_ext = original_name.rsplit('.').next().unwrap_or("bin").to_lowercase();
    let ext = sanitize_ext(&raw_ext);
    if ext.is_empty() { anyhow::bail!("Missing or invalid file extension"); }
    if BLOCKED_EXTENSIONS.contains(&ext.as_str()) { anyhow::bail!("File type not permitted"); }

    // #16: re-validate quota at finalize time (exclude this id's in-flight row,
    // which is already counted via progress_bytes) against the real on-disk size.
    {
        let lock = user_record_lock(username);
        let _guard = lock.lock().await;
        let records = load_records(data_dir, username).await;
        check_quota(&records, Some(&id), on_disk_len)?;
    }

    let filename = format!("{}.{}", Uuid::new_v4(), ext);
    std::fs::create_dir_all(upload_dir)?;
    let final_path = PathBuf::from(upload_dir).join(&filename);

    // #39: for formats we do not rewrite, move (rename) the assembled temp file
    // into the upload dir instead of read+strip+write (which held 2-3 full copies
    // in RAM). Falls back to copy when rename crosses filesystems.
    let size_final = if ext_needs_strip(&ext) {
        // Stripping needs the bytes in memory; the strippers now REJECT malformed
        // input (#88) and the A/V path REJECTS on ffmpeg failure (#30) rather
        // than silently storing un-stripped/partial data.
        let raw = tokio::fs::read(&data_path).await
            .map_err(|_| anyhow::anyhow!("No data uploaded"))?;
        if raw.is_empty() { anyhow::bail!("Empty file"); }
        let stripped = strip_metadata(&raw, &ext).await?;
        tokio::fs::write(&final_path, &stripped).await?;
        stripped.len()
    } else {
        match tokio::fs::rename(&data_path, &final_path).await {
            Ok(()) => {}
            Err(_) => { tokio::fs::copy(&data_path, &final_path).await?; }
        }
        on_disk_len
    };

    // Clean up the temp directory.
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let content_type = safe_content_type(&ext).to_string();
    let url = format!(
        "{}/files/{}",
        std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into()),
        filename
    );
    let now = chrono::Utc::now().timestamp();
    let rec = upsert_record(data_dir, username, &id,
        existing.clone(),
        |r| {
            r.status = UploadStatus::Done;
            r.filename = filename.clone();
            r.url = url.clone();
            r.content_type = content_type.clone();
            r.size = size_final;
            r.progress_bytes = size_final;
            r.completed_at = now;
            r.uploaded_at = now;
            r.error = String::new();
        },
    ).await;
    Ok(rec)
}

/// Cancel an in-flight upload: removes the temp dir and marks the record
/// as Canceled. (We keep the row briefly so other devices observe the
/// transition; callers may follow up with `remove_record`.)
pub async fn cancel_chunked_upload(
    data_dir: &str, username: &str, id: &str,
) -> Result<UploadRecord> {
    let id = safe_id(id);
    if let Some(dir) = inprogress_dir(data_dir, username, &id) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    let now = chrono::Utc::now().timestamp();
    let rec = upsert_record(data_dir, username, &id,
        UploadRecord {
            id: id.clone(), filename: String::new(), original_name: String::new(),
            size: 0, content_type: String::new(), url: String::new(),
            uploaded_at: 0, status: UploadStatus::Canceled,
            progress_bytes: 0, started_at: now, completed_at: now,
            error: String::new(),
            source_conn_id: String::new(), source_target: String::new(),
        },
        |r| {
            // Only transition from Uploading → Canceled. If already Done
            // or Error, leave it alone (caller should use remove_record).
            if r.status == UploadStatus::Uploading {
                r.status = UploadStatus::Canceled;
                r.completed_at = now;
            }
        },
    ).await;
    Ok(rec)
}

/// Mark an upload as Error (e.g. originating device hit a fatal client error).
pub async fn error_chunked_upload(
    data_dir: &str, username: &str, id: &str, message: &str,
) -> Result<UploadRecord> {
    let id = safe_id(id);
    if let Some(dir) = inprogress_dir(data_dir, username, &id) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    let now = chrono::Utc::now().timestamp();
    let msg: String = message.chars().take(300).collect();
    let rec = upsert_record(data_dir, username, &id,
        UploadRecord {
            id: id.clone(), filename: String::new(), original_name: String::new(),
            size: 0, content_type: String::new(), url: String::new(),
            uploaded_at: 0, status: UploadStatus::Error,
            progress_bytes: 0, started_at: now, completed_at: now,
            error: msg.clone(),
            source_conn_id: String::new(), source_target: String::new(),
        },
        |r| {
            if r.status == UploadStatus::Uploading {
                r.status = UploadStatus::Error;
                r.completed_at = now;
                r.error = msg.clone();
            }
        },
    ).await;
    Ok(rec)
}

/// Remove a record from the user's list. Also deletes:
///   - the temp dir if still in progress
///   - the final uploaded file if status==Done (matches existing
///     `delete_user_upload` semantics so "Remove" doubles as "delete file")
/// Returns true if a record was removed.
pub async fn remove_record(
    data_dir: &str, upload_dir: &str, username: &str, id: &str,
) -> bool {
    let id = safe_id(id);
    if let Some(dir) = inprogress_dir(data_dir, username, &id) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    // #21: serialize the records read-modify-write behind the per-user lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;
    let mut records = load_records(data_dir, username).await;
    let before = records.len();
    let mut to_unlink: Option<String> = None;
    records.retain(|r| {
        if r.id == id {
            if r.status == UploadStatus::Done && !r.filename.is_empty() {
                to_unlink = Some(r.filename.clone());
            }
            false
        } else { true }
    });
    if records.len() != before {
        save_records(data_dir, username, &records).await;
        if let Some(name) = to_unlink {
            // Reuse the same sanitize as delete_user_upload.
            let safe: String = name.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(128).collect();
            let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&safe)).await;
        }
        true
    } else { false }
}

/// All records for the user (in-flight + completed + errored + canceled).
/// Used to seed the client's Uploads channel on connect.
pub async fn list_all_records(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    load_records(data_dir, username).await
}

pub async fn list_user_uploads(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    // Historical "My Uploads" panel — finished uploads only. In-flight rows
    // belong to the live Uploads channel, not the archive.
    load_records(data_dir, username).await
        .into_iter()
        .filter(|r| r.status == UploadStatus::Done)
        .collect()
}

pub async fn delete_user_upload(data_dir: &str, upload_dir: &str, username: &str, filename: &str) {
    let safe: String = filename.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(128).collect();
    // #21: serialize the records read-modify-write behind the per-user lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;
    let path = user_uploads_path(data_dir, username);
    let mut records = load_user_records(&path).await;
    if records.iter().any(|r| r.filename == safe) {
        let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&safe)).await;
        records.retain(|r| r.filename != safe);
        write_records_atomic(&path, &records).await;
    }
}

pub async fn clear_user_uploads(data_dir: &str, upload_dir: &str, username: &str) {
    // #21: serialize the records read-modify-write behind the per-user lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;
    let path = user_uploads_path(data_dir, username);
    let records = load_user_records(&path).await;
    for r in &records {
        let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&r.filename)).await;
    }
    let tmp = path.with_extension("json.tmp");
    if tokio::fs::write(&tmp, "[]").await.is_ok() && tokio::fs::rename(&tmp, &path).await.is_err() {
        let _ = tokio::fs::write(&path, "[]").await;
        let _ = tokio::fs::remove_file(&tmp).await;
    }
}

async fn load_user_records(path: &PathBuf) -> Vec<UploadRecord> {
    match tokio::fs::read_to_string(path).await {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(_) => vec![],
    }
}

/// Returns true if the filename has an image extension (safe for inline display).
pub fn is_image(filename: &str) -> bool {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(ext.as_str(), "jpg" | "jpeg" | "png" | "gif" | "webp" | "avif" | "ico")
}

/// Strip metadata from uploads for privacy.
/// JPEG: removes all APP1-APP15 markers (EXIF, XMP, IPTC, GPS, camera info, etc.)
///       while preserving APP0 (JFIF), DQT, DHT, SOF, SOS and image data.
/// PNG:  removes all non-critical ancillary chunks (tEXt, iTXt, zTXt, eXIf, etc.)
///       while preserving IHDR, PLTE, IDAT, IEND, tRNS, gAMA, cHRM, sRGB, iCCP.
/// Video (mp4/webm): uses ffmpeg to strip all metadata while copying streams untouched.
///
/// #88/#30: this now returns Err on malformed images or ffmpeg failure instead
/// of silently storing un-stripped/partial bytes (which would leak EXIF/GPS or
/// corrupt the file). Formats that carry no metadata return their bytes as-is.
async fn strip_metadata(data: &[u8], ext: &str) -> Result<Vec<u8>> {
    match ext {
        "jpg" | "jpeg" => strip_jpeg_metadata(data),
        "png" => strip_png_metadata(data),
        "mp4" | "webm" | "mp3" | "ogg" | "wav" | "flac" =>
            strip_av_metadata(data, ext).await,
        _ => Ok(data.to_vec()),
    }
}

/// Strip metadata from audio/video files using ffmpeg.
/// Writes to a temp file, runs ffmpeg -map_metadata -1, reads back the result.
///
/// #30: bounded by a global concurrency semaphore + a wall-clock timeout +
/// a fixed `-threads` count, and REJECTS (returns Err) on ffmpeg failure,
/// timeout, or absence — rather than silently storing the un-stripped original.
async fn strip_av_metadata(data: &[u8], ext: &str) -> Result<Vec<u8>> {
    use tokio::process::Command;

    // Bound concurrent ffmpeg jobs so a burst cannot spawn unbounded CPU work.
    let _permit = av_strip_semaphore().acquire().await
        .map_err(|_| anyhow::anyhow!("Metadata stripper unavailable"))?;

    let tmp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let input_path = tmp_dir.join(format!("cryptirc_in_{}.{}", id, ext));
    let output_path = tmp_dir.join(format!("cryptirc_out_{}.{}", id, ext));

    // Helper to clean up temp files regardless of outcome.
    async fn cleanup(a: &std::path::Path, b: &std::path::Path) {
        let _ = tokio::fs::remove_file(a).await;
        let _ = tokio::fs::remove_file(b).await;
    }

    // Write input
    if tokio::fs::write(&input_path, data).await.is_err() {
        cleanup(&input_path, &output_path).await;
        anyhow::bail!("Failed to stage upload for metadata stripping");
    }

    let (in_str, out_str) = match (input_path.to_str(), output_path.to_str()) {
        (Some(i), Some(o)) => (i.to_string(), o.to_string()),
        _ => {
            cleanup(&input_path, &output_path).await;
            anyhow::bail!("Invalid temp path");
        }
    };

    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-nostdin",
        "-y",                   // overwrite output
        "-threads", "1",        // bound CPU per job
        "-i", &in_str,
        "-map_metadata", "-1",  // strip all metadata
        "-c", "copy",           // copy streams without re-encoding
        "-threads", "1",
        &out_str,
    ])
    .kill_on_drop(true)
    .stdin(std::process::Stdio::null())
    .stdout(std::process::Stdio::null())
    .stderr(std::process::Stdio::null());

    // Run under a wall-clock timeout so a crafted container cannot hang ffmpeg.
    let status = match tokio::time::timeout(AV_STRIP_TIMEOUT, cmd.status()).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            // ffmpeg missing / failed to spawn.
            cleanup(&input_path, &output_path).await;
            anyhow::bail!("Could not strip media metadata (ffmpeg unavailable)");
        }
        Err(_) => {
            // Timed out (child is killed on drop).
            cleanup(&input_path, &output_path).await;
            anyhow::bail!("Media metadata stripping timed out");
        }
    };

    if !status.success() {
        cleanup(&input_path, &output_path).await;
        anyhow::bail!("Could not strip media metadata");
    }

    let stripped = tokio::fs::read(&output_path).await;
    cleanup(&input_path, &output_path).await;

    match stripped {
        Ok(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => anyhow::bail!("Metadata stripping produced no output"),
    }
}

/// #88: on any malformed/truncated structure this now returns Err so the upload
/// is rejected rather than stored with EXIF/GPS intact or truncated.
fn strip_jpeg_metadata(data: &[u8]) -> Result<Vec<u8>> {
    // JPEG structure: FF D8 (SOI) followed by segments: FF xx [length_hi length_lo] [data...]
    // We keep: APP0 (FFE0/JFIF), DQT (FFDB), DHT (FFC4), SOF0-SOF15 (FFC0-FFCF except FFC4/FFC8),
    //          DRI (FFDD), SOS (FFDA) + image data, COM removal optional
    // We strip: APP1-APP15 (FFE1-FFEF = EXIF, XMP, IPTC, ICC, etc.)
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        anyhow::bail!("Corrupt image (not a valid JPEG)");
    }

    let mut out = Vec::with_capacity(data.len());
    out.push(0xFF);
    out.push(0xD8); // SOI

    let mut i = 2;
    let mut saw_sos = false;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            // Marker bytes must align; anything else means a malformed header.
            anyhow::bail!("Corrupt image (malformed JPEG segment)");
        }

        let marker = data[i + 1];

        // SOS (Start of Scan) — everything after this is image data, copy the rest
        if marker == 0xDA {
            out.extend_from_slice(&data[i..]);
            saw_sos = true;
            break;
        }

        // EOI
        if marker == 0xD9 {
            out.push(0xFF);
            out.push(0xD9);
            break;
        }

        // Standalone markers (no length field): RST0-RST7, SOI, TEM
        if (0xD0..=0xD7).contains(&marker) || marker == 0xD8 || marker == 0x01 {
            out.push(0xFF);
            out.push(marker);
            i += 2;
            continue;
        }

        // All other markers have a 2-byte length
        if i + 3 >= data.len() {
            anyhow::bail!("Corrupt image (truncated JPEG segment)");
        }
        let seg_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
        if seg_len < 2 || i + 2 + seg_len > data.len() {
            anyhow::bail!("Corrupt image (invalid JPEG segment length)");
        }

        let is_app_metadata = (0xE1..=0xEF).contains(&marker); // APP1-APP15
        let is_comment = marker == 0xFE; // COM marker

        if is_app_metadata || is_comment {
            // Skip this segment (strip it)
            i += 2 + seg_len;
        } else {
            // Keep this segment
            out.extend_from_slice(&data[i..i + 2 + seg_len]);
            i += 2 + seg_len;
        }
    }

    if !saw_sos {
        // No scan data means the JPEG was truncated before its image content.
        anyhow::bail!("Corrupt image (incomplete JPEG)");
    }
    Ok(out)
}

/// #88: rejects malformed/truncated PNGs instead of storing original/partial bytes.
fn strip_png_metadata(data: &[u8]) -> Result<Vec<u8>> {
    // PNG structure: 8-byte signature, then chunks: [4-byte length][4-byte type][data][4-byte CRC]
    // Critical chunks to keep: IHDR, PLTE, IDAT, IEND
    // Safe ancillary to keep: tRNS, gAMA, cHRM, sRGB, iCCP, sBIT, pHYs
    // Strip everything else: tEXt, iTXt, zTXt, eXIf, dSIG, tIME, etc.
    const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    if data.len() < 8 || data[..8] != PNG_SIG {
        anyhow::bail!("Corrupt image (not a valid PNG)");
    }

    let keep_chunks: &[&[u8]] = &[
        b"IHDR", b"PLTE", b"IDAT", b"IEND",
        b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs",
    ];

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&PNG_SIG);

    let mut i = 8;
    let mut saw_iend = false;
    while i + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let chunk_type = &data[i + 4..i + 8];
        let total = match chunk_len.checked_add(12) { // 4 (len) + 4 (type) + data + 4 (CRC)
            Some(t) => t,
            None => anyhow::bail!("Corrupt image (PNG chunk length overflow)"),
        };

        if i + total > data.len() {
            anyhow::bail!("Corrupt image (truncated PNG chunk)");
        }

        if keep_chunks.iter().any(|k| *k == chunk_type) {
            out.extend_from_slice(&data[i..i + total]);
        }

        // IEND is always last
        if chunk_type == b"IEND" {
            saw_iend = true;
            break;
        }

        i += total;
    }

    if !saw_iend {
        anyhow::bail!("Corrupt image (incomplete PNG)");
    }
    Ok(out)
}
