/// upload.rs — Multipart file upload handler
///
/// Fixes applied:
///   C8  — size enforced via axum DefaultBodyLimit (set in main.rs), plus stream guard
///   H4  — SVG served as application/octet-stream to prevent JS execution
///   M2  — blocklist of dangerous extensions
///   M6  — require non-empty extension after sanitize

use anyhow::Result;
use axum::extract::Multipart;
use serde::Serialize;
use std::path::PathBuf;
use uuid::Uuid;

/// Default max upload size — overridden at runtime by admin setting.
const DEFAULT_MAX_UPLOAD_BYTES: usize = 25 * 1024 * 1024;

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

        // Strip image metadata (EXIF, GPS, camera info, etc.) for privacy
        let data = strip_metadata(&data, &ext).await;

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
    let path = user_uploads_path(data_dir, username);
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let mut records = load_user_records(&path).await;
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
    let _ = tokio::fs::write(&path, serde_json::to_string(&records).unwrap_or_default()).await;
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

/// Read/write the per-user persistent record list. Single-writer; callers
/// must serialize their own mutations. We keep this private to nudge callers
/// toward [`update_record`] which atomically applies a mutation.
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
    let _ = tokio::fs::write(&path, serde_json::to_string(records).unwrap_or_default()).await;
}

/// Find-or-insert by id; apply mutation; persist. Returns the new record.
async fn upsert_record<F: FnOnce(&mut UploadRecord)>(
    data_dir: &str, username: &str, id: &str,
    blank: UploadRecord, mutate: F,
) -> UploadRecord {
    let mut records = load_records(data_dir, username).await;
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
    record
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
    let rec = upsert_record(data_dir, username, &id, blank, |r| {
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
    }).await;
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
    let mut file = tokio::fs::OpenOptions::new()
        .create(true).append(true).open(&data_path).await?;
    file.write_all(chunk).await?;
    file.flush().await?;
    let new_total = current + chunk.len();
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
    let raw = tokio::fs::read(&data_path).await
        .map_err(|_| anyhow::anyhow!("No data uploaded"))?;
    if raw.is_empty() { anyhow::bail!("Empty file"); }

    let existing = get_record(data_dir, username, &id).await
        .ok_or_else(|| anyhow::anyhow!("Unknown upload id"))?;
    let original_name = existing.original_name.clone();
    if existing.size > 0 && raw.len() != existing.size {
        anyhow::bail!("Size mismatch (declared {} got {})", existing.size, raw.len());
    }

    let raw_ext = original_name.rsplit('.').next().unwrap_or("bin").to_lowercase();
    let ext = sanitize_ext(&raw_ext);
    if ext.is_empty() { anyhow::bail!("Missing or invalid file extension"); }
    if BLOCKED_EXTENSIONS.contains(&ext.as_str()) { anyhow::bail!("File type not permitted"); }

    let stripped = strip_metadata(&raw, &ext).await;

    let filename = format!("{}.{}", Uuid::new_v4(), ext);
    std::fs::create_dir_all(upload_dir)?;
    let final_path = PathBuf::from(upload_dir).join(&filename);
    tokio::fs::write(&final_path, &stripped).await?;

    // Clean up the temp directory.
    let _ = tokio::fs::remove_dir_all(&dir).await;

    let content_type = safe_content_type(&ext).to_string();
    let url = format!(
        "{}/files/{}",
        std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into()),
        filename
    );
    let now = chrono::Utc::now().timestamp();
    let size_final = stripped.len();
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
    let path = user_uploads_path(data_dir, username);
    let mut records = load_user_records(&path).await;
    if records.iter().any(|r| r.filename == safe) {
        let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&safe)).await;
        records.retain(|r| r.filename != safe);
        let _ = tokio::fs::write(&path, serde_json::to_string(&records).unwrap_or_default()).await;
    }
}

pub async fn clear_user_uploads(data_dir: &str, upload_dir: &str, username: &str) {
    let path = user_uploads_path(data_dir, username);
    let records = load_user_records(&path).await;
    for r in &records {
        let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&r.filename)).await;
    }
    let _ = tokio::fs::write(&path, "[]").await;
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
async fn strip_metadata(data: &[u8], ext: &str) -> Vec<u8> {
    match ext {
        "jpg" | "jpeg" => strip_jpeg_metadata(data),
        "png" => strip_png_metadata(data),
        "mp4" | "webm" | "mp3" | "ogg" | "wav" | "flac" =>
            strip_av_metadata(data, ext).await.unwrap_or_else(|| data.to_vec()),
        _ => data.to_vec(),
    }
}

/// Strip metadata from audio/video files using ffmpeg.
/// Writes to a temp file, runs ffmpeg -map_metadata -1, reads back the result.
/// Returns None on any failure (caller falls back to original data).
async fn strip_av_metadata(data: &[u8], ext: &str) -> Option<Vec<u8>> {
    use tokio::process::Command;

    let tmp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let input_path = tmp_dir.join(format!("cryptirc_in_{}.{}", id, ext));
    let output_path = tmp_dir.join(format!("cryptirc_out_{}.{}", id, ext));

    // Write input
    tokio::fs::write(&input_path, data).await.ok()?;

    let result = Command::new("ffmpeg")
        .args([
            "-y",                   // overwrite output
            "-i", input_path.to_str()?,
            "-map_metadata", "-1",  // strip all metadata
            "-c", "copy",           // copy streams without re-encoding
            output_path.to_str()?,
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    // Read output
    let stripped = if result.map(|s| s.success()).unwrap_or(false) {
        tokio::fs::read(&output_path).await.ok()
    } else {
        None
    };

    // Clean up temp files
    let _ = tokio::fs::remove_file(&input_path).await;
    let _ = tokio::fs::remove_file(&output_path).await;

    stripped
}

fn strip_jpeg_metadata(data: &[u8]) -> Vec<u8> {
    // JPEG structure: FF D8 (SOI) followed by segments: FF xx [length_hi length_lo] [data...]
    // We keep: APP0 (FFE0/JFIF), DQT (FFDB), DHT (FFC4), SOF0-SOF15 (FFC0-FFCF except FFC4/FFC8),
    //          DRI (FFDD), SOS (FFDA) + image data, COM removal optional
    // We strip: APP1-APP15 (FFE1-FFEF = EXIF, XMP, IPTC, ICC, etc.)
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        return data.to_vec(); // Not JPEG, return as-is
    }

    let mut out = Vec::with_capacity(data.len());
    out.push(0xFF);
    out.push(0xD8); // SOI

    let mut i = 2;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            // Shouldn't happen in well-formed JPEG header area, skip byte
            i += 1;
            continue;
        }

        let marker = data[i + 1];

        // SOS (Start of Scan) — everything after this is image data, copy the rest
        if marker == 0xDA {
            out.extend_from_slice(&data[i..]);
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
            break;
        }
        let seg_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
        if seg_len < 2 || i + 2 + seg_len > data.len() {
            break; // Malformed, just return rest as-is
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

    out
}

fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    // PNG structure: 8-byte signature, then chunks: [4-byte length][4-byte type][data][4-byte CRC]
    // Critical chunks to keep: IHDR, PLTE, IDAT, IEND
    // Safe ancillary to keep: tRNS, gAMA, cHRM, sRGB, iCCP, sBIT, pHYs
    // Strip everything else: tEXt, iTXt, zTXt, eXIf, dSIG, tIME, etc.
    const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    if data.len() < 8 || data[..8] != PNG_SIG {
        return data.to_vec(); // Not PNG
    }

    let keep_chunks: &[&[u8]] = &[
        b"IHDR", b"PLTE", b"IDAT", b"IEND",
        b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs",
    ];

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&PNG_SIG);

    let mut i = 8;
    while i + 12 <= data.len() {
        let chunk_len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let chunk_type = &data[i + 4..i + 8];
        let total = 12 + chunk_len; // 4 (len) + 4 (type) + data + 4 (CRC)

        if i + total > data.len() {
            break; // Malformed
        }

        if keep_chunks.iter().any(|k| *k == chunk_type) {
            out.extend_from_slice(&data[i..i + total]);
        }

        // IEND is always last
        if chunk_type == b"IEND" {
            break;
        }

        i += total;
    }

    out
}
