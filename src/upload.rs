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
///   #99 — metadata stripping extended to every image/video format the app
///         accepts, not just JPEG/PNG/MP4/WEBM. JPEG/PNG keep the existing
///         in-process byte-level strippers (no external dependency, already
///         battle-tested). GIF/WEBP/AVIF/HEIC/HEIF/TIFF now route through
///         `exiftool` (the one tool on this box with genuine HEIC/HEIF write
///         support — ffmpeg has none, and ImageMagick would fully decode+
///         re-encode, which is lossy for these formats), via copy-then-
///         `-overwrite_original` (exiftool's `-o` direct-write mode rejects
///         WEBP/RIFF outright even though in-place edit works fine on it).
///         MOV/AVI/MKV/M4V/3GP/3G2/FLV/WMV now route through the EXISTING
///         ffmpeg `-c copy` path (same mechanism already trusted for MP4/
///         WEBM, just a wider extension allowlist) — verified empirically
///         for every new format (frame-count-exact, metadata confirmed
///         removed) before shipping.
///         ICO and BMP are deliberately NOT included: exiftool cannot WRITE
///         either format at all ("Writing of ICO/BMP files is not yet
///         supported" — confirmed empirically, not assumed), and neither
///         format has a realistic EXIF/GPS/personal-metadata exposure to
///         justify inventing a bespoke stripper for them (ICO is a Windows
///         icon container; BMP is a raw pixel dump with no standard
///         metadata segment for a camera/phone to have populated). Both are
///         still accepted as valid uploads with a correct content-type —
///         they're just not run through a stripping step, same as today.
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

/// Demuxers ffmpeg may use for an uploaded A/V file (`-format_whitelist`). Covers
/// every A/V extension in `ext_needs_strip` (mp4/mov/m4v/3gp/3g2 → mov family,
/// webm/mkv → matroska, avi, flv, wmv → asf, mp3, ogg, wav, flac) plus the few
/// self-contained containers a mislabelled phone/screen-recorder file can really
/// be (MPEG-TS/PS, raw AAC), so nothing that stripped before is newly rejected.
/// Deliberately excludes the demuxers that open OTHER files/URLs (hls, concat,
/// image2, dash, …).
const AV_DEMUXER_WHITELIST: &str =
    "mov,mp4,m4a,3gp,3g2,mj2,matroska,webm,avi,flv,live_flv,asf,mp3,ogg,wav,w64,flac,mpegts,mpeg,aac";

/// #26: global disk-space floor. On top of the per-user quota (which alone lets
/// K accounts each fill PER_USER_MAX_TOTAL_BYTES of in-progress chunks and
/// exhaust the shared data volume, failing log/DB writes server-wide), refuse
/// new chunk writes once the data volume's free space would drop below this
/// reserve. Only enforced when free space can actually be queried (see
/// `available_disk_bytes`); a query failure fails OPEN so uploads are never
/// blocked on a filesystem whose free space we cannot read.
pub(crate) const MIN_FREE_DISK_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB

/// Best-effort bytes available to an unprivileged writer on the filesystem
/// holding `path`. Returns None if the figure cannot be determined (fail open).
#[cfg(unix)]
pub(crate) fn available_disk_bytes(path: &std::path::Path) -> Option<u64> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `c_path` is a valid NUL-terminated C string and `stat` is a
    // properly sized, zero-initialized statvfs buffer that statvfs fills in.
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) };
    if rc != 0 { return None; }
    // f_bavail: blocks free to a non-privileged process; f_frsize: block size.
    Some((stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64))
}

#[cfg(not(unix))]
pub(crate) fn available_disk_bytes(_path: &std::path::Path) -> Option<u64> { None }

/// Global semaphore bounding concurrent ffmpeg invocations so a burst of A/V
/// uploads cannot spawn unbounded CPU-heavy processes.
fn av_strip_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(AV_STRIP_MAX_CONCURRENT))
}

/// #32: bound concurrent in-RAM image metadata strips. Each strip holds the source
/// image plus its stripped copy in RAM (up to ~2x the admin max_upload_mb), so a
/// burst of concurrent finalize/legacy-upload requests could otherwise amplify peak
/// RSS without bound. The per-user upload rate limit caps a single user; this caps
/// the cross-user total. Fires only under contention — normal uploads never wait.
const IMG_STRIP_MAX_CONCURRENT: usize = 4;
fn img_strip_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(IMG_STRIP_MAX_CONCURRENT))
}

/// #99: global cap on concurrent `exiftool` metadata-strip jobs (GIF/WEBP/AVIF/
/// HEIC/HEIF/TIFF — NOT BMP, see the module doc comment for why). Same
/// rationale as `av_strip_semaphore` — bounds CPU/process count under a
/// burst rather than letting it grow unbounded.
const EXIFTOOL_STRIP_MAX_CONCURRENT: usize = 4;
/// Wall-clock timeout for a single exiftool job. Shorter than the A/V timeout —
/// exiftool edits metadata segments directly rather than transcoding, so even a
/// large TIFF/HEIC finishes in well under this on any real upload.
const EXIFTOOL_STRIP_TIMEOUT: Duration = Duration::from_secs(30);
fn exiftool_strip_semaphore() -> &'static Semaphore {
    static SEM: OnceLock<Semaphore> = OnceLock::new();
    SEM.get_or_init(|| Semaphore::new(EXIFTOOL_STRIP_MAX_CONCURRENT))
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

/// #F19: drop idle per-user record locks so this static map can't grow without
/// bound. Previously every username that ever uploaded left a permanent entry
/// (never freed on account deletion). An entry whose Arc has strong_count==1 is
/// held only by the map — every caller of `user_record_lock` keeps a clone for
/// the duration of its critical section (count>=2) — so removing it can neither
/// race a live read-modify-write nor hand two callers different Mutexes for the
/// same user: DashMap's per-shard lock serializes this check against the
/// `entry().or_insert().clone()` in `user_record_lock` (the clone happens while
/// that shard lock is held), so a count==1 entry provably has no live holder or
/// waiter. Mirrors main.rs `prune_network_config_locks`; invoked from the hourly
/// (and startup) in-progress sweep so no wiring outside this file is needed.
fn prune_record_locks() {
    record_locks().retain(|_, v| Arc::strong_count(v) > 1);
}

/// Set of extensions that REQUIRE metadata stripping (image EXIF/GPS or A/V
/// container metadata). When this returns true, finalize must read + strip +
/// rewrite the file; when false, strip_metadata is a no-op and finalize can
/// simply move (rename) the temp file instead of re-buffering it (#39).
fn ext_needs_strip(ext: &str) -> bool {
    matches!(
        ext,
        "jpg" | "jpeg" | "png"
        | "gif" | "webp" | "avif" | "heic" | "heif" | "tiff" | "tif"
        | "mp4" | "webm" | "mov" | "avi" | "mkv" | "m4v" | "3gp" | "3g2" | "flv" | "wmv"
        | "mp3" | "ogg" | "wav" | "flac"
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

/// r9 (astra P1 main.rs:3380): the legacy multipart /upload reserves its share of the upload
/// budget BEFORE the body arrives, and its reads had no deadline, so a request whose body
/// stalled (or trickled a byte now and then) held that reservation for as long as the client
/// kept the connection open — two of them could block every other legacy upload. The body
/// must now keep moving: no read waits longer than LEGACY_BODY_IDLE, and after
/// LEGACY_BODY_GRACE the request must average LEGACY_BODY_MIN_RATE, else it fails and its
/// reservation is released. (The app itself uploads through /upload/init + chunks, which
/// have their own deadlines.)
const LEGACY_BODY_IDLE: Duration = if cfg!(test) { Duration::from_millis(300) } else { Duration::from_secs(30) };
const LEGACY_BODY_GRACE: Duration = if cfg!(test) { Duration::from_millis(600) } else { Duration::from_secs(60) };
const LEGACY_BODY_MIN_RATE: u64 = 64 * 1024;   // bytes per second, on average
const LEGACY_BODY_STALLED: &str = "Upload cancelled: the file arrived too slowly";

/// How long the next body read may wait, given when the request started and how much of
/// it has arrived.
fn legacy_body_wait(started: tokio::time::Instant, received: u64) -> Duration {
    let earned = LEGACY_BODY_GRACE + Duration::from_millis(received.saturating_mul(1000) / LEGACY_BODY_MIN_RATE);
    earned.saturating_sub(started.elapsed()).min(LEGACY_BODY_IDLE)
}

async fn legacy_body_read<T, E: Into<anyhow::Error>>(read: impl std::future::Future<Output = std::result::Result<T, E>>,
                                                     wait: Duration) -> Result<T> {
    match tokio::time::timeout(wait, read).await {
        Ok(r) => r.map_err(Into::into),
        Err(_) => anyhow::bail!(LEGACY_BODY_STALLED),
    }
}

pub async fn handle_upload(upload_dir: &str, mut multipart: Multipart, max_bytes: usize) -> Result<UploadResult> {
    let limit = if max_bytes > 0 { max_bytes } else { DEFAULT_MAX_UPLOAD_BYTES };
    let (started, mut received) = (tokio::time::Instant::now(), 0u64);
    while let Some(mut field) = legacy_body_read(multipart.next_field(), legacy_body_wait(started, received)).await? {
        let original_name = field.file_name().unwrap_or("upload").to_string();
        // Clamp original_name length
        let original_name: String = original_name.chars().take(255).collect();

        // #16: accumulate the field in bounded chunks with a running byte counter
        // and abort the MOMENT the configured limit is exceeded, instead of
        // buffering the entire (potentially attacker-controlled) field into RAM
        // via `field.bytes()` and only checking the size afterward. This caps
        // peak RAM for this path at `limit` (+ one in-flight chunk).
        let mut data: Vec<u8> = Vec::new();
        while let Some(chunk) = legacy_body_read(field.chunk(), legacy_body_wait(started, received)).await? {
            received += chunk.len() as u64;
            if data.len() + chunk.len() > limit {
                let limit_mb = limit / (1024 * 1024);
                anyhow::bail!("File too large (max {} MB)", limit_mb);
            }
            data.extend_from_slice(&chunk);
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
            // Hand back the PUBLIC /pub/ URL so a copied/shared link works outside the app
            // (the /files/ route is auth-gated → 401 externally). All uploads are shareable
            // by their unguessable UUID; see serve_file_public for the XSS-safe serving.
            // trim_end_matches('/') so a root install (CRYPTIRC_BASE_PATH="/") yields
            // "/pub/…" and not "//pub/…" — a leading "//" breaks the router.
            url: format!("{}/pub/{}", std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into()).trim_end_matches('/'), filename),
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
        "heic"         => "image/heic",
        "heif"         => "image/heif",
        "bmp"          => "image/bmp",
        "tiff" | "tif" => "image/tiff",
        "ico"          => "image/x-icon",
        "mp4"          => "video/mp4",
        "webm"         => "video/webm",
        "mov"          => "video/quicktime",
        "avi"          => "video/x-msvideo",
        "mkv"          => "video/x-matroska",
        "m4v"          => "video/x-m4v",
        "3gp"          => "video/3gpp",
        "3g2"          => "video/3gpp2",
        "flv"          => "video/x-flv",
        "wmv"          => "video/x-ms-wmv",
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

// ─── Upload index location (2026-11-01 H1) ───────────────────────────────────
//
// The per-user upload index (every upload's UUID filename, original name and the
// channel/nick it was sent to) used to live at `{data}/uploads/{username}.json` —
// INSIDE the directory the unauthenticated /pub route serves, at a guessable name,
// so `/pub/<username>.json` handed anyone the user's whole upload history. It now
// lives in `{data}/upload_index/{username}.json` (0700 dir, 0600 files), which no
// route serves. `migrate_upload_index` moves existing files at startup, and
// `is_reserved_upload_name` makes the file routes refuse index-shaped names even
// if one reappears in the served dir (e.g. written by a rolled-back old binary).

/// Directory holding the per-user upload index files. Never served.
pub fn upload_index_dir(data_dir: &str) -> PathBuf {
    PathBuf::from(data_dir).join("upload_index")
}

fn user_uploads_path(data_dir: &str, username: &str) -> PathBuf {
    upload_index_dir(data_dir).join(format!("{}.json", username))
}

/// Pre-2026-11-01 index location, inside the served uploads dir. Only read as a
/// fallback when the startup migration could not move a file (see
/// `load_user_records_for`), and removed by `clear_user_uploads`.
fn legacy_user_uploads_path(data_dir: &str, username: &str) -> PathBuf {
    PathBuf::from(data_dir).join("uploads").join(format!("{}.json", username))
}

/// True for a canonical lowercase-or-uppercase hyphenated UUID (8-4-4-4-12 hex).
fn is_uuid_shaped(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// The username part of an index-file name (`<username>.json`), or None when the
/// name is not index-shaped. Server-generated upload blobs (and the admin's
/// hand-dropped `<uuid>.<ext>` files) always have a UUID stem, which is never a
/// valid username (36 chars > the 32-char username cap), so they are never
/// mistaken for an index — not even an uploaded `<uuid>.json`.
fn index_stem(name: &str) -> Option<&str> {
    let stem = name.strip_suffix(".json")?;
    if stem.is_empty() || stem.len() > 64 || is_uuid_shaped(stem) { return None; }
    if !stem.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') { return None; }
    Some(stem)
}

/// Names in the uploads dir that the /pub and /files routes must never serve:
/// per-user index files (`<username>.json`), their atomic-write temps
/// (`<username>.json.tmp`), any other `*.tmp`, and `_`-prefixed internal entries
/// (`_inprogress`). Everything a user or the admin actually shares is
/// `<uuid>.<ext>`, which this never matches.
pub fn is_reserved_upload_name(name: &str) -> bool {
    if name.starts_with('_') || name.starts_with('.') { return true; }
    let lower = name.to_ascii_lowercase();
    if let Some(base) = lower.strip_suffix(".tmp") {
        // A temp file is only ever a stale partial write; a UUID-stemmed upload
        // can't end in .tmp unless a user uploaded "x.tmp" (allowed type), so
        // keep those servable.
        return base.split('.').next().map_or(true, |s| !is_uuid_shaped(s));
    }
    index_stem(&lower).is_some()
}

// The server is unix-only (main.rs create_dir_secure uses std::os::unix directly).
fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode));
}

/// Create `dir` 0700 (and re-tighten it if it pre-existed looser).
fn create_private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    set_mode(dir, 0o700);
    Ok(())
}

fn ensure_index_dir(data_dir: &str) -> std::io::Result<PathBuf> {
    let dir = upload_index_dir(data_dir);
    create_private_dir(&dir)?;
    Ok(dir)
}

/// Write `bytes` to `path` crash-safely: 0600 temp file in the same dir, fsync,
/// rename over the target. Sync — used by the startup migration.
fn write_file_atomic_sync(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    set_mode(&tmp, 0o600);
    std::fs::rename(&tmp, path)
}

/// One-time, idempotent, crash-safe move of the per-user upload index files out
/// of the served uploads dir into `{data}/upload_index/` (2026-11-01 H1). Called
/// once at startup, before the HTTP listener starts. Safe to run on every boot:
///   * only `old` exists        → atomic rename (same filesystem), else copy+fsync+
///                                rename, then delete the old file.
///   * only `new` exists        → nothing to do (already migrated).
///   * both exist               → a half-finished copy, or an OLD binary wrote a
///                                fresh index after a rollback. Merge: keep every
///                                record in `new`, add records only present in
///                                `old` (skipping Done rows whose blob is gone, so a
///                                deletion made after migration is not undone), keep
///                                a backup of `old` in upload_index/legacy-backup/,
///                                then delete `old`. Re-running after a crash at
///                                any step converges to the same result.
///   * stale `<user>.json.tmp`  → deleted (an interrupted old-style atomic write;
///                                the old code never read it either).
/// New files are 0600 in a 0700 dir. When run as root (manual invocation) the new
/// dir/files are chowned to the data dir's owner so the service can still write.
/// Returns (moved, merged, temps_removed).
pub fn migrate_upload_index(data_dir: &str) -> (usize, usize, usize) {
    let legacy_dir = PathBuf::from(data_dir).join("uploads");
    let new_dir = match ensure_index_dir(data_dir) {
        Ok(d) => d,
        Err(e) => {
            tracing::error!("[upload] cannot create upload index dir: {} — index files stay in uploads/ (still never served)", e);
            return (0, 0, 0);
        }
    };
    let (mut moved, mut merged, mut temps) = (0usize, 0usize, 0usize);
    if let Ok(rd) = std::fs::read_dir(&legacy_dir) {
        for ent in rd.flatten() {
            let name = match ent.file_name().into_string() { Ok(n) => n, Err(_) => continue };
            // Regular files only — never follow a symlink or touch _inprogress/.
            let is_file = std::fs::symlink_metadata(ent.path()).map(|m| m.file_type().is_file()).unwrap_or(false);
            if !is_file { continue; }
            if let Some(stem) = name.strip_suffix(".json.tmp") {
                if index_stem(&format!("{}.json", stem)).is_some() {
                    if std::fs::remove_file(ent.path()).is_ok() { temps += 1; }
                }
                continue;
            }
            if index_stem(&name).is_none() { continue; }
            let old = ent.path();
            let new = new_dir.join(&name);
            if !new.exists() {
                let ok = match std::fs::rename(&old, &new) {
                    Ok(()) => true,
                    // Cross-filesystem (EXDEV) or similar: copy crash-safely, then
                    // delete the old one. A crash between the two leaves both,
                    // identical — the merge branch below then just deletes `old`.
                    Err(_) => match std::fs::read(&old) {
                        Ok(bytes) => write_file_atomic_sync(&new, &bytes).is_ok() && std::fs::remove_file(&old).is_ok(),
                        Err(_) => false,
                    },
                };
                if ok { moved += 1; } else {
                    tracing::error!("[upload] could not migrate upload index {} — left in place (never served; read as a fallback)", name);
                }
                continue;
            }
            match merge_legacy_index(&old, &new, &new_dir, &legacy_dir, &name) {
                Ok(()) => merged += 1,
                Err(e) => tracing::error!("[upload] could not merge legacy upload index {}: {} — left in place (never served)", name, e),
            }
        }
    }
    harden_index_dir(data_dir, &new_dir);
    if moved + merged + temps > 0 {
        tracing::info!("[upload] upload index migration: {} moved, {} merged, {} stale temp(s) removed", moved, merged, temps);
    }
    (moved, merged, temps)
}

/// Both `old` (legacy, in uploads/) and `new` exist: back `old` up (and `new`
/// too if it is unreadable), merge old-only records into `new`, delete `old`.
/// Every step is idempotent, so a crash anywhere just repeats it next boot.
/// See `migrate_upload_index`.
fn merge_legacy_index(
    old: &std::path::Path, new: &std::path::Path, new_dir: &std::path::Path,
    legacy_dir: &std::path::Path, name: &str,
) -> std::io::Result<()> {
    let old_bytes = std::fs::read(old)?;
    let new_bytes = std::fs::read(new).unwrap_or_default();
    let new_parsed: Option<Vec<UploadRecord>> = serde_json::from_slice(&new_bytes).ok();
    let new_corrupt = new_parsed.is_none() && !new_bytes.is_empty();
    let new_recs = new_parsed.unwrap_or_default();
    let old_recs: Vec<UploadRecord> = serde_json::from_slice(&old_bytes).unwrap_or_default();

    // 1. Backups first (outside the served dir), so no later step can lose data.
    let backup_dir = new_dir.join("legacy-backup");
    create_private_dir(&backup_dir)?;
    let stamp = chrono::Utc::now().timestamp();
    write_file_atomic_sync(&backup_dir.join(format!("{}.{}", name, stamp)), &old_bytes)?;
    if new_corrupt {
        write_file_atomic_sync(&backup_dir.join(format!("{}.{}.unreadable", name, stamp)), &new_bytes)?;
    }

    // 2. Union: everything in `new` (authoritative on id conflicts) plus rows only
    //    in `old`. A Done row only in `old` whose blob is gone was deleted after the
    //    migration — don't resurrect it.
    let key = |r: &UploadRecord| if r.id.is_empty() { r.filename.clone() } else { r.id.clone() };
    let have: std::collections::HashSet<String> = new_recs.iter().map(key).collect();
    let mut out = new_recs.clone();
    for r in old_recs {
        if have.contains(&key(&r)) { continue; }
        if r.status == UploadStatus::Done {
            let safe: String = r.filename.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(128).collect();
            if safe.is_empty() || !legacy_dir.join(&safe).is_file() { continue; }
        }
        out.push(r);
    }
    if out.len() != new_recs.len() || new_corrupt {
        let json = serde_json::to_vec(&out).map_err(std::io::Error::other)?;
        write_file_atomic_sync(new, &json)?;
    }

    // 3. Only now remove the served copy.
    std::fs::remove_file(old)
}

/// 0700 on the index dir tree, 0600 on its files; chown to the data dir's owner
/// when running as root (so a manual root run can't leave the service unable to
/// write). Best-effort, never follows symlinks.
fn harden_index_dir(data_dir: &str, dir: &std::path::Path) {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owner = if unsafe { libc::geteuid() } == 0 {
        std::fs::metadata(data_dir).ok().map(|m| (m.uid(), m.gid()))
    } else { None };
    fn walk(p: &std::path::Path, depth: u32, owner: Option<(u32, u32)>) {
        if depth > 2 { return; }
        let meta = match std::fs::symlink_metadata(p) { Ok(m) => m, Err(_) => return };
        if meta.file_type().is_symlink() { return; }
        if let Some((u, g)) = owner { let _ = std::os::unix::fs::chown(p, Some(u), Some(g)); }
        if meta.is_dir() {
            set_mode(p, 0o700);
            if let Ok(rd) = std::fs::read_dir(p) { for e in rd.flatten() { walk(&e.path(), depth + 1, owner); } }
        } else if meta.is_file() {
            set_mode(p, 0o600);
        }
    }
    walk(dir, 0, owner);
}

pub async fn record_upload(data_dir: &str, username: &str, result: &UploadResult) -> Result<()> {
    // #21: serialize the read-modify-write behind the per-user records lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;

    let path = user_uploads_path(data_dir, username);
    let mut records = load_user_records_for(data_dir, username).await;
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
    // codex P1 upload.rs:821: a failed index write is an error (the route then removes the
    // just-stored file and reports the failure) instead of a success nothing remembers.
    write_records_atomic(&path, &records).await
        .map_err(|e| anyhow::anyhow!("Could not save the upload list: {}", e))?;
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

/// #96: sanitize a client-supplied upload id, REJECTING (rather than silently
/// collapsing) any id that contains disallowed characters or is over-length.
/// Without this, two distinct client ids that differ only in stripped chars
/// (e.g. `a/b` and `ab`, or `x` and `x\0`) would map to the same on-disk path
/// and the same record key, letting one upload clobber another's data. We
/// require the sanitized form to be byte-identical to the input so each
/// accepted id deterministically owns exactly one path.
fn checked_id(id: &str) -> Result<String> {
    let safe = safe_id(id);
    if safe.is_empty() {
        anyhow::bail!("Invalid upload id");
    }
    if safe != id {
        anyhow::bail!("Invalid upload id (illegal characters)");
    }
    Ok(safe)
}

/// A filename-shaped record id as written by record_upload / the pre-chunked era
/// ("<name>.<ext>": the stored filename's own charset, one or more dots, no path parts).
/// Only used to MATCH an existing record id exactly (remove_record) — never to build a path.
fn is_legacy_file_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.contains('.') && !id.starts_with('.') && !id.contains("..")
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
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

/// Per-user root of the in-progress chunked-upload tree
/// ({data_dir}/uploads/_inprogress/{username}), holding every in-flight upload's
/// dir for this user. Used by account deletion to reclaim abandoned chunk data.
/// Returns None if the username sanitizes to empty.
pub fn user_inprogress_dir(data_dir: &str, username: &str) -> Option<PathBuf> {
    let u = safe_user(username);
    if u.is_empty() { return None; }
    Some(PathBuf::from(data_dir).join("uploads").join("_inprogress").join(u))
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
    // #F19: on the same hourly/startup cadence, drop idle per-user record locks
    // so the static lock map can't grow without bound over the process lifetime
    // (see prune_record_locks). Safe under concurrency — only count==1 entries,
    // which have no live holder/waiter, are removed.
    prune_record_locks();
    removed
}

/// Read/write the per-user persistent record list. Mutations are serialized by
/// callers behind the per-user records lock (see [`user_record_lock`]) and
/// persisted via [`write_records_atomic`].
async fn load_records(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    let mut records = load_user_records_for(data_dir, username).await;
    // Migration: pre-chunked records have empty id. Backfill from filename
    // so every row has a unique stable key for in-memory maps and remove().
    for r in &mut records {
        if r.id.is_empty() {
            r.id = if r.filename.is_empty() { Uuid::new_v4().to_string() } else { r.filename.clone() };
        }
        if r.progress_bytes == 0 && r.status == UploadStatus::Done { r.progress_bytes = r.size; }
        // Argon P1 upload.rs:1299: records finalized by older builds carry the auth-gated
        // "<base>/files/<file>" link; hand out the public "<base>/pub/<file>" one (same
        // file, same bytes — exactly what the client already rewrote it to when sharing).
        if !r.filename.is_empty() {
            let old_tail = format!("/files/{}", r.filename);
            if let Some(base) = r.url.strip_suffix(old_tail.as_str()) {
                r.url = format!("{}/pub/{}", base, r.filename);
            }
        }
        if r.started_at == 0  { r.started_at  = r.uploaded_at; }
        if r.completed_at == 0 && r.status == UploadStatus::Done { r.completed_at = r.uploaded_at; }
    }
    records
}

async fn save_records(data_dir: &str, username: &str, records: &[UploadRecord]) -> Result<()> {
    let path = user_uploads_path(data_dir, username);
    write_records_atomic(&path, records).await
        .map_err(|e| {
            tracing::warn!("uploads: could not save the upload list of {}: {}", username, e);
            anyhow::anyhow!("Could not save the upload list (server storage problem) — try again later")
        })
}

/// Persist the records list via temp-file + atomic rename (#21) so a crash
/// mid-write cannot truncate the list and a concurrent reader never observes a
/// partial file. codex P1 upload.rs:821: fallible — callers must not treat an
/// unsaved list as committed.
async fn write_records_atomic(path: &PathBuf, records: &[UploadRecord]) -> std::io::Result<()> {
    let json = serde_json::to_string(records)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_index_bytes(path, json.as_bytes()).await
}

/// Atomically replace an index file (temp + fsync + rename) with 0600 perms, creating the
/// 0700 index dir if needed. H1: the index lives outside the served uploads dir.
/// codex P1 upload.rs:821: every step's error is returned (it used to be discarded, so a
/// full disk made finalize report Done and delete the staged upload while the index still
/// described it as unfinished).
async fn write_index_bytes(path: &PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    if let Some(parent) = path.parent() {
        if tokio::fs::metadata(parent).await.is_err() {
            let p = parent.to_path_buf();
            tokio::task::spawn_blocking(move || create_private_dir(&p)).await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))??;
        }
    }
    let tmp = path.with_extension("json.tmp");
    let wrote = async {
        let mut f = tokio::fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(&tmp).await?;
        f.write_all(bytes).await?;
        f.flush().await?;
        f.sync_all().await?;
        std::io::Result::Ok(())
    }.await;
    if let Err(e) = wrote {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(e);
    }
    if tokio::fs::rename(&tmp, path).await.is_err() {
        // Rename can fail across some filesystems; fall back to direct write.
        let direct = tokio::fs::write(path, bytes).await;
        let _ = tokio::fs::remove_file(&tmp).await;
        direct?;
    }
    set_mode(path, 0o600);
    Ok(())
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
        // Count EVERY record (incl. Canceled/Error) toward file_count so the
        // per-user PER_USER_MAX_FILES cap keeps bounding phantom cancel/error
        // rows — that cap is the only teeth of the anti-flood guard in
        // cancel_chunked_upload / error_chunked_upload. (This matches baseline.)
        file_count += 1;
        // #25: charge bytes only for data actually on disk. Canceled/Error rows
        // had their temp dir deleted and were never stored -> 0 bytes (else an
        // attacker pins quota via init-then-cancel with 0 bytes). Uploading rows
        // charge real progress_bytes so a large client-declared `size` cannot pin
        // quota it has not consumed. Done rows charge the stored size.
        total_bytes = total_bytes.saturating_add(match r.status {
            UploadStatus::Uploading => r.progress_bytes,
            UploadStatus::Canceled | UploadStatus::Error => 0,
            _ => r.size.max(r.progress_bytes),
        });
        if r.status == UploadStatus::Uploading { inprogress += 1; }
    }
    UserUsage { total_bytes, file_count, inprogress }
}

/// Reject if adding `incoming_bytes` (an upload not already counted under
/// `exclude_id`) would exceed the per-user storage quota or file-count cap.
///
/// #95: this is BEST-EFFORT. At init/append time `incoming_bytes` is the
/// client-DECLARED size (init) or the running on-disk size (append) — both are
/// PRE-strip, so the figure used here can be larger than the bytes ultimately
/// stored (metadata stripping only ever shrinks a file). The authoritative
/// recheck happens at finalize against the real assembled on-disk size, and
/// again post-strip against the final stored size (see finalize_chunked_upload).
/// Concurrent uploads for the same user are serialized behind the per-user
/// records lock, but a multi-account or pre-init estimate can still transiently
/// over- or under-count; the cap is a guard rail, not a hard accounting ledger.
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
/// Runs `validate` against the current record list
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
    save_records(data_dir, username, &records).await?;
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
    let id = checked_id(id)?;
    // #25: a real upload always declares a positive size. Rejecting 0 keeps the
    // init-time quota check meaningful and preserves the finalize size-mismatch
    // guard (which is skipped when size == 0).
    if size == 0 { anyhow::bail!("Invalid file size"); }
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    let data_path = dir.join("data");

    // #115: only a still-`Uploading` record for this id is a genuine resume; in
    // that case we keep the bytes already on disk and continue appending. Any
    // other state (no record, or a prior Done/Error/Canceled attempt reusing the
    // same id) is a FRESH start: remove any leftover `data` file so we never
    // resume on top of stale bytes from an aborted attempt (which would corrupt
    // the new file and mis-seed progress_bytes). The matching record mutate below
    // also resets progress to `existing_bytes` (0 after truncation).
    let is_resume = matches!(
        get_record(data_dir, username, &id).await,
        Some(r) if r.status == UploadStatus::Uploading
    );
    let existing_bytes = if is_resume {
        // Resume case: keep existing on-disk bytes (Err → 0 if the dir/file is gone).
        match tokio::fs::metadata(&data_path).await {
            Ok(m) => m.len() as usize,
            Err(_) => 0,
        }
    } else {
        // Fresh start: discard any pre-existing data file for this id.
        let _ = tokio::fs::remove_file(&data_path).await;
        0
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
            // Codex P1 (upload.rs:1027): a COMPLETED upload's id must not be re-initialised.
            // The revive below would blank its filename/url while the stored file stays on
            // disk, so the file drops out of quota accounting, clear and account deletion
            // (repeat → unbounded public files). Clients always mint a fresh id per upload.
            if records.iter().any(|r| r.id == id_for_check && r.status == UploadStatus::Done) {
                anyhow::bail!("Upload id already used by a completed upload");
            }
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
    // Create the per-id dir only AFTER validation passes, so a rejected init (cap or
    // quota) cannot leak an empty directory/inode and bypass PER_USER_MAX_INPROGRESS.
    // For a genuine resume the dir already exists (create_dir_all is idempotent).
    tokio::fs::create_dir_all(&dir).await?;
    Ok(rec)
}

/// Cheap O(1) pre-check for the chunk route (rust-http #10): does `id` name an
/// upload of this user that is still being assembled? (init creates the per-id
/// temp dir; finalize/cancel/error/sweep remove it.) A miss means append_chunk
/// would refuse the chunk anyway, so the route can answer before it reads the
/// body or takes a shared slot. Not authoritative — append_chunk re-validates
/// everything under the per-user lock.
pub async fn chunk_target_exists(data_dir: &str, username: &str, id: &str) -> bool {
    let Ok(id) = checked_id(id) else { return false };
    match inprogress_dir(data_dir, username, &id) {
        Some(dir) => tokio::fs::metadata(&dir).await.map(|m| m.is_dir()).unwrap_or(false),
        None => false,
    }
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
    let id = checked_id(id)?;
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    let data_path = dir.join("data");
    // #16/#21/#38: hold the per-user records lock across the offset/size
    // validation, the quota check, the file append, AND the record update so
    // read→validate→write→record is atomic per user. The metadata size read and
    // the offset==current comparison MUST happen under the lock: otherwise two
    // concurrent chunks for the same id both read the same `current`, both pass
    // validation, and both append (file corruption / quota bypass). Without the
    // lock the window also let concurrent chunks across different ids overrun
    // the quota, and a client could create records + write bytes without ever
    // calling init.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;
    let current = match tokio::fs::metadata(&data_path).await {
        Ok(m) => m.len() as usize,
        Err(_) => 0,
    };
    if offset != current {
        anyhow::bail!("Offset mismatch (have {}, got {})", current, offset);
    }
    let new_total = current + chunk.len();
    let mut records = load_records(data_dir, username).await;

    // #38: require that init already created an Uploading record for this id and
    // re-enforce the in-progress cap (mirrors the init validator). A client must
    // not be able to materialize new upload records / write bytes by chunking an
    // id that was never initialized.
    let already_uploading = records.iter()
        .any(|r| r.id == id && r.status == UploadStatus::Uploading);
    if !already_uploading {
        let inprogress = compute_usage(&records, None).inprogress;
        if inprogress >= PER_USER_MAX_INPROGRESS {
            anyhow::bail!(
                "Too many uploads in progress (max {})",
                PER_USER_MAX_INPROGRESS
            );
        }
        anyhow::bail!("Upload not initialized");
    }

    // #16: reject the chunk BEFORE writing it to disk if the resulting on-disk
    // size for this upload would push the user over quota. We exclude this id's
    // current row (its already-counted progress) and re-add new_total.
    check_quota(&records, Some(&id), new_total)?;

    // #26: global disk-space guard. Before writing this chunk, refuse it if
    // doing so would drop the data volume's free space below the reserve floor,
    // so K accounts' in-progress uploads cannot fill the shared volume and
    // starve log/DB writes. Fails OPEN when free space cannot be queried.
    if let Some(avail) = available_disk_bytes(std::path::Path::new(data_dir)) {
        if avail < MIN_FREE_DISK_BYTES.saturating_add(chunk.len() as u64) {
            anyhow::bail!("Server storage full, try again later");
        }
    }

    let mut file = tokio::fs::OpenOptions::new()
        .create(true).append(true).open(&data_path).await?;
    file.write_all(chunk).await?;
    file.flush().await?;

    // Update the existing record under the same lock. The Uploading record is
    // guaranteed to exist (checked above), so this always hits the find branch.
    let rec = match records.iter().position(|r| r.id == id) {
        Some(p) => {
            records[p].progress_bytes = new_total;
            records[p].status = UploadStatus::Uploading;
            records[p].clone()
        }
        None => {
            // Unreachable given the already_uploading check, but keep the data
            // consistent rather than panicking if records changed under us.
            anyhow::bail!("Upload not initialized");
        }
    };
    // codex P1 upload.rs:821: if the progress can't be recorded, take the chunk back off
    // the staged file so file and record agree and the client's retry of this same chunk
    // (same offset) is accepted.
    if let Err(e) = save_records(data_dir, username, &records).await {
        if let Ok(f) = tokio::fs::OpenOptions::new().write(true).open(&data_path).await {
            let _ = f.set_len(current as u64).await;
        }
        return Err(e);
    }
    Ok(rec)
}

/// r4 F1-1 (agy P1 upload.rs:1286): a finalize failure caused by server storage — the
/// stored file or the upload index could not be written — not by the upload itself. The
/// assembled bytes are kept in the staging dir and the record stays `Uploading`, so the
/// client's finalize retry (app.js retries a failed finalize) can still succeed;
/// route_upload_finalize answers 503 for it instead of marking the upload failed.
#[derive(Debug)]
pub struct FinalizeRetryable(pub String);
impl std::fmt::Display for FinalizeRetryable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.0) }
}
impl std::error::Error for FinalizeRetryable {}

fn finalize_retryable(what: &str, e: impl std::fmt::Display) -> anyhow::Error {
    tracing::warn!("[upload] finalize: {}: {} — upload kept for a retry", what, e);
    anyhow::Error::new(FinalizeRetryable(
        "Could not store the upload (server storage problem) — retrying may work".to_string()))
}

/// r4 F1-1: undo the store of `final_path` after a failed commit while keeping the upload
/// retryable. A file that was MOVED out of the staging dir (formats that are not rewritten)
/// goes back to `data_path`; otherwise (a stripped copy, or the copy fallback) the staged
/// original is still there and only the stored copy is removed. No orphan is left behind
/// in the public dir either way.
async fn unstore_final(final_path: &std::path::Path, data_path: &std::path::Path) {
    if tokio::fs::metadata(data_path).await.is_err() {
        if tokio::fs::rename(final_path, data_path).await.is_ok() { return; }
        if tokio::fs::copy(final_path, data_path).await.is_ok() {
            let _ = tokio::fs::remove_file(final_path).await;
            return;
        }
        tracing::warn!("[upload] finalize: could not return a stored file to its staging dir; the upload has to be sent again");
    }
    let _ = tokio::fs::remove_file(final_path).await;
}

/// Finalize: validate the assembled temp file, strip metadata, move into
/// the public upload dir, mark record as Done. Returns the final record.
/// A storage failure (stored file / index write) returns a [`FinalizeRetryable`] error
/// with the staged bytes intact (r4 F1-1); every other error is final.
pub async fn finalize_chunked_upload(
    data_dir: &str, upload_dir: &str, username: &str, id: &str,
) -> Result<UploadRecord> {
    let id = checked_id(id)?;
    let dir = inprogress_dir(data_dir, username, &id)
        .ok_or_else(|| anyhow::anyhow!("Invalid upload path"))?;
    let data_path = dir.join("data");

    // #F6: hold the per-user records lock across the ENTIRE finalize — record
    // load, quota rechecks, the strip/write of the final file, the Done commit,
    // AND the temp-dir reclaim. Previously the lock was taken only briefly for
    // the quota recheck (and again inside the upsert), while the fresh-UUID
    // strip+write ran with NO lock: two concurrent POST /upload/finalize/<id>
    // could each mint a distinct {uuid}.{ext}, each write a full copy, and the
    // serialized upsert pointed the record at whichever committed last — leaving
    // the earlier UUID file orphaned (referenced by no record, invisible to
    // compute_usage/check_quota, never swept) → quota bypass + disk fill.
    // Serializing the whole finalize per user closes that window; the idempotent
    // short-circuit below makes a repeat finalize return the already-committed
    // Done record instead of minting a second (orphaned) file.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;

    // Records are loaded ONCE under the lock and remain authoritative for the
    // whole finalize: every mutator of this user's records file (record_upload,
    // upsert_record_validated, remove_record, delete/clear) takes the same lock,
    // so nothing can change the file while we hold it.
    let mut records = load_records(data_dir, username).await;

    // Idempotent repeat: if this id already finalized, return it. This is the
    // loser of two concurrent finalizes (the winner committed Done + removed the
    // temp dir under the lock). Returning early avoids re-stripping a now-gone
    // temp file and — crucially — avoids writing a second, orphaned output file.
    match records.iter().find(|r| r.id == id) {
        Some(r) if r.status == UploadStatus::Done => return Ok(r.clone()),
        Some(_) => {}
        None => anyhow::bail!("Unknown upload id"),
    }

    let on_disk_len = tokio::fs::metadata(&data_path).await
        .map(|m| m.len() as usize)
        .map_err(|_| anyhow::anyhow!("No data uploaded"))?;
    if on_disk_len == 0 { anyhow::bail!("Empty file"); }

    // Existence guaranteed by the match above (still under the lock).
    let existing = records.iter().find(|r| r.id == id)
        .cloned()
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
    check_quota(&records, Some(&id), on_disk_len)?;

    let filename = format!("{}.{}", Uuid::new_v4(), ext);
    std::fs::create_dir_all(upload_dir).map_err(|e| finalize_retryable("creating the upload dir", e))?;
    let final_path = PathBuf::from(upload_dir).join(&filename);

    // Helper: move (rename, falling back to copy) the assembled temp file into
    // the upload dir without buffering it. Used for formats we do not rewrite
    // (#39).
    async fn move_into_place(src: &std::path::Path, dst: &std::path::Path) -> Result<()> {
        match tokio::fs::rename(src, dst).await {
            Ok(()) => Ok(()),
            Err(_) => { tokio::fs::copy(src, dst).await?; Ok(()) }
        }
    }

    // Strip metadata and avoid staging A/V bytes through a separate temp file.
    //   - JPEG/PNG: read + strip in RAM for every image (#20), bounded by the
    //     admin max_upload_mb cap. The strippers REJECT malformed input (#88).
    //   - A/V (ffmpeg): strip directly from data_path to final_path so we never
    //     re-buffer the (often large) media through RAM or an extra temp copy.
    //     REJECTS on ffmpeg failure (#30).
    //   - Everything else: move the temp file into place (#39).
    let size_final = if !ext_needs_strip(&ext) {
        // #39: formats with no metadata to strip — move the temp file into place.
        // r4 F1-1: on failure the staged file is still in place (a failed rename moves
        // nothing; the copy fallback leaves the source) — drop any partial copy, retryable.
        if let Err(e) = move_into_place(&data_path, &final_path).await {
            unstore_final(&final_path, &data_path).await;
            return Err(finalize_retryable("storing the file", e));
        }
        on_disk_len
    } else {
        match ext.as_str() {
            "jpg" | "jpeg" | "png" => {
                // #20: strip EXIF/GPS/XMP from EVERY image regardless of size. A
                // single upload is already bounded by the admin `max_upload_mb`
                // cap (enforced in route_upload_init / route_upload_chunk), and the
                // legacy /upload path strips unconditionally — so an oversized
                // image must never be stored with metadata intact merely to save
                // transient RAM. The strippers REJECT malformed input (#88).
                // #32: bound concurrent in-RAM image strips (held across read+strip).
                let _img_permit = img_strip_semaphore().acquire().await
                    .map_err(|_| anyhow::anyhow!("image strip unavailable"))?;
                let raw = tokio::fs::read(&data_path).await
                    .map_err(|_| anyhow::anyhow!("No data uploaded"))?;
                if raw.is_empty() { anyhow::bail!("Empty file"); }
                let stripped = if ext == "png" {
                    strip_png_metadata(&raw)?
                } else {
                    strip_jpeg_metadata(&raw)?
                };
                // r4 F1-1: a failed write (e.g. disk full) leaves the staged original; drop
                // the partial copy and keep the upload retryable.
                if let Err(e) = tokio::fs::write(&final_path, &stripped).await {
                    let _ = tokio::fs::remove_file(&final_path).await;
                    return Err(finalize_retryable("storing the file", e));
                }
                stripped.len()
            }
            // #99: GIF/WEBP/AVIF/HEIC/HEIF/TIFF — path-based exiftool strip,
            // same shape as the A/V arm below (avoids buffering large images
            // through RAM). REJECTS on failure rather than storing un-stripped data.
            "gif" | "webp" | "avif" | "heic" | "heif" | "tiff" | "tif" => {
                strip_image_metadata_exiftool_path(&data_path, &final_path, &ext).await?;
                tokio::fs::metadata(&final_path).await.map(|m| m.len() as usize).unwrap_or(on_disk_len)
            }
            // A/V (mp4/webm/mov/avi/mkv/m4v/3gp/3g2/flv/wmv/mp3/ogg/wav/flac):
            // path-based ffmpeg strip, input is data_path, output is final_path.
            // REJECTS on failure (#30) rather than storing un-stripped data.
            _ => {
                strip_av_metadata_path(&data_path, &final_path, &ext).await?;
                tokio::fs::metadata(&final_path).await.map(|m| m.len() as usize).unwrap_or(on_disk_len)
            }
        }
    };

    let content_type = safe_content_type(&ext).to_string();
    // Argon P1 upload.rs:1299: the PUBLIC /pub/ URL, exactly like handle_upload — the
    // /files/ route is auth-gated, so a chunked upload's recorded link 401'd for anyone
    // without the uploader's session (TUI, a recipient opening the link). Older records
    // that still say /files/ are rewritten when loaded (see load_records); both routes
    // keep serving the same file. trim_end_matches('/') so a root install
    // (CRYPTIRC_BASE_PATH="/") yields "/pub/…" not "//pub/…".
    let url = format!(
        "{}/pub/{}",
        std::env::var("CRYPTIRC_BASE_PATH").unwrap_or_else(|_| "/cryptirc".into()).trim_end_matches('/'),
        filename
    );
    let now = chrono::Utc::now().timestamp();

    // #95: authoritative post-strip quota recheck against the FINAL stored size
    // (size_final), still under the per-user lock, before committing the Done
    // record. The earlier checks used pre-strip/declared sizes; this is the real
    // number. On rejection remove the just-written final file and return Err; the
    // caller (route_upload_finalize) then runs error_chunked_upload, which removes
    // the temp dir and marks the record Error — so nothing is orphaned. (The client
    // must start a new upload to retry; this is not an in-place resumable retry.)
    if let Err(e) = check_quota(&records, Some(&id), size_final) {
        unstore_final(&final_path, &data_path).await;
        return Err(e);
    }

    // Commit Done into the in-memory list loaded under this lock, then persist.
    let rec = match records.iter().position(|r| r.id == id) {
        Some(p) => {
            let r = &mut records[p];
            r.status = UploadStatus::Done;
            r.filename = filename.clone();
            r.url = url.clone();
            r.content_type = content_type.clone();
            r.size = size_final;
            r.progress_bytes = size_final;
            r.completed_at = now;
            r.uploaded_at = now;
            r.error = String::new();
            r.clone()
        }
        None => {
            // Record vanished despite holding the lock (should be impossible).
            // Remove the just-written file rather than leak an uncounted orphan.
            let _ = tokio::fs::remove_file(&final_path).await;
            anyhow::bail!("Unknown upload id");
        }
    };
    // codex P1 upload.rs:821: only a durably saved Done record commits the upload. If the
    // index can't be written, the just-stored public file must not stay (nothing would
    // reference it: an orphan outside quota, listing and cleanup). r4 F1-1 (agy P1
    // upload.rs:1286): for formats that are moved rather than rewritten, that file WAS the
    // staged upload — deleting it destroyed the only copy, so the client's retry found "No
    // data uploaded". unstore_final moves it back into the staging dir instead, and the
    // error is retryable (the record stays Uploading; the route does not fail the upload).
    if let Err(e) = save_records(data_dir, username, &records).await {
        unstore_final(&final_path, &data_path).await;
        return Err(finalize_retryable("saving the upload list", e));
    }

    // #5/#34: the Done record is now durably written — reclaim the temp dir. The
    // temp `data` file was the only copy of the assembled upload until this
    // point, so removing it earlier meant a failed commit destroyed the upload
    // with no retry. The in-flight `Uploading` record reserved `on_disk_len`
    // bytes toward the user's quota for the whole strip/commit window
    // (compute_usage counts progress_bytes), so no concurrent finalize could
    // transiently exceed PER_USER_MAX_TOTAL_BYTES.
    let _ = tokio::fs::remove_dir_all(&dir).await;
    Ok(rec)
}

/// Cancel an in-flight upload: removes the temp dir and marks the record
/// as Canceled. (We keep the row briefly so other devices observe the
/// transition; callers may follow up with `remove_record`.)
pub async fn cancel_chunked_upload(
    data_dir: &str, username: &str, id: &str,
) -> Result<UploadRecord> {
    let id = checked_id(id)?;
    if let Some(dir) = inprogress_dir(data_dir, username, &id) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    let now = chrono::Utc::now().timestamp();
    let id_for_check = id.clone();
    let rec = upsert_record_validated(data_dir, username, &id,
        UploadRecord {
            id: id.clone(), filename: String::new(), original_name: String::new(),
            size: 0, content_type: String::new(), url: String::new(),
            uploaded_at: 0, status: UploadStatus::Canceled,
            progress_bytes: 0, started_at: now, completed_at: now,
            error: String::new(),
            source_conn_id: String::new(), source_target: String::new(),
        },
        |records| {
            // No-op for an existing id (every legitimate cancel acts on an init'd id);
            // for a crafted brand-new id, apply the same file-count cap init uses so a
            // flood of /upload/cancel/<random-id> can't push phantom Canceled records
            // past PER_USER_MAX_FILES (the cap lived only in the init/append validators).
            if records.iter().any(|r| r.id == id_for_check) { Ok(()) }
            else { check_quota(records, Some(&id_for_check), 0) }
        },
        |r| {
            // Only transition from Uploading → Canceled. If already Done
            // or Error, leave it alone (caller should use remove_record).
            if r.status == UploadStatus::Uploading {
                r.status = UploadStatus::Canceled;
                r.completed_at = now;
            }
        },
    ).await?;
    Ok(rec)
}

/// Mark an upload as Error (e.g. originating device hit a fatal client error).
pub async fn error_chunked_upload(
    data_dir: &str, username: &str, id: &str, message: &str,
) -> Result<UploadRecord> {
    let id = checked_id(id)?;
    if let Some(dir) = inprogress_dir(data_dir, username, &id) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    let now = chrono::Utc::now().timestamp();
    let msg: String = message.chars().take(300).collect();
    let id_for_check = id.clone();
    let rec = upsert_record_validated(data_dir, username, &id,
        UploadRecord {
            id: id.clone(), filename: String::new(), original_name: String::new(),
            size: 0, content_type: String::new(), url: String::new(),
            uploaded_at: 0, status: UploadStatus::Error,
            progress_bytes: 0, started_at: now, completed_at: now,
            error: msg.clone(),
            source_conn_id: String::new(), source_target: String::new(),
        },
        |records| {
            // Same cap as cancel: no-op for an existing id, file-count guard for a
            // crafted brand-new id so /upload/error/<random-id> can't grow the records
            // JSON without bound.
            if records.iter().any(|r| r.id == id_for_check) { Ok(()) }
            else { check_quota(records, Some(&id_for_check), 0) }
        },
        |r| {
            if r.status == UploadStatus::Uploading {
                r.status = UploadStatus::Error;
                r.completed_at = now;
                r.error = msg.clone();
            }
        },
    ).await?;
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
    // #96: reject ids that aren't byte-identical after sanitization rather than
    // collapsing distinct client ids onto one path/record key.
    // Codex P1 (upload.rs:1426): except a legacy record id — direct/legacy uploads use
    // their stored filename ("<uuid>.<ext>") as id, and the dot failed checked_id, so
    // My Uploads could list such a file but its Remove did nothing. Such an id only ever
    // matches a record exactly; it has no in-progress dir.
    let (id, legacy) = match checked_id(id) {
        Ok(i) => (i, false),
        Err(_) if is_legacy_file_id(id) => (id.to_string(), true),
        Err(_) => return false,
    };
    if !legacy {
        if let Some(dir) = inprogress_dir(data_dir, username, &id) {
            let _ = tokio::fs::remove_dir_all(&dir).await;
        }
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
        // codex P1 upload.rs:821: keep file and record together — if the shortened list
        // can't be saved, leave both in place and report "not removed".
        if save_records(data_dir, username, &records).await.is_err() { return false; }
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
    let mut records = load_user_records_for(data_dir, username).await;
    if records.iter().any(|r| r.filename == safe) {
        records.retain(|r| r.filename != safe);
        // codex P1 upload.rs:821: save first, then unlink — an unsaved removal must not
        // leave a record pointing at a deleted file.
        match write_records_atomic(&path, &records).await {
            Ok(()) => { let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&safe)).await; }
            Err(e) => tracing::warn!("uploads: could not save the upload list of {}: {} — file kept", username, e),
        }
    }
}

pub async fn clear_user_uploads(data_dir: &str, upload_dir: &str, username: &str) {
    // #21: serialize the records read-modify-write behind the per-user lock.
    let lock = user_record_lock(username);
    let _guard = lock.lock().await;
    let path = user_uploads_path(data_dir, username);
    let records = load_user_records_for(data_dir, username).await;
    for r in &records {
        // Sanitize before joining, consistent with delete_user_upload (filenames are
        // server-generated UUIDs today, so this is defense-in-depth, not a behavior change).
        let safe: String = r.filename.chars().filter(|c| c.is_alphanumeric() || *c == '.' || *c == '-').take(128).collect();
        let _ = tokio::fs::remove_file(PathBuf::from(upload_dir).join(&safe)).await;
    }
    // If the empty list can't be written, remove the index instead (a missing index reads
    // as empty) so no record survives pointing at the files just deleted.
    if write_index_bytes(&path, b"[]").await.is_err() {
        let _ = tokio::fs::remove_file(&path).await;
    }
    // Codex P1 (upload.rs:1499): the staged chunks of every in-flight upload go too. Their
    // records were just wiped, so the bytes would otherwise sit outside quota accounting
    // until the 24 h sweeper (stage ~2 GiB, clear, repeat). Done under the records lock,
    // which append_chunk also holds, so no chunk lands in a dir mid-delete; a later chunk
    // for a cleared id is refused ("Upload not initialized").
    if let Some(dir) = user_inprogress_dir(data_dir, username) {
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
    // H1: also drop any copy still in the served dir (a migration that could not
    // move it, or one written by a rolled-back old binary) and this user's merge
    // backups, so clearing / account deletion leaves no index residue anywhere.
    let _ = tokio::fs::remove_file(legacy_user_uploads_path(data_dir, username)).await;
    let _ = tokio::fs::remove_file(legacy_user_uploads_path(data_dir, username).with_extension("json.tmp")).await;
    let backup_dir = upload_index_dir(data_dir).join("legacy-backup");
    if let Ok(mut rd) = tokio::fs::read_dir(&backup_dir).await {
        let prefix = format!("{}.json.", username);
        while let Ok(Some(e)) = rd.next_entry().await {
            if e.file_name().to_str().map_or(false, |n| n.starts_with(&prefix)) {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
}

/// Read a user's records from the index dir; if that file does not exist yet but
/// a legacy copy is still in the served uploads dir (the startup migration could
/// not move it), read that instead so My Uploads / quota / delete keep working.
/// The next write lands in the new location; the next startup migration merges
/// and removes the legacy copy.
async fn load_user_records_for(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    match tokio::fs::read_to_string(user_uploads_path(data_dir, username)).await {
        Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match tokio::fs::read_to_string(legacy_user_uploads_path(data_dir, username)).await {
                Ok(json) => serde_json::from_str(&json).unwrap_or_default(),
                Err(_) => vec![],
            }
        }
        Err(_) => vec![],
    }
}

/// Returns true if the filename has an image extension (safe for inline display).
pub fn is_image(filename: &str) -> bool {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "avif" | "ico"
        | "heic" | "heif" | "bmp" | "tiff" | "tif"
    )
}

/// Media types the /pub route serves INLINE (rendered/played in the browser:
/// images, video, audio — link previews and inline players need that). Kept in
/// lockstep with the client's _PUBLIC_MEDIA_EXTS in app.js and with the extensions
/// safe_content_type knows. This does NOT decide WHETHER /pub serves a file: since
/// v0.4.0 (343fc82) every upload is public-by-link (its unguessable UUID is the
/// capability), so documents/archives/text/unknown types are served too, just as
/// `Content-Disposition: attachment` (PDF is also inline; see serve_file_public).
/// Only the reserved internal names (`is_reserved_upload_name`) are never served.
pub fn is_public_media(filename: &str) -> bool {
    if is_image(filename) { return true; }
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    matches!(
        ext.as_str(),
        // video
        "mp4" | "webm" | "mov" | "avi" | "mkv" | "m4v" | "3gp" | "3g2" | "flv" | "wmv"
        // audio
        | "mp3" | "ogg" | "wav" | "flac"
    )
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
        "jpg" | "jpeg" => {
            // #32: bound concurrent in-RAM image strips (see img_strip_semaphore).
            let _permit = img_strip_semaphore().acquire().await
                .map_err(|_| anyhow::anyhow!("image strip unavailable"))?;
            strip_jpeg_metadata(data)
        }
        "png" => {
            let _permit = img_strip_semaphore().acquire().await
                .map_err(|_| anyhow::anyhow!("image strip unavailable"))?;
            strip_png_metadata(data)
        }
        "gif" | "webp" | "avif" | "heic" | "heif" | "tiff" | "tif" =>
            strip_image_metadata_exiftool(data, ext).await,
        "mp4" | "webm" | "mov" | "avi" | "mkv" | "m4v" | "3gp" | "3g2" | "flv" | "wmv"
        | "mp3" | "ogg" | "wav" | "flac" =>
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
    // Stage the in-RAM bytes to a temp input file, run the shared path-based
    // stripper into a temp output file, then read the result back. Used by the
    // legacy /upload path which only has the bytes in memory. The finalize path
    // (#17) uses strip_av_metadata_path directly against the on-disk temp file
    // so it never re-buffers large media through RAM.
    let tmp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let input_path = tmp_dir.join(format!("cryptirc_in_{}.{}", id, ext));
    let output_path = tmp_dir.join(format!("cryptirc_out_{}.{}", id, ext));

    if tokio::fs::write(&input_path, data).await.is_err() {
        let _ = tokio::fs::remove_file(&input_path).await;
        anyhow::bail!("Failed to stage upload for metadata stripping");
    }

    let result = strip_av_metadata_path(&input_path, &output_path, ext).await;
    let read_back = match &result {
        Ok(()) => tokio::fs::read(&output_path).await.ok(),
        Err(_) => None,
    };
    let _ = tokio::fs::remove_file(&input_path).await;
    let _ = tokio::fs::remove_file(&output_path).await;

    result?;
    match read_back {
        Some(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => anyhow::bail!("Metadata stripping produced no output"),
    }
}

/// Path-based A/V metadata strip: runs `ffmpeg -map_metadata -1 -c copy` from
/// `input_path` to `output_path`. Bounded by the global concurrency semaphore
/// and a wall-clock timeout, and REJECTS (returns Err) on ffmpeg failure,
/// timeout, or absence (#30). On error the (partial) output file is removed.
async fn strip_av_metadata_path(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    _ext: &str,
) -> Result<()> {
    use tokio::process::Command;

    // Bound concurrent ffmpeg jobs so a burst cannot spawn unbounded CPU work.
    let _permit = av_strip_semaphore().acquire().await
        .map_err(|_| anyhow::anyhow!("Metadata stripper unavailable"))?;

    let (in_str, out_str) = match (input_path.to_str(), output_path.to_str()) {
        (Some(i), Some(o)) => (i, o),
        _ => anyhow::bail!("Invalid temp path"),
    };

    let mut cmd = Command::new("ffmpeg");
    cmd.args([
        "-nostdin",
        "-y",                   // overwrite output
        "-threads", "1",        // bound CPU per job
        // Defense in depth against crafted "media" that is really a playlist /
        // concat script (HLS, ffconcat, …) pointing at local files or URLs: the
        // input may only be opened via the plain file protocol, and only by a
        // real container demuxer for the formats we accept (no hls/concat/
        // image2/dash/…). Every ext_needs_strip A/V type maps to one of these.
        "-protocol_whitelist", "file",
        "-format_whitelist", AV_DEMUXER_WHITELIST,
        "-i", in_str,
        "-map_metadata", "-1",  // strip all metadata
        "-c", "copy",           // copy streams without re-encoding
        "-threads", "1",
        out_str,
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
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Could not strip media metadata (ffmpeg unavailable)");
        }
        Err(_) => {
            // Timed out (child is killed on drop).
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Media metadata stripping timed out");
        }
    };

    if !status.success() {
        let _ = tokio::fs::remove_file(output_path).await;
        anyhow::bail!("Could not strip media metadata");
    }

    // Ensure ffmpeg actually produced a non-empty output file.
    match tokio::fs::metadata(output_path).await {
        Ok(m) if m.len() > 0 => Ok(()),
        _ => {
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Metadata stripping produced no output");
        }
    }
}

/// #99: strip metadata from GIF/WEBP/AVIF/HEIC/HEIF/TIFF via `exiftool -all=`,
/// copying `input_path` to `output_path` first, then running exiftool's
/// `-overwrite_original` in place on the copy. (Exiftool's `-o <new-file>`
/// direct-write mode was tried first but rejects WEBP/RIFF outright — "Can't
/// write RIFF files" — even though in-place `-overwrite_original` edits a
/// WEBP file just fine; copy-then-edit-in-place is the one approach that
/// works for every format this function is actually called with.)
/// Bounded by a concurrency semaphore + wall-clock timeout, and REJECTS (returns
/// Err) on exiftool failure, timeout, or absence — same fail-closed contract as
/// `strip_av_metadata_path`. Verified empirically (see module doc comment) that
/// this is a metadata-only edit: exiftool does not decode/re-encode the image,
/// so pixel data is untouched and dimensions/frame data are preserved exactly.
async fn strip_image_metadata_exiftool_path(
    input_path: &std::path::Path,
    output_path: &std::path::Path,
    _ext: &str,
) -> Result<()> {
    use tokio::process::Command;

    let _permit = exiftool_strip_semaphore().acquire().await
        .map_err(|_| anyhow::anyhow!("Metadata stripper unavailable"))?;

    tokio::fs::copy(input_path, output_path).await
        .map_err(|_| anyhow::anyhow!("Failed to stage upload for metadata stripping"))?;

    let out_str = match output_path.to_str() {
        Some(o) => o,
        None => anyhow::bail!("Invalid temp path"),
    };

    // `-all=` drops Orientation along with everything else, which leaves phone
    // photos displayed sideways (the sensor frame is stored as-captured and the
    // rotation lives only in that tag). Copy it back from the source afterwards;
    // every other tag — GPS, timestamps, camera serial — still goes.
    //
    // Must be `-EXIF:Orientation`, not bare `-Orientation`: for a container with
    // nowhere native to put it (GIF) the unqualified form makes exiftool fall
    // back to writing an XMP packet, which stamps our exiftool version into the
    // file and pads it by ~2KB. Qualifying the group makes exiftool decline
    // instead, so those formats come out exactly as they did before — no loss,
    // since nothing renders orientation from a GIF anyway.
    let mut cmd = Command::new(exiftool_program());
    cmd.args(["-all=", "-tagsfromfile", "@", "-EXIF:Orientation", "-overwrite_original", out_str])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    let status = match tokio::time::timeout(EXIFTOOL_STRIP_TIMEOUT, cmd.status()).await {
        Ok(Ok(s)) => s,
        Ok(Err(_)) => {
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Could not strip image metadata (exiftool unavailable)");
        }
        Err(_) => {
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Image metadata stripping timed out");
        }
    };

    if !status.success() {
        let _ = tokio::fs::remove_file(output_path).await;
        anyhow::bail!("Could not strip image metadata (malformed or unsupported file)");
    }

    match tokio::fs::metadata(output_path).await {
        Ok(m) if m.len() > 0 => Ok(()),
        _ => {
            let _ = tokio::fs::remove_file(output_path).await;
            anyhow::bail!("Metadata stripping produced no output");
        }
    }
}

/// The exiftool to run: `exiftool` from PATH when it is there, else Arch's
/// perl-image-exiftool location (/usr/bin/vendor_perl, which is not on a systemd
/// service's default PATH), else plain `exiftool` (fails closed as before).
/// Resolved once.
fn exiftool_program() -> &'static std::ffi::OsStr {
    static P: OnceLock<std::ffi::OsString> = OnceLock::new();
    P.get_or_init(|| {
        use std::os::unix::fs::PermissionsExt;
        let is_exec = |p: &std::path::Path| std::fs::metadata(p)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false);
        let on_path = std::env::var_os("PATH").map_or(false, |path| {
            std::env::split_paths(&path).any(|d| is_exec(&d.join("exiftool")))
        });
        if !on_path {
            let arch = std::path::Path::new("/usr/bin/vendor_perl/exiftool");
            if is_exec(arch) { return arch.as_os_str().to_os_string(); }
        }
        std::ffi::OsString::from("exiftool")
    }).as_os_str()
}

/// In-RAM wrapper around `strip_image_metadata_exiftool_path` for the legacy
/// (non-chunked) `/upload` path, which only has the bytes in memory. Mirrors
/// `strip_av_metadata`'s stage-to-temp-file/read-back/cleanup shape.
async fn strip_image_metadata_exiftool(data: &[u8], ext: &str) -> Result<Vec<u8>> {
    let tmp_dir = std::env::temp_dir();
    let id = uuid::Uuid::new_v4();
    let input_path = tmp_dir.join(format!("cryptirc_in_{}.{}", id, ext));
    let output_path = tmp_dir.join(format!("cryptirc_out_{}.{}", id, ext));

    if tokio::fs::write(&input_path, data).await.is_err() {
        let _ = tokio::fs::remove_file(&input_path).await;
        anyhow::bail!("Failed to stage upload for metadata stripping");
    }

    let result = strip_image_metadata_exiftool_path(&input_path, &output_path, ext).await;
    let read_back = match &result {
        Ok(()) => tokio::fs::read(&output_path).await.ok(),
        Err(_) => None,
    };
    let _ = tokio::fs::remove_file(&input_path).await;
    let _ = tokio::fs::remove_file(&output_path).await;

    result?;
    match read_back {
        Some(bytes) if !bytes.is_empty() => Ok(bytes),
        _ => anyhow::bail!("Metadata stripping produced no output"),
    }
}

/// Read the EXIF `Orientation` (tag 0x0112) out of a JPEG's APP1 segment.
///
/// Phone cameras store the sensor frame as-captured and record how to rotate it
/// for display in this one tag. Stripping APP1 wholesale (which is what we want
/// for GPS/timestamps/camera serial) therefore also lays every portrait photo on
/// its side. We read the value here so `strip_jpeg_metadata` can re-emit it from
/// bytes we build ourselves — no attacker-controlled EXIF is ever copied through.
///
/// Returns None unless a well-formed value in 2..=8 is present; 1 means "already
/// upright", which needs no segment at all.
fn jpeg_exif_orientation(data: &[u8]) -> Option<u16> {
    let mut i = 2usize;
    while i + 3 < data.len() {
        if data[i] != 0xFF {
            return None;
        }
        let marker = data[i + 1];
        // Start of scan / end of image: past the headers, nothing left to find.
        if marker == 0xDA || marker == 0xD9 {
            return None;
        }
        // Standalone markers carry no length field.
        if (0xD0..=0xD7).contains(&marker) || marker == 0xD8 || marker == 0x01 {
            i += 2;
            continue;
        }
        let seg_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
        if seg_len < 2 || i + 2 + seg_len > data.len() {
            return None;
        }
        if marker == 0xE1 {
            if let Some(o) = exif_orientation_from_app1(&data[i + 4..i + 2 + seg_len]) {
                return Some(o);
            }
        }
        i += 2 + seg_len;
    }
    None
}

/// Parse `Orientation` out of an APP1 payload (`"Exif\0\0"` + TIFF block).
/// Every offset is bounds-checked against the payload; a malformed or hostile
/// block yields None rather than panicking.
fn exif_orientation_from_app1(payload: &[u8]) -> Option<u16> {
    if payload.len() < 14 || &payload[..6] != b"Exif\0\0" {
        return None;
    }
    exif_orientation_from_tiff(&payload[6..])
}

/// Parse `Orientation` out of a bare TIFF block — the APP1 payload minus its
/// `"Exif\0\0"` prefix, which is also exactly what a PNG `eXIf` chunk holds.
fn exif_orientation_from_tiff(t: &[u8]) -> Option<u16> {
    if t.len() < 8 {
        return None;
    }
    let be = match &t[..2] {
        b"MM" => true,
        b"II" => false,
        _ => return None,
    };
    let rd16 = |b: &[u8]| if be { u16::from_be_bytes([b[0], b[1]]) } else { u16::from_le_bytes([b[0], b[1]]) };
    let rd32 = |b: &[u8]| {
        if be { u32::from_be_bytes([b[0], b[1], b[2], b[3]]) } else { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
    };
    if rd16(&t[2..4]) != 42 {
        return None;
    }
    let ifd0 = rd32(&t[4..8]) as usize;
    if ifd0 < 8 || ifd0.checked_add(2)? > t.len() {
        return None;
    }
    let entries = rd16(&t[ifd0..ifd0 + 2]) as usize;
    for e in 0..entries {
        // Each IFD entry is exactly 12 bytes: tag, type, count, value/offset.
        let off = ifd0.checked_add(2)?.checked_add(e.checked_mul(12)?)?;
        if off.checked_add(12)? > t.len() {
            return None;
        }
        if rd16(&t[off..off + 2]) == 0x0112 {
            // SHORT, count 1 — anything else is not a orientation we understand.
            if rd16(&t[off + 2..off + 4]) != 3 || rd32(&t[off + 4..off + 8]) != 1 {
                return None;
            }
            let v = rd16(&t[off + 8..off + 10]);
            return if (2..=8).contains(&v) { Some(v) } else { None };
        }
    }
    None
}

/// Build a canonical 36-byte APP1 segment carrying ONLY `Orientation`.
/// Fixed layout, generated here rather than copied from the upload, so the
/// re-added segment cannot smuggle anything back in.
fn orientation_app1_segment(orientation: u16) -> [u8; 36] {
    let mut s = [0u8; 36];
    s[0..4].copy_from_slice(&[0xFF, 0xE1, 0x00, 0x22]); // APP1, segment length 34
    s[4..10].copy_from_slice(b"Exif\0\0");
    // Big-endian TIFF header, IFD0 at offset 8.
    s[10..18].copy_from_slice(&[b'M', b'M', 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08]);
    s[18..20].copy_from_slice(&[0x00, 0x01]); // exactly one IFD0 entry
    s[20..22].copy_from_slice(&[0x01, 0x12]); // tag 0x0112 = Orientation
    s[22..24].copy_from_slice(&[0x00, 0x03]); // type 3 = SHORT
    s[24..28].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]); // count 1
    s[28..30].copy_from_slice(&orientation.to_be_bytes()); // value, left-aligned
    // s[30..32] value padding, s[32..36] next-IFD offset — both already zero.
    s
}

/// Read `Orientation` from a PNG's `eXIf` chunk, which the stripper removes
/// along with the rest of the metadata (see `orientation_exif_chunk`).
fn png_exif_orientation(data: &[u8]) -> Option<u16> {
    const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || data[..8] != PNG_SIG {
        return None;
    }
    let mut i = 8usize;
    while i + 12 <= data.len() {
        let len = u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]) as usize;
        let ctype = &data[i + 4..i + 8];
        let total = len.checked_add(12)?;
        if i + total > data.len() {
            return None;
        }
        if ctype == b"eXIf" {
            return exif_orientation_from_tiff(&data[i + 8..i + 8 + len]);
        }
        if ctype == b"IEND" {
            return None;
        }
        i += total;
    }
    None
}

/// CRC-32 (IEEE, reflected) — PNG chunks carry one. Bitwise rather than
/// table-driven: this runs once per upload over ~30 bytes.
fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xEDB8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

/// Build a PNG `eXIf` chunk holding ONLY `Orientation`, reusing the same
/// canonical TIFF block the JPEG path emits (bytes 10.. of the APP1 segment).
fn orientation_exif_chunk(orientation: u16) -> Vec<u8> {
    let seg = orientation_app1_segment(orientation);
    let tiff = &seg[10..]; // 26-byte TIFF block, no "Exif\0\0" prefix
    let mut chunk = Vec::with_capacity(12 + tiff.len());
    chunk.extend_from_slice(&(tiff.len() as u32).to_be_bytes());
    chunk.extend_from_slice(b"eXIf");
    chunk.extend_from_slice(tiff);
    let crc = png_crc32(&chunk[4..]); // CRC covers chunk type + data
    chunk.extend_from_slice(&crc.to_be_bytes());
    chunk
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

    // Everything below strips APP1, which is where the display orientation lives.
    // Re-emit just that one value from a segment we construct ourselves, so
    // portrait photos stay upright without carrying any of the original EXIF.
    if let Some(o) = jpeg_exif_orientation(data) {
        out.extend_from_slice(&orientation_app1_segment(o));
    }

    let mut i = 2;
    let mut saw_sos = false;
    while i + 1 < data.len() {
        if data[i] != 0xFF {
            // Marker bytes must align; anything else means a malformed header.
            anyhow::bail!("Corrupt image (malformed JPEG segment)");
        }

        let marker = data[i + 1];

        // SOS (Start of Scan) — a scan header (which carries a 2-byte length)
        // followed by entropy-coded image data. A progressive JPEG contains
        // MULTIPLE scans (each its own SOS, sometimes interleaved with DHT/DQT
        // tables), but exactly one terminating EOI (FF D9) at the very end.
        //
        // We copy the scan header, then walk the entropy-coded data honoring
        // byte-stuffing (a literal 0xFF is encoded FF 00) and restart markers
        // (FF D0-D7) — neither terminates the scan. Any OTHER FF-marker ends the
        // scan, so we hand control back to the main loop at that marker: for a
        // progressive JPEG it is the next scan/table (copied and re-scanned),
        // and for the final scan it is the genuine EOI. Stopping at that FIRST
        // real EOI drops any trailing EXIF/GPS/XMP/polyglot bytes appended past
        // the image (#35), while still preserving every legitimate scan (#94)
        // (mirrors the PNG path stopping at IEND).
        if marker == 0xDA {
            if i + 3 >= data.len() {
                anyhow::bail!("Corrupt image (truncated JPEG segment)");
            }
            let hdr_len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
            if hdr_len < 2 || i + 2 + hdr_len > data.len() {
                anyhow::bail!("Corrupt image (invalid JPEG segment length)");
            }
            // Copy the scan header.
            out.extend_from_slice(&data[i..i + 2 + hdr_len]);
            // Walk entropy-coded data to the next real marker.
            let scan_start = i + 2 + hdr_len;
            let mut j = scan_start;
            while j + 1 < data.len() {
                if data[j] == 0xFF {
                    let m = data[j + 1];
                    if m == 0x00 || (0xD0..=0xD7).contains(&m) {
                        j += 2; // byte-stuffed 0xFF or RSTn: still scan data
                        continue;
                    }
                    if m == 0xFF {
                        j += 1; // fill byte before a marker
                        continue;
                    }
                    break; // real marker begins at j
                }
                j += 1;
            }
            if j + 1 >= data.len() {
                // Ran off the end without a terminating marker/EOI.
                anyhow::bail!("Corrupt image (missing JPEG end marker)");
            }
            // Copy the entropy-coded bytes and resume marker parsing at j.
            out.extend_from_slice(&data[scan_start..j]);
            saw_sos = true;
            i = j;
            continue;
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
    // APNG animation (r4 C1-10): acTL (animation control), fcTL (frame control: sequence
    //   number, size, offset, delay, dispose/blend), fdAT (frame data). They carry no
    //   metadata; dropping them turned every animated PNG into its static first frame.
    //   Kept in their original order, so the sequence numbers stay valid.
    // Strip everything else: tEXt, iTXt, zTXt, eXIf, dSIG, tIME, etc.
    const PNG_SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    if data.len() < 8 || data[..8] != PNG_SIG {
        anyhow::bail!("Corrupt image (not a valid PNG)");
    }

    let keep_chunks: &[&[u8]] = &[
        b"IHDR", b"PLTE", b"IDAT", b"IEND",
        b"tRNS", b"gAMA", b"cHRM", b"sRGB", b"iCCP", b"sBIT", b"pHYs",
        b"acTL", b"fcTL", b"fdAT",
    ];

    let mut out = Vec::with_capacity(data.len());
    out.extend_from_slice(&PNG_SIG);

    // eXIf goes out with the rest of the metadata below; keep just the display
    // orientation so a rotated PNG doesn't end up on its side.
    let orientation = png_exif_orientation(data);
    let mut wrote_orientation = false;

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
            // Must land before IDAT to be valid; straight after IHDR is simplest.
            // Only after the FIRST IHDR — a malformed input with two of them
            // would otherwise get two eXIf chunks, which the spec forbids.
            if chunk_type == b"IHDR" && !wrote_orientation {
                if let Some(o) = orientation {
                    out.extend_from_slice(&orientation_exif_chunk(o));
                }
                wrote_orientation = true;
            }
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

#[cfg(test)]
mod orientation_tests {
    use super::*;

    /// Minimal but real JPEG: SOI, an APP1 holding one IFD0 Orientation entry,
    /// a token SOF/SOS pair, EOI. `be` picks the TIFF byte order.
    fn jpeg_with_orientation(orientation: u16, be: bool) -> Vec<u8> {
        let mut tiff = Vec::new();
        tiff.extend_from_slice(if be { b"MM" } else { b"II" });
        let w16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
        tiff.extend_from_slice(&w16(42));
        tiff.extend_from_slice(&w32(8)); // IFD0 offset
        tiff.extend_from_slice(&w16(1)); // one entry
        tiff.extend_from_slice(&w16(0x0112)); // Orientation
        tiff.extend_from_slice(&w16(3)); // SHORT
        tiff.extend_from_slice(&w32(1)); // count
        tiff.extend_from_slice(&w16(orientation));
        tiff.extend_from_slice(&[0, 0]); // value padding
        tiff.extend_from_slice(&w32(0)); // no next IFD

        let mut payload = b"Exif\0\0".to_vec();
        payload.extend_from_slice(&tiff);

        let mut out = vec![0xFF, 0xD8];
        let seg_len = (payload.len() + 2) as u16;
        out.extend_from_slice(&[0xFF, 0xE1]);
        out.extend_from_slice(&seg_len.to_be_bytes());
        out.extend_from_slice(&payload);
        out.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0, 1, 0, 1, 1, 1, 0x11, 0]); // SOF0
        out.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]); // SOS
        out.extend_from_slice(&[0x00]); // one byte of scan data
        out.extend_from_slice(&[0xFF, 0xD9]); // EOI
        out
    }

    #[test]
    fn reads_orientation_both_byte_orders() {
        for be in [true, false] {
            for o in 2..=8u16 {
                assert_eq!(jpeg_exif_orientation(&jpeg_with_orientation(o, be)), Some(o), "be={be} o={o}");
            }
        }
    }

    #[test]
    fn ignores_upright_and_out_of_range() {
        // 1 = already upright: nothing worth re-emitting.
        assert_eq!(jpeg_exif_orientation(&jpeg_with_orientation(1, true)), None);
        assert_eq!(jpeg_exif_orientation(&jpeg_with_orientation(9, true)), None);
        assert_eq!(jpeg_exif_orientation(&jpeg_with_orientation(0, true)), None);
    }

    #[test]
    fn survives_the_strip_that_used_to_destroy_it() {
        // The actual bug: stripping APP1 laid portrait photos on their side.
        let src = jpeg_with_orientation(6, true);
        let stripped = strip_jpeg_metadata(&src).expect("strip should succeed");
        assert_eq!(jpeg_exif_orientation(&stripped), Some(6));
        // ...and the re-emitted segment is our own fixed 36 bytes, not the original.
        assert_eq!(&stripped[2..38], &orientation_app1_segment(6)[..]);
    }

    #[test]
    fn strip_drops_other_exif_while_keeping_orientation() {
        let mut src = jpeg_with_orientation(8, true);
        // Splice in a second APP1 (pretend GPS blob) plus a COM comment.
        let junk_at = 2;
        // Segment length counts the 2 length bytes plus the payload.
        let mut junk = vec![0xFF, 0xE1, 0x00, 0x08];
        junk.extend_from_slice(b"SECRET"); // 6-byte payload → length 8
        junk.extend_from_slice(&[0xFF, 0xFE, 0x00, 0x08]);
        junk.extend_from_slice(b"COMMEN"); // 6-byte COM payload → length 8
        src.splice(junk_at..junk_at, junk);

        let stripped = strip_jpeg_metadata(&src).expect("strip should succeed");
        assert_eq!(jpeg_exif_orientation(&stripped), Some(8), "orientation kept");
        assert!(!stripped.windows(6).any(|w| w == b"SECRET"), "foreign APP1 payload must still be stripped");
        assert!(!stripped.windows(6).any(|w| w == b"COMMEN"), "COM comment must still be stripped");
        let app1_markers = stripped.windows(2).filter(|w| w == b"\xFF\xE1").count();
        assert_eq!(app1_markers, 1, "exactly one APP1 (ours) survives");
    }

    #[test]
    fn malformed_exif_never_panics() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0xFF, 0xD8],
            vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x02],
            vec![0xFF, 0xD8, 0xFF, 0xE1, 0xFF, 0xFF, b'E', b'x', b'i', b'f', 0, 0],
            {
                // Exif header, then a TIFF block claiming a huge IFD entry count.
                let mut v = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x18];
                v.extend_from_slice(b"Exif\0\0");
                v.extend_from_slice(&[b'M', b'M', 0x00, 0x2A, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xFF]);
                v
            },
            {
                // IFD0 offset points past the end of the block.
                let mut v = vec![0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x10];
                v.extend_from_slice(b"Exif\0\0");
                v.extend_from_slice(&[b'I', b'I', 42, 0x00, 0xFF, 0xFF, 0xFF, 0x7F]);
                v
            },
        ];
        for c in cases {
            let _ = jpeg_exif_orientation(&c); // must not panic
        }
    }

    #[test]
    fn jpeg_without_exif_is_byte_identical_to_before() {
        // The "add nothing when there is nothing to add" property — the JPEG
        // counterpart of png_without_exif_is_byte_identical_to_before.
        let mut v = vec![0xFF, 0xD8];
        v.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]); // APP0/JFIF
        v.extend_from_slice(b"JFIF\0\x01\x02\x00\x00\x01\x00\x01\x00\x00");
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        v.extend_from_slice(&[0x00]);
        v.extend_from_slice(&[0xFF, 0xD9]);
        let out = strip_jpeg_metadata(&v).expect("strip should succeed");
        assert_eq!(out, v, "a JPEG with no EXIF must pass through unchanged");
    }

    #[test]
    fn jfif_app0_survives_orientation_insert() {
        // Inserting our APP1 must not cost the JFIF header.
        let mut src = jpeg_with_orientation(6, true);
        let app0: Vec<u8> = {
            let mut a = vec![0xFF, 0xE0, 0x00, 0x10];
            a.extend_from_slice(b"JFIF\0\x01\x02\x00\x00\x01\x00\x01\x00\x00");
            a
        };
        src.splice(2..2, app0);
        let out = strip_jpeg_metadata(&src).expect("strip should succeed");
        assert!(out.windows(4).any(|w| w == b"JFIF"), "JFIF APP0 must survive");
        assert_eq!(jpeg_exif_orientation(&out), Some(6));
    }

    #[test]
    fn orientation_survives_alongside_trailing_polyglot_strip() {
        // #35 (trailing bytes after EOI are dropped) must still hold with the
        // orientation segment in play.
        let mut src = jpeg_with_orientation(3, true);
        src.extend_from_slice(b"TRAILINGSECRET");
        let out = strip_jpeg_metadata(&src).expect("strip should succeed");
        assert_eq!(jpeg_exif_orientation(&out), Some(3));
        assert!(!out.windows(14).any(|w| w == b"TRAILINGSECRET"), "trailing data must be dropped");
    }

    #[test]
    fn xmp_only_app1_yields_no_orientation_segment() {
        // An APP1 that is XMP rather than Exif must not produce a segment.
        let mut v = vec![0xFF, 0xD8];
        let payload = b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>";
        let seg_len = (payload.len() + 2) as u16;
        v.extend_from_slice(&[0xFF, 0xE1]);
        v.extend_from_slice(&seg_len.to_be_bytes());
        v.extend_from_slice(payload);
        v.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x0B, 0x08, 0, 1, 0, 1, 1, 1, 0x11, 0]);
        v.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00]);
        v.extend_from_slice(&[0x00, 0xFF, 0xD9]);
        assert_eq!(jpeg_exif_orientation(&v), None);
        let out = strip_jpeg_metadata(&v).expect("strip should succeed");
        assert!(!out.windows(2).any(|w| w == b"\xFF\xE1"), "no APP1 should be emitted");
    }

    #[test]
    fn segment_is_well_formed() {
        let s = orientation_app1_segment(6);
        assert_eq!(s.len(), 36);
        assert_eq!(&s[0..2], &[0xFF, 0xE1]);
        // Declared length covers everything after the 2 marker bytes.
        assert_eq!(u16::from_be_bytes([s[2], s[3]]) as usize, s.len() - 2);
        assert_eq!(&s[4..10], b"Exif\0\0");
        // Round-trips through our own parser.
        assert_eq!(exif_orientation_from_app1(&s[4..]), Some(6));
    }
}

#[cfg(test)]
mod png_orientation_tests {
    use super::*;

    const SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    fn chunk(ctype: &[u8; 4], data: &[u8]) -> Vec<u8> {
        let mut c = Vec::new();
        c.extend_from_slice(&(data.len() as u32).to_be_bytes());
        c.extend_from_slice(ctype);
        c.extend_from_slice(data);
        let crc = png_crc32(&c[4..]);
        c.extend_from_slice(&crc.to_be_bytes());
        c
    }

    /// PNG with an eXIf chunk (orientation), a tEXt comment, and the required
    /// IHDR/IDAT/IEND scaffolding.
    fn png_with_orientation(o: u16) -> Vec<u8> {
        let seg = orientation_app1_segment(o);
        let mut v = SIG.to_vec();
        v.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        v.extend_from_slice(&chunk(b"eXIf", &seg[10..]));
        v.extend_from_slice(&chunk(b"tEXt", b"Comment\0SECRET-PNG"));
        v.extend_from_slice(&chunk(b"IDAT", &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]));
        v.extend_from_slice(&chunk(b"IEND", &[]));
        v
    }

    #[test]
    fn crc32_matches_known_vector() {
        // Standard CRC-32/IEEE check value for "123456789".
        assert_eq!(png_crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn orientation_survives_png_strip_but_comment_does_not() {
        for o in 2..=8u16 {
            let src = png_with_orientation(o);
            assert_eq!(png_exif_orientation(&src), Some(o), "fixture readable");
            let out = strip_png_metadata(&src).expect("strip should succeed");
            assert_eq!(png_exif_orientation(&out), Some(o), "orientation kept (o={o})");
            assert!(!out.windows(6).any(|w| w == b"SECRET"), "tEXt comment must be stripped");
        }
    }

    #[test]
    fn emitted_chunk_is_structurally_valid() {
        let c = orientation_exif_chunk(6);
        let len = u32::from_be_bytes([c[0], c[1], c[2], c[3]]) as usize;
        assert_eq!(&c[4..8], b"eXIf");
        assert_eq!(len, c.len() - 12, "declared length matches payload");
        // CRC must verify over type + data, as any PNG decoder will check.
        let crc = u32::from_be_bytes([c[c.len() - 4], c[c.len() - 3], c[c.len() - 2], c[c.len() - 1]]);
        assert_eq!(crc, png_crc32(&c[4..c.len() - 4]));
        assert_eq!(exif_orientation_from_tiff(&c[8..c.len() - 4]), Some(6));
    }

    #[test]
    fn png_without_exif_is_byte_identical_to_before() {
        // No eXIf → we must add nothing at all.
        let mut v = SIG.to_vec();
        v.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
        v.extend_from_slice(&chunk(b"IDAT", &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]));
        v.extend_from_slice(&chunk(b"IEND", &[]));
        let out = strip_png_metadata(&v).expect("strip should succeed");
        assert_eq!(out, v);
    }

    /// r4 C1-10: an animated PNG keeps its animation chunks (acTL / fcTL / fdAT, in order)
    /// while text metadata is still stripped; with an eXIf orientation the kept chunk
    /// lands right after IHDR, before acTL and the first IDAT (both stay valid).
    #[test]
    fn r4_apng_animation_chunks_survive_the_strip() {
        let fctl = |seq: u32| { let mut d = seq.to_be_bytes().to_vec(); d.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 10, 0, 0]); d };
        let idat = [0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let mut fdat = 2u32.to_be_bytes().to_vec(); fdat.extend_from_slice(&idat);
        let build = |with_exif: bool| {
            let mut v = SIG.to_vec();
            v.extend_from_slice(&chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]));
            if with_exif { v.extend_from_slice(&chunk(b"eXIf", &orientation_app1_segment(6)[10..])); }
            v.extend_from_slice(&chunk(b"acTL", &[0, 0, 0, 2, 0, 0, 0, 0]));
            v.extend_from_slice(&chunk(b"tEXt", b"Comment\0SECRET-APNG"));
            v.extend_from_slice(&chunk(b"fcTL", &fctl(0)));
            v.extend_from_slice(&chunk(b"IDAT", &idat));
            v.extend_from_slice(&chunk(b"fcTL", &fctl(1)));
            v.extend_from_slice(&chunk(b"fdAT", &fdat));
            v.extend_from_slice(&chunk(b"IEND", &[]));
            v
        };
        let types = |png: &[u8]| {
            let mut t = Vec::new();
            let mut i = 8;
            while i + 12 <= png.len() {
                let len = u32::from_be_bytes([png[i], png[i + 1], png[i + 2], png[i + 3]]) as usize;
                t.push(String::from_utf8_lossy(&png[i + 4..i + 8]).to_string());
                i += 12 + len;
            }
            t
        };
        let out = strip_png_metadata(&build(false)).expect("strip");
        println!("R4 APNG strip: chunks kept = {:?}", types(&out));
        assert_eq!(types(&out), ["IHDR", "acTL", "fcTL", "IDAT", "fcTL", "fdAT", "IEND"]);
        assert!(!out.windows(6).any(|w| w == b"SECRET"), "text metadata still stripped");
        let out = strip_png_metadata(&build(true)).expect("strip");
        assert_eq!(types(&out), ["IHDR", "eXIf", "acTL", "fcTL", "IDAT", "fcTL", "fdAT", "IEND"]);
        assert_eq!(png_exif_orientation(&out), Some(6));
    }

    #[test]
    fn malformed_png_never_panics() {
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            SIG.to_vec(),
            {
                let mut v = SIG.to_vec();
                v.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // absurd chunk length
                v.extend_from_slice(b"eXIf");
                v
            },
            {
                let mut v = SIG.to_vec();
                v.extend_from_slice(&chunk(b"eXIf", &[0x00])); // truncated TIFF block
                v
            },
        ];
        for c in cases {
            let _ = png_exif_orientation(&c);
            let _ = strip_png_metadata(&c);
        }
    }
}

#[cfg(test)]
mod index_location_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_data() -> String {
        let d = std::env::temp_dir().join(format!("cryptirc-upidx-{}", Uuid::new_v4()));
        std::fs::create_dir_all(d.join("uploads")).unwrap();
        d.to_str().unwrap().to_string()
    }
    fn rec(id: &str, filename: &str, status: UploadStatus) -> UploadRecord {
        UploadRecord {
            id: id.into(), filename: filename.into(), original_name: "o.txt".into(), size: 1,
            content_type: "text/plain".into(), url: String::new(), uploaded_at: 1, status,
            progress_bytes: 1, started_at: 1, completed_at: 1, error: String::new(),
            source_conn_id: String::new(), source_target: "#secret".into(),
        }
    }
    fn mode(p: &std::path::Path) -> u32 { std::fs::metadata(p).unwrap().permissions().mode() & 0o777 }

    #[test]
    fn reserved_names() {
        for n in ["alice.json", "Alice.JSON", "a.json", "bob_1-x.json", "alice.json.tmp", "x.tmp", "_inprogress", ".hidden"] {
            assert!(is_reserved_upload_name(n), "{} must be reserved", n);
        }
        for n in ["93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.pdf", "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.json",
                  "93D1A2B4-1C2D-4E5F-8A9B-0C1D2E3F4A5B.png", "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.tmp",
                  "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.mp4", "report.pdf", "notes.txt"] {
            assert!(!is_reserved_upload_name(n), "{} must stay servable", n);
        }
    }

    #[test]
    fn migration_moves_merges_and_is_idempotent() {
        let data = tmp_data();
        let up = PathBuf::from(&data).join("uploads");
        let blob = "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.pdf";
        let gone = "00000000-1c2d-4e5f-8a9b-0c1d2e3f4a5b.pdf";
        let user_json = "11111111-1c2d-4e5f-8a9b-0c1d2e3f4a5b.json"; // an uploaded .json blob
        std::fs::write(up.join(blob), b"pdf").unwrap();
        std::fs::write(up.join(user_json), b"{}").unwrap();
        // alice: only legacy → moved.
        let alice = vec![rec(blob, blob, UploadStatus::Done)];
        std::fs::write(up.join("alice.json"), serde_json::to_vec(&alice).unwrap()).unwrap();
        set_mode(&up.join("alice.json"), 0o644);
        // bob: both exist (rolled-back old binary wrote a new legacy file) → merged.
        let idx = upload_index_dir(&data);
        std::fs::create_dir_all(&idx).unwrap();
        std::fs::write(idx.join("bob.json"), serde_json::to_vec(&vec![rec("n1", blob, UploadStatus::Done)]).unwrap()).unwrap();
        std::fs::write(up.join("bob.json"), serde_json::to_vec(&vec![
            rec("n1", blob, UploadStatus::Done),          // dup id → new wins
            rec("o1", blob, UploadStatus::Done),          // old-only, blob present → kept
            rec("o2", gone, UploadStatus::Done),          // old-only, blob deleted → not resurrected
            rec("o3", "", UploadStatus::Error),           // old-only non-Done → kept
        ]).unwrap()).unwrap();
        // stale temp from the old atomic writer
        std::fs::write(up.join("carol.json.tmp"), b"[partial").unwrap();

        let (moved, merged, temps) = migrate_upload_index(&data);
        assert_eq!((moved, merged, temps), (1, 1, 1));
        assert!(!up.join("alice.json").exists() && !up.join("bob.json").exists() && !up.join("carol.json.tmp").exists());
        assert!(up.join(blob).exists() && up.join(user_json).exists(), "blobs (incl. <uuid>.json) untouched");
        let a: Vec<UploadRecord> = serde_json::from_slice(&std::fs::read(idx.join("alice.json")).unwrap()).unwrap();
        assert_eq!(a.len(), 1);
        let b: Vec<UploadRecord> = serde_json::from_slice(&std::fs::read(idx.join("bob.json")).unwrap()).unwrap();
        let ids: Vec<&str> = b.iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, vec!["n1", "o1", "o3"]);
        assert_eq!(mode(&idx), 0o700);
        assert_eq!(mode(&idx.join("alice.json")), 0o600);
        assert_eq!(mode(&idx.join("bob.json")), 0o600);
        // Backup of bob's legacy file exists, outside the served dir.
        let backups: Vec<_> = std::fs::read_dir(idx.join("legacy-backup")).unwrap().flatten().collect();
        assert_eq!(backups.len(), 1);
        // Second run: nothing to do, nothing changes.
        assert_eq!(migrate_upload_index(&data), (0, 0, 0));
        let b2: Vec<UploadRecord> = serde_json::from_slice(&std::fs::read(idx.join("bob.json")).unwrap()).unwrap();
        assert_eq!(b2.len(), 3);
        let _ = std::fs::remove_dir_all(&data);
    }

    #[tokio::test]
    async fn runtime_paths_use_index_dir_with_legacy_fallback() {
        let data = tmp_data();
        let up = PathBuf::from(&data).join("uploads");
        let blob = "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.png";
        std::fs::write(up.join(blob), b"png").unwrap();
        // A legacy file the migration could not move is still readable …
        std::fs::write(up.join("dave.json"), serde_json::to_vec(&vec![rec(blob, blob, UploadStatus::Done)]).unwrap()).unwrap();
        assert_eq!(list_user_uploads(&data, "dave").await.len(), 1);
        // … and clearing removes both the blob and every copy of the index.
        clear_user_uploads(&data, up.to_str().unwrap(), "dave").await;
        assert!(!up.join(blob).exists() && !up.join("dave.json").exists());
        assert_eq!(std::fs::read(upload_index_dir(&data).join("dave.json")).unwrap(), b"[]");
        // New writes land in the index dir (0600), never in the served dir.
        let r = UploadResult { url: "/pub/x".into(), filename: blob.into(), original_name: "a.png".into(),
                               size: 3, content_type: "image/png".into(), is_image: true };
        record_upload(&data, "erin", &r).await.unwrap();
        assert!(!up.join("erin.json").exists());
        let p = upload_index_dir(&data).join("erin.json");
        assert_eq!(mode(&p), 0o600);
        assert_eq!(list_user_uploads(&data, "erin").await.len(), 1);
        delete_user_upload(&data, up.to_str().unwrap(), "erin", blob).await;
        assert_eq!(list_user_uploads(&data, "erin").await.len(), 0);
        let _ = std::fs::remove_dir_all(&data);
    }
}

#[cfg(test)]
mod r2_srv_a_upload_tests {
    //! Round-2 (srv-a): completed ids can't be re-initialised (quota bypass), clear also
    //! drops staged chunks, and Remove works for legacy filename-shaped record ids.
    use super::*;

    fn tmp_data() -> (String, String) {
        let d = std::env::temp_dir().join(format!("cryptirc-r2up-{}", Uuid::new_v4()));
        std::fs::create_dir_all(d.join("uploads")).unwrap();
        let data = d.to_str().unwrap().to_string();
        (data.clone(), format!("{}/uploads", data))
    }
    fn stored_files(up: &str) -> usize {
        std::fs::read_dir(up).unwrap().flatten().filter(|e| e.path().is_file()).count()
    }

    #[tokio::test]
    async fn completed_upload_id_cannot_be_reinitialised() {
        let (data, up) = tmp_data();
        let id = "11111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "mallory", id, "a.txt", 5, "", "").await.unwrap();
        append_chunk(&data, "mallory", id, 0, b"hello").await.unwrap();
        let done = finalize_chunked_upload(&data, &up, "mallory", id).await.unwrap();
        assert_eq!(done.status, UploadStatus::Done);
        // Re-init the same (completed) id: refused, record + file untouched.
        let again = init_chunked_upload(&data, "mallory", id, "b.txt", 5, "", "").await;
        let rec = get_record(&data, "mallory", id).await.unwrap();
        println!("R2 reinit-done: result={:?} status={:?} filename_kept={}", again.as_ref().map(|r| r.status.clone()).map_err(|e| e.to_string()),
            rec.status, rec.filename == done.filename);
        assert!(again.is_err());
        assert_eq!(rec.status, UploadStatus::Done);
        assert_eq!(rec.filename, done.filename);
        assert_eq!(stored_files(&up), 1);
        // A canceled id may still be retried (unchanged behaviour).
        let id2 = "21111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "mallory", id2, "c.txt", 3, "", "").await.unwrap();
        cancel_chunked_upload(&data, "mallory", id2).await.unwrap();
        assert!(init_chunked_upload(&data, "mallory", id2, "c.txt", 3, "", "").await.is_ok());
        let _ = std::fs::remove_dir_all(&data);
    }

    /// codex P1 upload.rs:821: when the index can't be written, finalize is NOT a commit —
    /// it errors, removes the just-stored public file (no orphan) and the record never says
    /// Done; a failed chunk save is taken back off the staged file so a retry fits.
    /// (The index write is made to fail by occupying its temp path with a directory.)
    #[tokio::test]
    async fn r3_index_write_failure_is_not_a_commit() {
        let (data, up) = tmp_data();
        let id = "41111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "full", id, "a.txt", 10, "", "").await.unwrap();
        append_chunk(&data, "full", id, 0, b"hello").await.unwrap();
        let blocker = user_uploads_path(&data, "full").with_extension("json.tmp");
        std::fs::create_dir_all(&blocker).unwrap();
        // A chunk whose progress can't be saved is rolled back off the staged file.
        let staged = inprogress_dir(&data, "full", id).unwrap().join("data");
        assert!(append_chunk(&data, "full", id, 5, b"world").await.is_err());
        assert_eq!(std::fs::metadata(&staged).unwrap().len(), 5, "chunk taken back");
        std::fs::remove_dir(&blocker).unwrap();
        append_chunk(&data, "full", id, 5, b"world").await.unwrap(); // the retry fits
        std::fs::create_dir_all(&blocker).unwrap();
        let r = finalize_chunked_upload(&data, &up, "full", id).await;
        let rec = get_record(&data, "full", id).await.unwrap();
        println!("R3 index-fail finalize: result={:?} record={:?} stored_files={}", r.as_ref().map(|r| r.status.clone()).map_err(|e| e.to_string()), rec.status, stored_files(&up));
        assert!(r.is_err(), "no Done without a saved index");
        assert_eq!(rec.status, UploadStatus::Uploading);
        assert_eq!(stored_files(&up), 0, "no orphan public file");
        // Legacy direct upload: record_upload reports the failure (the route deletes the file).
        let res = UploadResult { url: "/cryptirc/pub/x.txt".into(), filename: "x.txt".into(), original_name: "x.txt".into(), size: 1, content_type: "text/plain".into(), is_image: false };
        assert!(record_upload(&data, "full", &res).await.is_err());
        // Removing a record whose shortened list can't be saved keeps both record and file.
        std::fs::remove_dir(&blocker).unwrap();
        let id2 = "51111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "full", id2, "b.txt", 2, "", "").await.unwrap();
        append_chunk(&data, "full", id2, 0, b"ok").await.unwrap();
        let done = finalize_chunked_upload(&data, &up, "full", id2).await.unwrap();
        std::fs::create_dir_all(&blocker).unwrap();
        assert!(!remove_record(&data, &up, "full", id2).await);
        assert!(std::path::Path::new(&up).join(&done.filename).exists());
        assert!(get_record(&data, "full", id2).await.is_some());
        std::fs::remove_dir(&blocker).unwrap();
        assert!(remove_record(&data, &up, "full", id2).await);
        let _ = std::fs::remove_dir_all(&data);
    }

    /// r4 F1-1 (agy P1 upload.rs:1286): an index-write failure at finalize keeps the upload
    /// retryable — for a moved (not rewritten) format the stored file goes back to the
    /// staging dir, for a stripped one the staged original stays; the error is
    /// FinalizeRetryable, the record stays Uploading, no public orphan is left, and the
    /// retry after the disk recovers commits the original bytes.
    #[tokio::test]
    async fn r4_failed_index_commit_keeps_the_upload_retryable() {
        let (data, up) = tmp_data();
        let blocker = user_uploads_path(&data, "retry").with_extension("json.tmp");
        // A moved format (.txt) and a stripped one (.png).
        let png = {
            let mut v = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
            let mut chunk = |t: &[u8; 4], d: &[u8]| {
                let mut c = (d.len() as u32).to_be_bytes().to_vec();
                c.extend_from_slice(t); c.extend_from_slice(d);
                let crc = png_crc32(&c[4..]);
                c.extend_from_slice(&crc.to_be_bytes());
                v.extend_from_slice(&c);
            };
            chunk(b"IHDR", &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
            chunk(b"tEXt", b"Comment\0secret");
            chunk(b"IDAT", &[0x78, 0x9C, 0x63, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]);
            chunk(b"IEND", &[]);
            v
        };
        for (id, name, body) in [
            ("71111111-2222-4333-8444-555555555555", "a.txt", b"helloworld".to_vec()),
            ("81111111-2222-4333-8444-555555555555", "p.png", png.clone()),
        ] {
            init_chunked_upload(&data, "retry", id, name, body.len(), "", "").await.unwrap();
            append_chunk(&data, "retry", id, 0, &body).await.unwrap();
            let staged = inprogress_dir(&data, "retry", id).unwrap().join("data");
            std::fs::create_dir_all(&blocker).unwrap();
            let r = finalize_chunked_upload(&data, &up, "retry", id).await;
            let err = r.as_ref().err().map(|e| e.to_string()).unwrap_or_default();
            let retryable = r.as_ref().err().map_or(false, |e| e.downcast_ref::<FinalizeRetryable>().is_some());
            let staged_now = std::fs::read(&staged).ok();
            println!("R4 F1-1 {}: err={:?} retryable={} staged_bytes_left={:?} public_files={}", name, err, retryable,
                staged_now.as_ref().map(|b| b.len()), stored_files(&up));
            assert!(retryable, "{name}: storage failure is retryable");
            assert_eq!(staged_now.as_deref(), Some(&body[..]), "{name}: staged bytes intact");
            assert_eq!(get_record(&data, "retry", id).await.unwrap().status, UploadStatus::Uploading);
            assert_eq!(stored_files(&up), 0, "{name}: no orphan public file");
            // Disk recovers: the client's retry commits.
            std::fs::remove_dir(&blocker).unwrap();
            let done = finalize_chunked_upload(&data, &up, "retry", id).await.expect("retry commits");
            assert_eq!(done.status, UploadStatus::Done);
            let stored = std::fs::read(std::path::Path::new(&up).join(&done.filename)).unwrap();
            if name.ends_with(".txt") { assert_eq!(stored, body); } else { assert!(!stored.windows(6).any(|w| w == b"secret")); }
            assert!(!staged.exists(), "staging reclaimed after the commit");
            let n = stored_files(&up);
            std::fs::remove_file(std::path::Path::new(&up).join(&done.filename)).unwrap();
            assert_eq!(n, 1);
        }
        // A permanent failure (corrupt image) is NOT marked retryable.
        let id = "91111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "retry", id, "bad.png", 4, "", "").await.unwrap();
        append_chunk(&data, "retry", id, 0, b"nope").await.unwrap();
        let e = finalize_chunked_upload(&data, &up, "retry", id).await.unwrap_err();
        assert!(e.downcast_ref::<FinalizeRetryable>().is_none(), "{e}");
        let _ = std::fs::remove_dir_all(&data);
    }

    /// Argon P1 upload.rs:1299: chunked uploads record the public /pub/ link like the direct
    /// upload path; records an older build stored with /files/ are handed out as /pub/.
    #[tokio::test]
    async fn r3_chunked_upload_records_public_link() {
        let (data, up) = tmp_data();
        let id = "61111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "pubber", id, "c.txt", 2, "", "").await.unwrap();
        append_chunk(&data, "pubber", id, 0, b"hi").await.unwrap();
        let done = finalize_chunked_upload(&data, &up, "pubber", id).await.unwrap();
        assert!(done.url.ends_with(&format!("/pub/{}", done.filename)), "{}", done.url);
        assert!(!done.url.contains("/files/"));
        // An index written by 0d3570d (or older) with /files/ links.
        let old = format!(r#"[{{"id":"legacy.txt","filename":"aa.txt","original_name":"a.txt","size":1,"content_type":"text/plain","url":"/cryptirc/files/aa.txt","uploaded_at":1,"status":"done","progress_bytes":1,"started_at":1,"completed_at":1,"error":"","source_conn_id":"","source_target":""}},
            {{"id":"root","filename":"bb.png","original_name":"b.png","size":1,"content_type":"image/png","url":"/files/bb.png","uploaded_at":1,"status":"done","progress_bytes":1,"started_at":1,"completed_at":1,"error":"","source_conn_id":"","source_target":""}}]"#);
        std::fs::create_dir_all(upload_index_dir(&data)).unwrap();
        std::fs::write(user_uploads_path(&data, "olduser"), old).unwrap();
        let recs = list_all_records(&data, "olduser").await;
        let urls: Vec<&str> = recs.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(urls, vec!["/cryptirc/pub/aa.txt", "/pub/bb.png"]);
        let _ = std::fs::remove_dir_all(&data);
    }

    #[tokio::test]
    async fn clear_drops_staged_chunks() {
        let (data, up) = tmp_data();
        let id = "31111111-2222-4333-8444-555555555555";
        init_chunked_upload(&data, "stager", id, "big.bin", 10, "", "").await.unwrap();
        append_chunk(&data, "stager", id, 0, b"12345").await.unwrap();
        let staged = user_inprogress_dir(&data, "stager").unwrap();
        assert!(staged.join(id).join("data").exists());
        clear_user_uploads(&data, &up, "stager").await;
        println!("R2 clear: staged dir left after clear = {}", staged.exists());
        assert!(!staged.exists());
        // A late chunk for the cleared id is refused, not re-staged.
        assert!(append_chunk(&data, "stager", id, 5, b"67890").await.is_err());
        assert!(!staged.join(id).join("data").exists());
        let _ = std::fs::remove_dir_all(&data);
    }

    #[tokio::test]
    async fn remove_record_accepts_legacy_filename_ids() {
        let (data, up) = tmp_data();
        let blob = "93d1a2b4-1c2d-4e5f-8a9b-0c1d2e3f4a5b.png";
        std::fs::write(format!("{}/{}", up, blob), b"png").unwrap();
        let r = UploadResult { url: format!("/pub/{}", blob), filename: blob.into(), original_name: "a.png".into(),
                               size: 3, content_type: "image/png".into(), is_image: true };
        record_upload(&data, "legacy", &r).await.unwrap();
        assert_eq!(list_user_uploads(&data, "legacy").await[0].id, blob);
        // Path-ish ids are still refused outright.
        for bad in ["../x.png", "a/b.png", ".hidden.png", "x..png", "", "a b.png"] {
            assert!(!remove_record(&data, &up, "legacy", bad).await, "{:?}", bad);
        }
        let removed = remove_record(&data, &up, "legacy", blob).await;
        println!("R2 remove legacy id: removed={} file_left={}", removed, std::path::Path::new(&format!("{}/{}", up, blob)).exists());
        assert!(removed);
        assert!(list_user_uploads(&data, "legacy").await.is_empty());
        assert!(!std::path::Path::new(&format!("{}/{}", up, blob)).exists());
        let _ = std::fs::remove_dir_all(&data);
    }
}

#[cfg(test)]
mod srv_b_r9_upload_tests {
    use super::*;
    use axum::extract::FromRequest;
    use futures_util::StreamExt;

    const HEAD: &str = "--XB\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\nContent-Type: text/plain\r\n\r\n";

    async fn multipart<S>(body: S) -> Multipart
    where S: futures_util::Stream<Item = std::result::Result<axum::body::Bytes, std::io::Error>> + Send + 'static {
        let req = axum::http::Request::builder().method("POST").uri("/upload")
            .header("content-type", "multipart/form-data; boundary=XB")
            .body(axum::body::Body::from_stream(body)).unwrap();
        Multipart::from_request(req, &()).await.unwrap()
    }
    fn tmpdir() -> String {
        let d = std::env::temp_dir().join(format!("cryptirc-upload-r9-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d.to_string_lossy().into_owned()
    }
    fn head() -> std::result::Result<axum::body::Bytes, std::io::Error> { Ok(axum::body::Bytes::from_static(HEAD.as_bytes())) }

    /// r9 (astra P1 main.rs:3380): a legacy upload whose body stops arriving used to wait
    /// forever, holding its reservation of the upload budget; it now fails.
    #[tokio::test]
    async fn a_stalled_legacy_upload_body_gives_up() {
        let d = tmpdir();
        let body = futures_util::stream::iter(vec![head()]).chain(futures_util::stream::pending());
        let r = tokio::time::timeout(Duration::from_secs(5), handle_upload(&d, multipart(body).await, 1 << 20)).await;
        assert!(r.is_ok(), "the upload is still waiting for its body after 5 s (holding its upload budget)");
        assert!(r.unwrap().is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    /// A body that trickles a byte now and then (never idle for long) is cut off too.
    #[tokio::test]
    async fn a_trickling_legacy_upload_body_gives_up() {
        let d = tmpdir();
        let drip = futures_util::stream::unfold((), |_| async {
            tokio::time::sleep(Duration::from_millis(100)).await;
            Some((Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"x")), ()))
        });
        let body = futures_util::stream::iter(vec![head()]).chain(drip);
        let r = tokio::time::timeout(Duration::from_secs(5), handle_upload(&d, multipart(body).await, 1 << 20)).await;
        assert!(r.is_ok(), "a trickling upload body is still being waited for after 5 s");
        assert!(r.unwrap().is_err());
        let _ = std::fs::remove_dir_all(d);
    }

    /// A body that arrives normally is stored as before.
    #[tokio::test]
    async fn a_normal_legacy_upload_still_works() {
        let d = tmpdir();
        let all = format!("{}hello\r\n--XB--\r\n", HEAD);
        let body = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(axum::body::Bytes::from(all))]);
        let r = handle_upload(&d, multipart(body).await, 1 << 20).await.unwrap();
        assert_eq!(r.size, 5);
        assert!(std::path::Path::new(&d).join(&r.filename).exists());
        let _ = std::fs::remove_dir_all(d);
    }
}
