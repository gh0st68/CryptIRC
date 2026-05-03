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

#[derive(Debug, Serialize, serde::Deserialize, Clone)]
pub struct UploadRecord {
    pub filename: String,
    pub original_name: String,
    pub size: usize,
    pub content_type: String,
    pub url: String,
    pub uploaded_at: i64,
}

fn user_uploads_path(data_dir: &str, username: &str) -> PathBuf {
    PathBuf::from(data_dir).join("uploads").join(format!("{}.json", username))
}

pub async fn record_upload(data_dir: &str, username: &str, result: &UploadResult) -> Result<()> {
    let path = user_uploads_path(data_dir, username);
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let mut records = load_user_records(&path).await;
    records.push(UploadRecord {
        filename: result.filename.clone(),
        original_name: result.original_name.clone(),
        size: result.size,
        content_type: result.content_type.clone(),
        url: result.url.clone(),
        uploaded_at: chrono::Utc::now().timestamp(),
    });
    let _ = tokio::fs::write(&path, serde_json::to_string(&records).unwrap_or_default()).await;
    Ok(())
}

pub async fn list_user_uploads(data_dir: &str, username: &str) -> Vec<UploadRecord> {
    load_user_records(&user_uploads_path(data_dir, username)).await
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
