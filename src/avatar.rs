//! User avatars. v1 (this file): an account's picture, shown next to its IRC nick to other
//! CryptIRC users of THIS instance, vouched for by this server. v2 (`remote`): an owner who
//! opts in shares it publicly with people on OTHER CryptIRC servers (announced on IRC by the
//! nick's current holder, fetched and re-encoded by the viewer's server).
//!
//! - Processing (`process_image`): PNG / JPEG / WebP up to 2 MB, decoded on the blocking
//!   pool under strict limits (at most 4096 px per side, a capped decode buffer, one image
//!   at a time, a deadline). EXIF orientation is applied, the picture is centre-cropped to a
//!   square, resized to 128 px and 48 px and re-encoded as PNG. Only those decoded pixels
//!   survive: no EXIF / ICC / text chunk and no original byte is ever stored or served.
//! - Storage (`AvatarStore`): `users/<name>/avatar.json` + `avatar-<version>-<size>.png`,
//!   inside the account's own data directory, so every path that removes an account
//!   (purge_account, the admin scripts, the stale-unverified reaper) removes these too.
//! - Serving (`route_image`): `/avatar/<token>?v=<version>[&s=48]`, for sessions of this
//!   instance only (Authorization header), `no-store`: every fetch re-checks the session, the
//!   owner's account and visibility. The token is random per avatar, not the username.
//! - Discovery (`discover`): which nicks the server vouches for. Security-critical; the
//!   rules are on that function.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{FromRef, Path as UrlPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
use image::{DynamicImage, ImageDecoder, ImageEncoder, ImageFormat};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, Semaphore};

use crate::auth::AuthManager;
use crate::irc::IrcConnection;

/// Largest accepted upload (the request body).
pub const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024;
/// Largest accepted width / height of the decoded picture.
pub const MAX_DIMENSION: u32 = 4096;
/// The decoder's output buffer may not exceed a 4096² RGBA8 picture (16-bit pictures of that
/// size are refused rather than decoded).
const MAX_DECODED_BYTES: u64 = 4096 * 4096 * 4;
/// Allocation budget handed to the decoders (progressive JPEG keeps coefficients for the
/// whole picture: ~96 MiB at 4096² plus the output).
const MAX_DECODE_ALLOC: u64 = 192 * 1024 * 1024;
pub const SIZE_LARGE: u32 = 128;
pub const SIZE_SMALL: u32 = 48;
/// Pictures processed at once, process-wide (peak memory of one 4096² decode ≈ 200 MiB).
const PROCESS_SLOTS: usize = 1;
const PROCESS_QUEUE_WAIT: Duration = Duration::from_secs(10);
const PROCESS_DEADLINE: Duration = Duration::from_secs(20);

/// Request-body cap of a discovery lookup.
pub const LOOKUP_BODY_MAX: usize = 32 * 1024;
/// Nicks per lookup request (clients batch larger member lists).
pub const LOOKUP_MAX_NICKS: usize = 300;
const NICK_MAX_BYTES: usize = 64;
const LOOKUP_RATE_MAX: u32 = 120;
const LOOKUP_RATE_WINDOW: Duration = Duration::from_secs(60);
/// How long a client may keep an answer before asking again (sent in each answer).
pub const LOOKUP_TTL_SECS: u64 = 180;
/// A nick the viewer's server returned in a WHOIS reply counts as "seen" this long.
const WHOIS_SEEN_TTL: Duration = Duration::from_secs(15 * 60);
const WHOIS_SEEN_MAX: usize = 64;

/// Uploads whose body is being received at once, process-wide, and per account.
const UPLOAD_BODIES_MAX: usize = 4;
/// A body must keep arriving (each chunk within the idle limit) and be complete in time.
const UPLOAD_IDLE: Duration = Duration::from_secs(15);
const UPLOAD_TOTAL: Duration = Duration::from_secs(60);
const PRIVATE_NO_STORE: &str = "private, no-store";
/// Capability names (or prefixes) only bouncers advertise: soju (soju.im/*, bouncer-networks),
/// pounce (causal.agency/*) and ZNC's core-only znc.in/batch / znc.in/server-time-iso. NOT
/// znc.in/playback or znc.in/self-message: Ergo — a real ircd — advertises those two.
const BOUNCER_CAP_PREFIXES: &[&str] = &["soju.im/", "causal.agency/"];
const BOUNCER_CAPS: &[&str] = &["draft/bouncer-networks", "draft/bouncer-networks-notify", "znc.in/batch", "znc.in/server-time-iso"];
/// ZNC answers CAP itself, from this server name.
const ZNC_SERVER_NAME: &str = "irc.znc.in";
/// user@host observations kept per connection.
const SEEN_HOSTS_MAX: usize = 4096;
/// Per-connection classifications that survive a web restart (see `SessionRecord`).
const SESSIONS_FILE: &str = "avatar_sessions.json";
const META_FILE: &str = "avatar.json";
/// Sanity cap when reading a stored image back (a 128 px PNG is far smaller).
const STORED_IMAGE_MAX: u64 = 512 * 1024;

// ─── Processing ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvatarError {
    Empty,
    TooLarge,
    Unsupported,
    Dimensions,
    Malformed,
    Busy,
    Slow,
    Gone,
    Internal,
}

impl AvatarError {
    fn status(self) -> StatusCode {
        match self {
            AvatarError::Empty | AvatarError::Malformed | AvatarError::Dimensions => StatusCode::BAD_REQUEST,
            AvatarError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            AvatarError::Unsupported => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            AvatarError::Busy => StatusCode::SERVICE_UNAVAILABLE,
            AvatarError::Slow => StatusCode::REQUEST_TIMEOUT,
            AvatarError::Gone => StatusCode::GONE,
            AvatarError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            AvatarError::Empty => "No image received.",
            AvatarError::TooLarge => "That image is larger than 2 MB.",
            AvatarError::Unsupported => "Use a PNG, JPEG or WebP image.",
            AvatarError::Dimensions => "That image is too large (at most 4096 × 4096 pixels).",
            AvatarError::Malformed => "That image could not be read.",
            AvatarError::Busy => "The server is busy — try again in a moment.",
            AvatarError::Slow => "The upload took too long.",
            AvatarError::Gone => "This account is being deleted.",
            AvatarError::Internal => "The avatar could not be saved.",
        }
    }
}

/// The format named by the file's own signature; the declared Content-Type is ignored.
pub fn sniff_format(b: &[u8]) -> Option<ImageFormat> {
    if b.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some(ImageFormat::Png)
    } else if b.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(ImageFormat::Jpeg)
    } else if b.len() >= 12 && &b[0..4] == b"RIFF" && &b[8..12] == b"WEBP" {
        Some(ImageFormat::WebP)
    } else {
        None
    }
}

fn classify(e: image::ImageError) -> AvatarError {
    match e {
        image::ImageError::Limits(_) => AvatarError::Dimensions,
        image::ImageError::Unsupported(_) => AvatarError::Unsupported,
        _ => AvatarError::Malformed,
    }
}

/// The re-encoded avatar: PNGs of SIZE_LARGE and SIZE_SMALL px and their content version.
pub struct Processed {
    pub large: Vec<u8>,
    pub small: Vec<u8>,
    pub version: String,
}

/// Decode, orient, crop, resize and re-encode one uploaded picture. Synchronous and
/// CPU-bound: call it through `process_in_background`.
pub fn process_image(bytes: &[u8]) -> Result<Processed, AvatarError> {
    process_image_with(bytes, MAX_DIMENSION, MAX_DECODE_ALLOC)
}

/// `process_image` with its own dimension and decoder-allocation limits (remote pictures
/// use smaller ones, `remote::REMOTE_MAX_DIMENSION`).
pub fn process_image_with(bytes: &[u8], max_dimension: u32, max_alloc: u64) -> Result<Processed, AvatarError> {
    let max_decoded = u64::from(max_dimension) * u64::from(max_dimension) * 4;
    if bytes.is_empty() {
        return Err(AvatarError::Empty);
    }
    if bytes.len() > MAX_UPLOAD_BYTES {
        return Err(AvatarError::TooLarge);
    }
    let format = sniff_format(bytes).ok_or(AvatarError::Unsupported)?;
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(max_dimension);
    limits.max_image_height = Some(max_dimension);
    limits.max_alloc = Some(max_alloc);
    reader.limits(limits);
    // Only the header has been read here; the dimensions are checked before any pixel
    // buffer exists.
    let mut decoder = reader.into_decoder().map_err(classify)?;
    let (w, h) = decoder.dimensions();
    if w == 0 || h == 0 || w > max_dimension || h > max_dimension || decoder.total_bytes() > max_decoded.min(MAX_DECODED_BYTES) {
        return Err(AvatarError::Dimensions);
    }
    let orientation = decoder.orientation().unwrap_or(image::metadata::Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder).map_err(classify)?;
    img.apply_orientation(orientation);
    let (w, h) = (img.width(), img.height());
    let side = w.min(h);
    let square = if w == h { img } else { img.crop_imm((w - side) / 2, (h - side) / 2, side, side) };
    // Large pictures are first area-averaged down to 2× the large size, then both sizes are
    // resampled from that (fast, and no aliasing from a single huge step).
    let base = if side > SIZE_LARGE * 2 { square.thumbnail_exact(SIZE_LARGE * 2, SIZE_LARGE * 2) } else { square };
    let large = base.resize_exact(SIZE_LARGE, SIZE_LARGE, image::imageops::FilterType::Lanczos3).into_rgba8();
    let small = base.resize_exact(SIZE_SMALL, SIZE_SMALL, image::imageops::FilterType::Lanczos3).into_rgba8();
    let large = encode_png(&large)?;
    let small = encode_png(&small)?;
    let version = content_version(&large);
    Ok(Processed { large, small, version })
}

/// PNG with no ancillary chunks (no text, no ICC, no EXIF); RGB when fully opaque.
fn encode_png(img: &image::RgbaImage) -> Result<Vec<u8>, AvatarError> {
    use image::codecs::png::{CompressionType, FilterType, PngEncoder};
    let (w, h) = img.dimensions();
    let mut out = Vec::new();
    let enc = PngEncoder::new_with_quality(&mut out, CompressionType::Best, FilterType::Adaptive);
    let res = if img.pixels().all(|p| p.0[3] == 255) {
        let rgb: Vec<u8> = img.pixels().flat_map(|p| [p.0[0], p.0[1], p.0[2]]).collect();
        enc.write_image(&rgb, w, h, image::ExtendedColorType::Rgb8)
    } else {
        enc.write_image(img.as_raw(), w, h, image::ExtendedColorType::Rgba8)
    };
    res.map_err(|_| AvatarError::Internal)?;
    Ok(out)
}

fn content_version(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes).iter().take(8).map(|b| format!("{:02x}", b)).collect()
}

/// Run `process_image` on the blocking pool: one picture at a time process-wide (waiting
/// at most PROCESS_QUEUE_WAIT for the slot), answered within PROCESS_DEADLINE. The slot
/// stays held by the blocking task until it really returns, so a slow decode past the
/// deadline still counts against the limit. A panicking decoder is reported as Malformed.
pub async fn process_in_background(slots: &Arc<Semaphore>, bytes: Vec<u8>) -> Result<Processed, AvatarError> {
    let permit = tokio::time::timeout(PROCESS_QUEUE_WAIT, slots.clone().acquire_owned())
        .await
        .map_err(|_| AvatarError::Busy)?
        .map_err(|_| AvatarError::Internal)?;
    let task = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        process_image(&bytes)
    });
    match tokio::time::timeout(PROCESS_DEADLINE, task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(AvatarError::Malformed),
        Err(_) => Err(AvatarError::Busy),
    }
}

// ─── Storage ──────────────────────────────────────────────────────────────────

/// `users/<name>/avatar.json`. `token` names the avatar in URLs; `v` is the content
/// version of the stored pictures; `visible` is the owner's "show my avatar to other
/// CryptIRC users" choice (default on). `share` is "share my avatar with people on other
/// CryptIRC servers" (public link `pub_id`): on for an avatar uploaded with this version,
/// off for one saved before it (its owner never agreed to a public link). `pub_id` is
/// random, empty while not sharing, and new each time sharing is turned on again.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvatarMeta {
    pub token: String,
    pub v: String,
    #[serde(default = "default_visible")]
    pub visible: bool,
    #[serde(default)]
    pub share: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub pub_id: String,
}

fn default_visible() -> bool {
    true
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_token(t: &str) -> bool {
    is_lower_hex(t, 32)
}
fn valid_version(v: &str) -> bool {
    is_lower_hex(v, 16)
}

fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// The version of a stored picture file name `avatar-<v>-<size>.png`.
fn image_file_version(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("avatar-")?.strip_suffix(".png")?;
    let (v, size) = rest.split_once('-')?;
    (valid_version(v) && (size == "128" || size == "48")).then_some(v)
}

/// Is this CAP line (its source and capability list) a bouncer's?
pub fn cap_line_names_a_bouncer(source: Option<&str>, caps: &str) -> bool {
    source.map_or(false, |s| s.eq_ignore_ascii_case(ZNC_SERVER_NAME)) || caps_name_a_bouncer(caps)
}

/// Does this CAP LS / NEW capability list name a bouncer?
pub fn caps_name_a_bouncer(caps: &str) -> bool {
    caps.split_whitespace().any(|cap| {
        let name = cap.split('=').next().unwrap_or(cap).to_ascii_lowercase();
        BOUNCER_CAP_PREFIXES.iter().any(|p| name.starts_with(p)) || BOUNCER_CAPS.contains(&name.as_str())
    })
}

/// Does this ISUPPORT (005) line name a bouncer (BOUNCER_NETID)?
pub fn isupport_names_a_bouncer(params: &[String]) -> bool {
    params.iter().any(|t| t.split('=').next().map_or(false, |k| k.eq_ignore_ascii_case("BOUNCER_NETID")))
}

/// Classify a connection from its own CAP LS / NEW lines (irc.rs): `behind_bouncer` once any
/// of them is a bouncer's, `cap_ls_done` at the final line of a LIVE CAP LS listing. A
/// replayed line can only make it more restrictive (mark a bouncer): earlier fragments of a
/// multiline listing may have been evicted from the replay ring, so a replayed final
/// fragment proves nothing (codex re-check M avatar.rs:383). After a web restart
/// "negotiated" comes only from the continuity-checked record or a live negotiation. Both
/// flags are per live connection (reset when it reconnects — ipc_client), so one account's
/// connection can never change how another's is classified.
pub fn note_cap_line(c: &mut IrcConnection, source: Option<&str>, sub: &str, multiline: bool, caps: &str, replayed: bool) {
    if cap_line_names_a_bouncer(source, caps) {
        c.behind_bouncer = true;
    }
    if sub == "LS" && !multiline && !replayed {
        c.cap_ls_done = true;
    }
}

/// What an Attach replay showed about one connection's irc-core session.
/// `first_backlog`: whether its first replayed line had NOT been delivered to a web before.
/// The ring evicts oldest-first, so a first line that WAS delivered proves that no line
/// received while no web was attached was dropped. `restarted`: such a (backlog) line was a
/// session start (RPL_WELCOME, CAP LS) — irc-core reconnected while no web was attached.
/// `no_backlog_info`: a line came from an irc-core that does not say (recv_ts 0).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReplayEvidence {
    pub first_backlog: Option<bool>,
    pub restarted: bool,
    pub no_backlog_info: bool,
}

fn replay_evidence() -> &'static DashMap<String, ReplayEvidence> {
    static M: std::sync::OnceLock<DashMap<String, ReplayEvidence>> = std::sync::OnceLock::new();
    M.get_or_init(DashMap::new)
}
/// A new Attach cycle starts (ipc_client): forget the previous cycle's evidence.
pub fn replay_cycle_start() {
    replay_evidence().clear();
}
/// One replayed RawLine of `conn_id` (irc.rs dispatch_line, replayed == true).
pub fn note_replayed_line(conn_id: &str, backlog: bool, recv_ts: i64, command: &str, params: &[String]) {
    let map = replay_evidence();
    if map.len() > 65536 && !map.contains_key(conn_id) {
        return;
    }
    let mut e = map.entry(conn_id.to_string()).or_default();
    if recv_ts <= 0 {
        e.no_backlog_info = true;
    }
    if e.first_backlog.is_none() {
        e.first_backlog = Some(backlog);
    }
    let session_start = command == "001" || (command == "CAP" && params.get(1).map_or(false, |s| s.eq_ignore_ascii_case("LS")));
    if backlog && session_start {
        e.restarted = true;
    }
}
pub fn take_replay_evidence(conn_id: &str) -> Option<ReplayEvidence> {
    replay_evidence().remove(conn_id).map(|(_, e)| e)
}

/// Does an Attach replay prove that the irc-core session is the one this process knew (replay
/// information present, its first line delivered before, no session start while no web was
/// attached)? Missing evidence → no.
pub fn replay_proves_session(ev: Option<ReplayEvidence>) -> bool {
    ev.map_or(false, |e| !e.no_backlog_info && !e.restarted && e.first_backlog == Some(false))
}

/// At AttachComplete, for one connection: drop what remote avatars learned unless the replay
/// proves the same irc-core session. True when dropped.
pub fn remote_after_attach(c: &mut IrcConnection, ev: Option<ReplayEvidence>) -> bool {
    if replay_proves_session(ev) {
        return false;
    }
    c.avx.drop_unproven();
    true
}

/// May `record` be restored for a connection after a web restart? Some(behind_bouncer) only
/// when the record's owner and dial endpoint match the live connection's, and the replay
/// proves the same irc-core session: replay information present, its first line already
/// delivered before, and no session start among the lines received while no web was attached.
pub fn restorable(record: Option<&SessionRecord>, owner: Option<&str>, endpoint: Option<(&str, u16)>, ev: Option<ReplayEvidence>) -> Option<bool> {
    let (record, ev) = (record?, ev?);
    if owner? != record.owner {
        return None;
    }
    let (host, port) = endpoint?;
    if canonical_host(host) != record.host || port != record.port {
        return None;
    }
    if ev.no_backlog_info || ev.restarted || ev.first_backlog != Some(false) {
        return None;
    }
    Some(record.bouncer)
}

/// At AttachComplete: give each connection the irc-core session still has its recorded
/// classification back, when `restorable` allows; otherwise drop the record (fail closed).
pub async fn restore_after_attach(state: &crate::AppState, seen: &HashSet<String>) {
    let mut sync_meta: Vec<(String, Arc<Mutex<IrcConnection>>)> = Vec::new();
    for conn_id in seen {
        let ev = take_replay_evidence(conn_id);
        let Some(conn) = state.connections.get(conn_id).map(|c| c.clone()) else { continue };
        let owner = state.conn_owners.get(conn_id).map(|o| o.value().clone());
        let record = state.avatars.session(conn_id);
        let mut c = conn.lock().await;
        c.replay_view = None; // the replay is over (IrcConnection::replay_view)
        // Remote avatars (codex astra M ipc_client.rs:475): announces learned before this
        // Attach — or from its replay — are kept only when the replay proves the same
        // irc-core session; the IRC connection may have restarted while no link was up (its
        // lifecycle events are not replayed) and a nick changed hands.
        let had_meta = c.avx.meta2_on || c.avx.meta2_offered || record.as_ref().map_or(false, |r| r.meta2);
        if remote_after_attach(&mut c, ev) {
            state.avatar_remote.forget_conn(conn_id);
            // …but never leave draft/metadata-2 off for good: ask again (ACK → SUB / SET /
            // SYNC, so publication and opt-out deletion keep working; NAK → not offered).
            let disabled = c.cfg.disabled_caps.iter().any(|d| d == remote::META_CAP);
            let live = c.connected && c.registered;
            if remote::meta_recheck(had_meta, true, live, disabled) {
                c.avx.meta2_offered = true;
                c.avx.meta2_requested = true;
                let _ = c.send_raw(&format!("CAP REQ :{}\r\n", remote::META_CAP)).await;
            }
        }
        if c.cap_ls_done {
            // Metadata-2 kept across this Attach: sync our value too (a change made while the
            // link was down could not be sent then).
            if c.avx.meta2_on {
                if let Some(o) = owner.clone() {
                    sync_meta.push((o, conn.clone()));
                }
            }
            continue; // this process saw it negotiate (backlog) — already classified
        }
        let endpoint = c.dial_endpoint.clone();
        let decision = restorable(record.as_ref(), owner.as_deref(), endpoint.as_ref().map(|(h, p)| (h.as_str(), *p)), ev);
        if apply_restore(&mut c, decision) {
            c.avx.meta2_on = record.as_ref().map_or(false, |r| r.meta2);
            // Metadata-2 is active again: sync our value (it may have changed while no web
            // was attached — a withdrawal must reach IRC).
            if c.avx.meta2_on {
                if let Some(o) = owner.clone() {
                    sync_meta.push((o, conn.clone()));
                }
            }
        } else {
            drop(c);
            if record.is_some() {
                state.avatars.forget_session(conn_id);
            }
        }
    }
    replay_evidence().clear();
    for (owner, conn) in sync_meta {
        remote::meta_sync(state, &owner, &conn).await;
    }
}

/// Apply a `restorable` decision to a live connection. A saved bouncer mark is kept, and so
/// is one replay added (`behind_bouncer` is only ever OR-ed here). False: not restored.
pub fn apply_restore(c: &mut IrcConnection, decision: Option<bool>) -> bool {
    match decision {
        Some(bouncer) if c.registered && c.connected => {
            c.cap_ls_done = true;
            c.behind_bouncer |= bouncer;
            true
        }
        _ => false,
    }
}

pub struct AvatarStore {
    users_dir: PathBuf,
    enabled: AtomicBool,
    by_user: DashMap<String, AvatarMeta>,
    by_token: DashMap<String, String>,
    /// pub_id → owner, for owners sharing publicly (remote avatars).
    by_pub: DashMap<String, String>,
    /// CRYPTIRC_BASE_URL when other servers can reach it (remote::announce_base), else None:
    /// nothing is announced.
    public_base: std::sync::RwLock<Option<String>>,
    locks: DashMap<String, Arc<Mutex<()>>>,
    pub slots: Arc<Semaphore>,
    lookup_rate: DashMap<String, (Instant, u32)>,
    /// Upload bodies being received: process-wide slots, and the accounts receiving one.
    upload_bodies: Arc<Semaphore>,
    uploading: Arc<DashMap<String, ()>>,
    /// conn_id → what that connection negotiated (see `SessionRecord`), and where it is kept.
    sessions: Arc<DashMap<String, SessionRecord>>,
    sessions_file: Option<PathBuf>,
    sessions_write_pending: Arc<AtomicBool>,
}

/// What one connection negotiated (CAP negotiation completed; behind a bouncer or not), kept
/// so a web-only restart — irc-core keeps the IRC session — does not switch its avatars off
/// until the next IRC reconnect. Keyed by conn_id, with the owner and the dial endpoint,
/// which must still match. Written only after a LIVE CAP negotiation on that connection;
/// only for a conn_id the owner's saved networks
/// name (conn_owners — so bounded by them); cleared on Dial, on every (re)connect or end of
/// the session, on a network edit or removal and on account purge. After a restart it is
/// trusted only when the replay proves the SAME irc-core session (`restorable`); anything
/// missing → not restored (no match until the connection negotiates again).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub owner: String,
    pub host: String,
    pub port: u16,
    pub bouncer: bool,
    /// The session negotiated draft/metadata-2 (remote avatars).
    #[serde(default)]
    pub meta2: bool,
}

impl AvatarStore {
    pub fn new(data_dir: &str, enabled: bool) -> Self {
        AvatarStore {
            users_dir: PathBuf::from(data_dir).join("users"),
            enabled: AtomicBool::new(enabled),
            by_user: DashMap::new(),
            by_token: DashMap::new(),
            by_pub: DashMap::new(),
            public_base: std::sync::RwLock::new(None),
            locks: DashMap::new(),
            slots: Arc::new(Semaphore::new(PROCESS_SLOTS)),
            lookup_rate: DashMap::new(),
            upload_bodies: Arc::new(Semaphore::new(UPLOAD_BODIES_MAX)),
            uploading: Arc::new(DashMap::new()),
            sessions: Arc::new(DashMap::new()),
            sessions_file: None,
            sessions_write_pending: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn session(&self, conn_id: &str) -> Option<SessionRecord> {
        self.sessions.get(conn_id).map(|r| r.clone())
    }
    /// A CAP negotiation completed on `conn_id` (owned by `owner`, dialing `endpoint`).
    pub fn record_session(&self, conn_id: &str, owner: &str, endpoint: (&str, u16), bouncer: bool, conn_owners: &DashMap<String, String>) {
        if conn_owners.get(conn_id).map_or(true, |o| o.value().as_str() != owner) {
            return;
        }
        let rec = SessionRecord { owner: owner.to_string(), host: canonical_host(endpoint.0), port: endpoint.1, bouncer, meta2: false };
        if rec.host.is_empty() {
            return;
        }
        let changed = self.sessions.insert(conn_id.to_string(), rec.clone()) != Some(rec);
        let before = self.sessions.len();
        self.sessions.retain(|cid, r| conn_owners.get(cid).map_or(false, |o| o.value() == &r.owner));
        if changed || self.sessions.len() != before {
            self.persist_sessions();
        }
    }
    /// A later bouncer sign on `conn_id` (CAP NEW, ISUPPORT BOUNCER_NETID).
    pub fn mark_session_bouncer(&self, conn_id: &str) {
        let changed = match self.sessions.get_mut(conn_id) {
            Some(mut r) if !r.bouncer => {
                r.bouncer = true;
                true
            }
            _ => false,
        };
        if changed {
            self.persist_sessions();
        }
    }
    /// The session on `conn_id` negotiated draft/metadata-2 (remote avatars): mark the record,
    /// or create one when a reattach dropped it (codex astra re-check 2 L avatar.rs:448). A
    /// record created here knows nothing about the connection's classification, so it says
    /// `bouncer: true` — unknown counts as a bouncer — until a live CAP LS records the truth.
    pub fn ensure_session_meta2(&self, conn_id: &str, owner: &str, endpoint: (&str, u16), conn_owners: &DashMap<String, String>) {
        if self.sessions.contains_key(conn_id) {
            self.mark_session_meta2(conn_id);
            return;
        }
        if conn_owners.get(conn_id).map_or(true, |o| o.value().as_str() != owner) {
            return;
        }
        let host = canonical_host(endpoint.0);
        if host.is_empty() {
            return;
        }
        self.sessions.insert(conn_id.to_string(), SessionRecord { owner: owner.to_string(), host, port: endpoint.1, bouncer: true, meta2: true });
        self.persist_sessions();
    }
    /// The session on `conn_id` negotiated draft/metadata-2 (remote avatars).
    pub fn mark_session_meta2(&self, conn_id: &str) {
        let changed = match self.sessions.get_mut(conn_id) {
            Some(mut r) if !r.meta2 => {
                r.meta2 = true;
                true
            }
            _ => false,
        };
        if changed {
            self.persist_sessions();
        }
    }
    pub fn forget_session(&self, conn_id: &str) {
        if self.sessions.remove(conn_id).is_some() {
            self.persist_sessions();
        }
    }
    pub fn forget_owner_sessions(&self, owner: &str) {
        let before = self.sessions.len();
        self.sessions.retain(|_, r| r.owner != owner);
        if self.sessions.len() != before {
            self.persist_sessions();
        }
    }
    /// Keep only records whose conn_id a saved network of the same owner still names.
    pub fn prune_sessions(&self, conn_owners: &DashMap<String, String>) {
        let before = self.sessions.len();
        self.sessions.retain(|cid, r| conn_owners.get(cid).map_or(false, |o| o.value() == &r.owner));
        if self.sessions.len() != before {
            self.persist_sessions();
        }
    }
    fn persist_sessions(&self) {
        let Some(path) = self.sessions_file.clone() else { return };
        if self.sessions_write_pending.swap(true, Ordering::AcqRel) {
            return;
        }
        let Ok(rt) = tokio::runtime::Handle::try_current() else {
            self.sessions_write_pending.store(false, Ordering::Release);
            return;
        };
        let (sessions, pending) = (self.sessions.clone(), self.sessions_write_pending.clone());
        rt.spawn(async move {
            tokio::time::sleep(Duration::from_millis(500)).await;
            pending.store(false, Ordering::Release);
            let snapshot: HashMap<String, SessionRecord> = sessions.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
            if let Ok(body) = serde_json::to_vec(&snapshot) {
                let _ = crate::write_user_file_atomic(&path, &body).await;
            }
        });
    }

    /// The store with every account's saved avatar indexed (startup).
    pub async fn load(data_dir: &str, enabled: bool) -> Self {
        let mut store = Self::new(data_dir, enabled);
        let sessions_file = PathBuf::from(data_dir).join(SESSIONS_FILE);
        if let Ok(bytes) = tokio::fs::read(&sessions_file).await {
            if let Ok(saved) = serde_json::from_slice::<HashMap<String, SessionRecord>>(&bytes) {
                // Pruned against the saved networks once conn_owners is seeded (main).
                for (cid, rec) in saved.into_iter().take(65536) {
                    if crate::auth::validate_uuid(&cid).as_deref() == Some(cid.as_str()) {
                        store.sessions.insert(cid, rec);
                    }
                }
            }
        }
        store.sessions_file = Some(sessions_file);
        let mut rd = match tokio::fs::read_dir(&store.users_dir).await {
            Ok(rd) => rd,
            Err(_) => return store,
        };
        while let Ok(Some(entry)) = rd.next_entry().await {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else { continue };
            if !crate::auth::is_safe_username(&name) || name != name.to_lowercase() {
                continue;
            }
            if !entry.file_type().await.map_or(false, |t| t.is_dir()) {
                continue;
            }
            if let Some(meta) = read_meta(&entry.path().join(META_FILE)).await {
                store.by_token.insert(meta.token.clone(), name.clone());
                if meta.share {
                    store.by_pub.insert(meta.pub_id.clone(), name.clone());
                }
                store.by_user.insert(name, meta);
            }
        }
        store
    }

    pub fn enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
    pub fn set_enabled(&self, on: bool) {
        self.enabled.store(on, Ordering::Relaxed);
    }
    pub fn meta(&self, user: &str) -> Option<AvatarMeta> {
        self.by_user.get(user).map(|m| m.clone())
    }
    pub fn owner_of(&self, token: &str) -> Option<String> {
        self.by_token.get(token).map(|u| u.clone())
    }
    pub fn owner_of_pub(&self, pub_id: &str) -> Option<String> {
        self.by_pub.get(pub_id).map(|u| u.clone())
    }
    pub fn set_public_base(&self, base: Option<String>) {
        if let Ok(mut b) = self.public_base.write() {
            *b = base;
        }
    }
    pub fn public_base(&self) -> Option<String> {
        self.public_base.read().ok().and_then(|b| b.clone())
    }
    /// The public URL `user` shares right now: avatars on, an avatar, visible, sharing on and
    /// a public base URL. (The account's own state — disabled, being deleted — is checked by
    /// the callers: remote::share_url.)
    pub fn public_url(&self, user: &str) -> Option<String> {
        if !self.enabled() {
            return None;
        }
        let base = self.public_base()?;
        let m = self.meta(user)?;
        (m.visible && m.share && valid_token(&m.pub_id)).then(|| format!("{}/avatar/pub/{}-{}.png", base, m.pub_id, m.v))
    }
    fn user_dir(&self, user: &str) -> PathBuf {
        self.users_dir.join(user)
    }
    fn image_path(&self, user: &str, v: &str, size: u32) -> PathBuf {
        self.user_dir(user).join(format!("avatar-{}-{}.png", v, size))
    }

    /// This account's avatar lock (serialises save / remove / visibility changes).
    fn user_lock(&self, user: &str) -> Arc<Mutex<()>> {
        self.locks.entry(user.to_string()).or_insert_with(|| Arc::new(Mutex::new(()))).clone()
    }
    /// Drop the lock entry once nobody holds or waits for it.
    fn release_lock(&self, user: &str, lock: Arc<Mutex<()>>) {
        drop(lock);
        self.locks.remove_if(user, |_, l| Arc::strong_count(l) == 1);
    }

    /// Store a processed avatar for `user` (replacing any previous one). The token and the
    /// visibility choice are kept across replacements. `epoch` is the account generation
    /// (AuthManager::account_epoch) when the request was accepted: an upload that outlives
    /// its account (deleted, perhaps re-registered under the same name meanwhile) is refused
    /// — checked before writing and again before committing.
    /// `share_first`: a FIRST avatar is shared with other servers only when the owner agreed
    /// in the upload flow (a replacement keeps the owner's choice).
    pub async fn save(&self, auth: &AuthManager, user: &str, epoch: u64, p: Processed, share_first: bool) -> Result<AvatarMeta, AvatarError> {
        if !crate::auth::is_safe_username(user) {
            return Err(AvatarError::Gone);
        }
        let lock = self.user_lock(user);
        let guard = lock.lock().await;
        let out = self.save_locked(auth, user, epoch, p, share_first).await;
        drop(guard);
        self.release_lock(user, lock);
        out
    }

    async fn save_locked(&self, auth: &AuthManager, user: &str, epoch: u64, p: Processed, share_first: bool) -> Result<AvatarMeta, AvatarError> {
        if !auth.account_ticket_live(user, epoch) || !auth.account_exists(user).await {
            return Err(AvatarError::Gone);
        }
        let dir = self.user_dir(user);
        tokio::fs::create_dir_all(&dir).await.map_err(|_| AvatarError::Internal)?;
        // The file on disk is authoritative: an account removed and re-created behind our
        // back (admin scripts) must not inherit the old index entry's token or choice.
        let prev = read_meta(&dir.join(META_FILE)).await;
        if let Some(stale) = self.meta(user) {
            if prev.as_ref().map_or(true, |p| p.token != stale.token) {
                self.by_token.remove(&stale.token);
                self.by_pub.remove(&stale.pub_id);
                self.by_user.remove(user);
            }
        }
        // A first avatar is shared only with the owner's consent given in the upload flow
        // (codex astra M app.js:9931: never public before the owner saw what sharing means);
        // a replacement keeps the owner's choice and public id.
        let (share, pub_id) = match &prev {
            Some(m) if m.share => (true, if valid_token(&m.pub_id) { m.pub_id.clone() } else { new_token() }),
            Some(_) => (false, String::new()),
            None if share_first => (true, new_token()),
            None => (false, String::new()),
        };
        let meta = AvatarMeta {
            token: prev.as_ref().map(|m| m.token.clone()).unwrap_or_else(new_token),
            v: p.version.clone(),
            visible: prev.as_ref().map_or(true, |m| m.visible),
            share,
            pub_id,
        };
        let json = serde_json::to_vec(&meta).map_err(|_| AvatarError::Internal)?;
        for (bytes, size) in [(&p.large, SIZE_LARGE), (&p.small, SIZE_SMALL)] {
            crate::write_user_file_atomic(&self.image_path(user, &meta.v, size), bytes)
                .await
                .map_err(|_| AvatarError::Internal)?;
        }
        crate::write_user_file_atomic(&dir.join(META_FILE), &json).await.map_err(|_| AvatarError::Internal)?;
        // A deletion that began while we wrote: leave nothing behind (purge_account's own
        // pass may have run before our files landed). Under this account's avatar lock, so
        // the files removed here can only be the ones this call wrote.
        if !auth.account_ticket_live(user, epoch) {
            self.remove_files(user, None).await;
            return Err(AvatarError::Gone);
        }
        if let Some(old) = &prev {
            if old.token != meta.token {
                self.by_token.remove(&old.token);
            }
            if old.pub_id != meta.pub_id {
                self.by_pub.remove(&old.pub_id);
            }
        }
        self.by_token.insert(meta.token.clone(), user.to_string());
        if meta.share {
            self.by_pub.insert(meta.pub_id.clone(), user.to_string());
        }
        self.by_user.insert(user.to_string(), meta.clone());
        self.remove_files(user, Some(&meta.v)).await;
        Ok(meta)
    }

    /// Remove `user`'s avatar (index, metadata and every picture). True if there was one.
    pub async fn remove(&self, user: &str) -> bool {
        if !crate::auth::is_safe_username(user) {
            return false;
        }
        let lock = self.user_lock(user);
        let guard = lock.lock().await;
        let had = match self.by_user.remove(user) {
            Some((_, m)) => {
                self.by_token.remove(&m.token);
                self.by_pub.remove(&m.pub_id);
                true
            }
            None => false,
        };
        let files = self.remove_files(user, None).await;
        drop(guard);
        self.release_lock(user, lock);
        had || files
    }

    /// Account deletion: forget and delete the avatar (purge_account, both passes).
    pub async fn purge_user(&self, user: &str) {
        self.remove(user).await;
        self.lookup_rate.remove(user);
        self.forget_owner_sessions(user);
    }

    /// The owner's "show my avatar to other CryptIRC users" choice. None without an avatar.
    pub async fn set_visible(&self, user: &str, visible: bool) -> Option<AvatarMeta> {
        if !crate::auth::is_safe_username(user) {
            return None;
        }
        let lock = self.user_lock(user);
        let guard = lock.lock().await;
        let out = match self.meta(user) {
            Some(mut meta) => {
                meta.visible = visible;
                match serde_json::to_vec(&meta) {
                    Ok(json) if crate::write_user_file_atomic(&self.user_dir(user).join(META_FILE), &json).await.is_ok() => {
                        self.by_user.insert(user.to_string(), meta.clone());
                        Some(meta)
                    }
                    _ => None,
                }
            }
            None => None,
        };
        drop(guard);
        self.release_lock(user, lock);
        out
    }

    /// The owner's "share my avatar with people on other CryptIRC servers" choice. Turning it
    /// off discards the public id (the old link stops working for good); turning it on
    /// mints a new one. None without an avatar.
    pub async fn set_share(&self, user: &str, share: bool) -> Option<AvatarMeta> {
        if !crate::auth::is_safe_username(user) {
            return None;
        }
        let lock = self.user_lock(user);
        let guard = lock.lock().await;
        let out = match self.meta(user) {
            Some(mut meta) => {
                let old = meta.pub_id.clone();
                meta.share = share;
                meta.pub_id = if share { if valid_token(&old) { old.clone() } else { new_token() } } else { String::new() };
                match serde_json::to_vec(&meta) {
                    Ok(json) if crate::write_user_file_atomic(&self.user_dir(user).join(META_FILE), &json).await.is_ok() => {
                        if old != meta.pub_id {
                            self.by_pub.remove(&old);
                        }
                        if meta.share {
                            self.by_pub.insert(meta.pub_id.clone(), user.to_string());
                        }
                        self.by_user.insert(user.to_string(), meta.clone());
                        Some(meta)
                    }
                    _ => None,
                }
            }
            None => None,
        };
        drop(guard);
        self.release_lock(user, lock);
        out
    }

    /// Delete the metadata (unless `keep` is given) and every picture whose version is not
    /// `keep`, plus temp files of interrupted writes. True if anything was removed.
    async fn remove_files(&self, user: &str, keep: Option<&str>) -> bool {
        let dir = self.user_dir(user);
        let mut removed = false;
        if keep.is_none() {
            removed |= tokio::fs::remove_file(dir.join(META_FILE)).await.is_ok();
        }
        if let Ok(mut rd) = tokio::fs::read_dir(&dir).await {
            while let Ok(Some(entry)) = rd.next_entry().await {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if let Some(v) = image_file_version(name) {
                    if keep != Some(v) {
                        removed |= tokio::fs::remove_file(entry.path()).await.is_ok();
                    }
                } else if name.starts_with("avatar") && name.contains(".tmp.") {
                    let _ = tokio::fs::remove_file(entry.path()).await;
                }
            }
        }
        removed
    }

    pub async fn read_image(&self, user: &str, v: &str, size: u32) -> Option<Vec<u8>> {
        if !valid_version(v) || !crate::auth::is_safe_username(user) {
            return None;
        }
        let path = self.image_path(user, v, size);
        let md = tokio::fs::symlink_metadata(&path).await.ok()?;
        if !md.is_file() || md.len() > STORED_IMAGE_MAX {
            return None;
        }
        tokio::fs::read(&path).await.ok()
    }

    /// Per-account sliding window for discovery lookups.
    pub fn lookup_rate_ok(&self, user: &str) -> bool {
        let now = Instant::now();
        if self.lookup_rate.len() > 4096 {
            self.lookup_rate.retain(|_, (start, _)| now.duration_since(*start) <= LOOKUP_RATE_WINDOW);
        }
        let mut e = self.lookup_rate.entry(user.to_string()).or_insert((now, 0));
        let (start, count) = &mut *e;
        if now.duration_since(*start) > LOOKUP_RATE_WINDOW {
            *start = now;
            *count = 0;
        }
        *count += 1;
        *count <= LOOKUP_RATE_MAX
    }
}

async fn read_meta(path: &std::path::Path) -> Option<AvatarMeta> {
    let md = tokio::fs::symlink_metadata(path).await.ok()?;
    if !md.is_file() || md.len() > 4096 {
        return None;
    }
    let mut meta: AvatarMeta = serde_json::from_slice(&tokio::fs::read(path).await.ok()?).ok()?;
    if !(meta.pub_id.is_empty() || valid_token(&meta.pub_id)) {
        return None;
    }
    if !meta.share || meta.pub_id.is_empty() {
        meta.share = false;
        meta.pub_id.clear();
    }
    (valid_token(&meta.token) && valid_version(&meta.v)).then_some(meta)
}

// ─── Discovery ────────────────────────────────────────────────────────────────

/// Nicks the viewer's own server returned in a WHOIS reply (RPL_WHOISUSER) recently, kept
/// on the connection (irc.rs). Bounded and time-limited.
#[derive(Debug, Default, Clone)]
pub struct SeenNicks(VecDeque<(String, Instant)>);

impl SeenNicks {
    pub fn note(&mut self, nick: &str) {
        if nick.is_empty() || nick.len() > NICK_MAX_BYTES {
            return;
        }
        let now = Instant::now();
        self.0.retain(|(n, at)| n != nick && now.duration_since(*at) < WHOIS_SEEN_TTL);
        self.0.push_back((nick.to_string(), now));
        while self.0.len() > WHOIS_SEEN_MAX {
            self.0.pop_front();
        }
    }
    pub fn fresh(&self) -> impl Iterator<Item = &str> {
        let now = Instant::now();
        self.0.iter().filter(move |(_, at)| now.duration_since(*at) < WHOIS_SEEN_TTL).map(|(n, _)| n.as_str())
    }
    pub fn clear(&mut self) {
        self.0.clear();
    }
}

/// The server host the discovery rule compares: trimmed, no trailing dot, no IPv6 brackets,
/// lowercase. Ports are not part of it.
pub fn canonical_host(host: &str) -> String {
    let h = host.trim().trim_end_matches('.');
    let h = h.strip_prefix('[').and_then(|x| x.strip_suffix(']')).unwrap_or(h);
    h.to_lowercase()
}

/// The host this connection really dials (the daemon's report, else what was dialed, else
/// the config as first seen) — never the editable saved config.
pub fn conn_host(c: &IrcConnection) -> String {
    canonical_host(c.dial_endpoint.as_ref().map_or(c.cfg.server.as_str(), |(s, _)| s.as_str()))
}

fn plausible_nick(n: &str) -> bool {
    !n.is_empty() && n.len() <= NICK_MAX_BYTES && !n.chars().any(|c| c.is_whitespace() || c.is_control() || c == ',')
}

/// user@host this connection's server showed for each nick (JOIN / PRIVMSG / NOTICE / PART /
/// … prefixes, userhost-in-names, WHO, WHOIS, CHGHOST), newest wins. Keyed by the ASCII-
/// lowercased nick (the narrowest IRC fold); bounded.
#[derive(Debug, Default, Clone)]
pub struct SeenHosts {
    map: HashMap<String, (String, String, u64)>,
    seq: u64,
}

impl SeenHosts {
    pub fn note(&mut self, nick: &str, userhost: &str) {
        let nick = cryptirc::ircproto::strip_pfx(nick);
        if !plausible_nick(nick) || userhost.len() > 256 || !userhost.contains('@') || userhost.contains(' ') {
            return;
        }
        self.seq += 1;
        self.map.insert(nick.to_ascii_lowercase(), (nick.to_string(), userhost.to_string(), self.seq));
        if self.map.len() > SEEN_HOSTS_MAX {
            let mut seqs: Vec<u64> = self.map.values().map(|v| v.2).collect();
            seqs.sort_unstable();
            let cut = seqs[SEEN_HOSTS_MAX / 4];
            self.map.retain(|_, v| v.2 >= cut);
        }
    }
    pub fn forget(&mut self, nick: &str) {
        self.map.remove(&nick.to_ascii_lowercase());
    }
    /// The newest user@host shown for this nick (ASCII-lowercased match).
    pub fn get(&self, nick: &str) -> Option<&str> {
        self.map.get(&nick.to_ascii_lowercase()).map(|v| v.1.as_str())
    }
    pub fn clear(&mut self) {
        self.map.clear();
    }
    /// The newest observation per nick under `fold`.
    fn latest_by(&self, fold: impl Fn(&str) -> String) -> HashMap<String, String> {
        let mut out: HashMap<String, (String, u64)> = HashMap::new();
        for (nick, uh, seq) in self.map.values() {
            let e = out.entry(fold(nick)).or_insert_with(|| (uh.clone(), *seq));
            if *seq > e.1 {
                *e = (uh.clone(), *seq);
            }
        }
        out.into_iter().map(|(k, (uh, _))| (k, uh)).collect()
    }
}

/// Record what one IRC line says about the user@host behind a nick (irc.rs dispatch_line).
pub fn observe_line(c: &mut IrcConnection, prefix: Option<&str>, command: &str, params: &[String]) {
    let p = |i: usize| params.get(i).map(String::as_str).unwrap_or("");
    if let Some((nick, uh)) = prefix.and_then(|pf| pf.split_once('!')) {
        match command {
            "JOIN" | "PRIVMSG" | "NOTICE" | "PART" | "TAGMSG" | "AWAY" | "ACCOUNT" | "SETNAME" | "INVITE" | "KICK" | "TOPIC" => {
                c.seen_userhosts.note(nick, uh)
            }
            "NICK" => {
                c.seen_userhosts.forget(nick);
                c.seen_userhosts.note(p(0), uh);
            }
            "CHGHOST" if !p(0).is_empty() && !p(1).is_empty() => c.seen_userhosts.note(nick, &format!("{}@{}", p(0), p(1))),
            "QUIT" => c.seen_userhosts.forget(nick),
            _ => {}
        }
        return;
    }
    match command {
        // RPL_WHOISUSER: me nick user host * :realname
        "311" if !p(2).is_empty() && !p(3).is_empty() => c.seen_userhosts.note(p(1), &format!("{}@{}", p(2), p(3))),
        // RPL_WHOREPLY: me channel user host server nick flags :hops realname
        "352" if !p(2).is_empty() && !p(3).is_empty() => c.seen_userhosts.note(p(5), &format!("{}@{}", p(2), p(3))),
        // RPL_NAMREPLY with userhost-in-names: @nick!user@host …
        "353" => {
            for entry in p(3).split_whitespace() {
                if let Some((nick, uh)) = entry.split_once('!') {
                    c.seen_userhosts.note(nick, uh);
                }
            }
        }
        _ => {}
    }
}

/// Same user@host: identical user, host compared case-insensitively.
fn same_userhost(a: &str, b: &str) -> bool {
    match (a.split_once('@'), b.split_once('@')) {
        (Some((ua, ha)), Some((ub, hb))) => !ua.is_empty() && ua == ub && ha.eq_ignore_ascii_case(hb),
        _ => false,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum LookupError {
    NotYourConnection,
}

/// Which of `nicks` (as seen on the viewer's connection `viewer_conn`) the server vouches
/// for, and with which avatar. The rules — each one is required:
/// 1. `viewer_conn` is the viewer's own connection, live (connected + registered), and its
///    state comes from the CURRENT irc-core link whose Attach replay is over (`link`, 0 = no
///    link up or replay still running: nothing is vouched for — cached flags and nicks may
///    be stale). A connection's nick and user@host only change by snapshot or LIVE line
///    (IrcConnection::adopt_self_nick).
/// 2. The viewer's connection currently sees the nick: it is a member of a channel the
///    viewer is in, or the viewer's server just returned it in a WHOIS reply.
/// 3. Both the viewer's and the candidate's connection completed CAP negotiation in this
///    process (their CAP LS was seen) and neither is behind a bouncer (bouncer capability,
///    CAP answered as ZNC, ISUPPORT BOUNCER_NETID): a shared bouncer authenticates itself,
///    not the upstream network of each of its users. Unknown → no match.
/// 4. The candidate connection is live on the current link, dials the SAME server host as
///    the viewer's (canonical_host; the port may differ), and its CURRENT nick (as this
///    server tracks it) equals the nick under the viewer's network casemapping (unknown →
///    ASCII only, never wider). A network NAME never links two hosts; two connections whose
///    ISUPPORT NETWORK names are both known and differ never match.
/// 5. If the viewer's server has shown a user@host for the nick, it equals the candidate
///    connection's own user@host (unknown own user@host → no match).
/// 6. Exactly one ACCOUNT holds the nick that way — counting every account, with or without
///    an avatar; two accounts match neither.
/// 7. That account has an avatar, has not opted out (the viewer always sees their own),
///    still exists, is not disabled by an admin (its IRC session may outlive the ban) or
///    being deleted, and avatars are enabled.
///
/// The answer tells the viewer "this nick is a CryptIRC user of this instance", and
/// nothing about nicks the viewer cannot already see.
#[allow(clippy::too_many_arguments)]
pub async fn discover(
    connections: &DashMap<String, Arc<Mutex<IrcConnection>>>,
    conn_owners: &DashMap<String, String>,
    store: &AvatarStore,
    auth: &AuthManager,
    link: u64,
    viewer: &str,
    viewer_conn: &str,
    nicks: &[String],
) -> Result<HashMap<String, AvatarMeta>, LookupError> {
    if crate::is_noncanonical_network_id(viewer_conn)
        || conn_owners.get(viewer_conn).map_or(true, |o| o.value().as_str() != viewer)
    {
        return Err(LookupError::NotYourConnection);
    }
    let mut out = HashMap::new();
    if !store.enabled() || nicks.is_empty() || link == 0 {
        return Ok(out);
    }
    let Some(vconn) = connections.get(viewer_conn).map(|c| c.clone()) else { return Ok(out) };
    let rfc8265 = crate::e2e::utf8mapping_is_rfc8265(viewer_conn);
    let (host, cm, visible_raw, seen_hosts) = {
        let c = vconn.lock().await;
        if !(c.connected && c.registered) || c.synced_link != link || !c.cap_ls_done || c.behind_bouncer {
            return Ok(out);
        }
        let cm = c.server_casemapping.or_else(|| crate::irc::known_casemapping(viewer_conn));
        let mut seen: Vec<String> = c
            .channels
            .values()
            .flat_map(|ch| ch.names.iter().map(|n| cryptirc::ircproto::strip_pfx(n).to_string()))
            .collect();
        seen.extend(c.whois_seen.fresh().map(str::to_string));
        let seen_hosts = c.seen_userhosts.latest_by(|n| crate::e2e_nick_fold(cm, rfc8265, n));
        (conn_host(&c), cm, seen, seen_hosts)
    };
    if host.is_empty() {
        return Ok(out);
    }
    let fold = |n: &str| crate::e2e_nick_fold(cm, rfc8265, n);
    let visible: HashSet<String> = visible_raw.iter().map(|n| fold(n)).collect();
    // folded nick → the spellings the client asked with
    let mut wanted: HashMap<String, Vec<String>> = HashMap::new();
    for n in nicks.iter().take(LOOKUP_MAX_NICKS) {
        let n = cryptirc::ircproto::strip_pfx(n.trim());
        if !plausible_nick(n) {
            continue;
        }
        let k = fold(n);
        if !visible.contains(&k) {
            continue;
        }
        let spellings = wanted.entry(k).or_default();
        if spellings.len() < 4 && !spellings.iter().any(|s| s == n) {
            spellings.push(n.to_string());
        }
    }
    if wanted.is_empty() {
        return Ok(out);
    }
    let viewer_network = crate::e2e::network_name(viewer_conn);
    // Every account's live connections on this host holding a wanted nick (avatar or not).
    let candidates: Vec<(String, Arc<Mutex<IrcConnection>>)> =
        connections.iter().map(|e| (e.key().clone(), e.value().clone())).collect();
    let mut holders: HashMap<String, HashSet<String>> = HashMap::new();
    for (cid, conn) in candidates {
        if crate::is_noncanonical_network_id(&cid) {
            continue;
        }
        let Some(owner) = conn_owners.get(&cid).map(|o| o.value().clone()) else { continue };
        let (live, nick, target_host, own_userhost) = {
            let c = conn.lock().await;
            let classified = c.cap_ls_done && !c.behind_bouncer;
            (c.connected && c.registered && c.synced_link == link && classified, c.nick.clone(), conn_host(&c), c.self_userhost.clone())
        };
        if !live || nick.is_empty() || target_host != host {
            continue;
        }
        let target_network = crate::e2e::network_name(&cid);
        if let (Some(a), Some(b)) = (&viewer_network, &target_network) {
            if a != b {
                continue;
            }
        }
        let k = fold(&nick);
        if !wanted.contains_key(&k) {
            continue;
        }
        if let Some(observed) = seen_hosts.get(&k) {
            if !same_userhost(observed, &own_userhost) {
                continue;
            }
        }
        holders.entry(k).or_default().insert(owner);
    }
    for (k, owners) in holders {
        if owners.len() != 1 {
            continue;
        }
        let Some(owner) = owners.into_iter().next() else { continue };
        if !owner_shown(auth, &owner).await {
            continue;
        }
        let Some(meta) = store.meta(&owner) else { continue };
        if !(meta.visible || owner == viewer) {
            continue;
        }
        for spelling in &wanted[&k] {
            out.insert(spelling.clone(), meta.clone());
        }
    }
    Ok(out)
}

/// The owner's account may have its avatar shown: it exists, is not being deleted and is not
/// disabled by an admin.
async fn owner_shown(auth: &AuthManager, owner: &str) -> bool {
    !auth.is_being_deleted(owner)
        && auth.account_exists(owner).await
        && !auth.get_user(owner).await.map_or(false, |u| u.disabled)
}

// ─── Routes ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AvatarRouteState {
    pub auth: Arc<AuthManager>,
    pub store: Arc<AvatarStore>,
    pub remote: Arc<remote::RemoteAvatars>,
    pub connections: Arc<DashMap<String, Arc<Mutex<IrcConnection>>>>,
    pub conn_owners: Arc<DashMap<String, String>>,
    /// The live irc-core link generation once its Attach replay is complete
    /// (ipc_client::attached_link; 0 = no link, or replay still running).
    pub link: fn() -> u64,
}

impl FromRef<crate::AppState> for AvatarRouteState {
    fn from_ref(s: &crate::AppState) -> Self {
        AvatarRouteState {
            auth: s.auth.clone(),
            store: s.avatars.clone(),
            remote: s.avatar_remote.clone(),
            connections: s.connections.clone(),
            conn_owners: s.conn_owners.clone(),
            link: crate::ipc_client::attached_link,
        }
    }
}

fn no_store(mut r: Response) -> Response {
    r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static(PRIVATE_NO_STORE));
    r
}
fn json_message(status: StatusCode, message: &str) -> Response {
    no_store((status, Json(serde_json::json!({ "message": message }))).into_response())
}
fn unauthorized() -> Response {
    no_store(StatusCode::UNAUTHORIZED.into_response())
}
fn not_found() -> Response {
    no_store(StatusCode::NOT_FOUND.into_response())
}

/// API routes: the session token in the Authorization header only (no cookie, so no CSRF).
fn api_user(state: &AvatarRouteState, headers: &HeaderMap) -> Option<String> {
    let token = crate::bearer_token(headers)?;
    state.auth.validate_session(&token)
}

/// Holds one of the process-wide upload-body slots and the account's single upload slot.
struct UploadSlot {
    _body: tokio::sync::OwnedSemaphorePermit,
    user: String,
    uploading: Arc<DashMap<String, ()>>,
}
impl Drop for UploadSlot {
    fn drop(&mut self) {
        self.uploading.remove(&self.user);
    }
}

/// Read an upload body under a hard byte cap, an idle limit per chunk and a total deadline.
async fn read_upload(body: Body) -> Result<Vec<u8>, AvatarError> {
    use futures_util::StreamExt;
    let mut stream = body.into_data_stream();
    let mut out: Vec<u8> = Vec::new();
    let deadline = tokio::time::Instant::now() + UPLOAD_TOTAL;
    loop {
        let wait = deadline.saturating_duration_since(tokio::time::Instant::now()).min(UPLOAD_IDLE);
        match tokio::time::timeout(wait, stream.next()).await {
            Err(_) => return Err(AvatarError::Slow),
            Ok(None) => return Ok(out),
            Ok(Some(Err(_))) => return Err(AvatarError::Malformed),
            Ok(Some(Ok(chunk))) => {
                if out.len() + chunk.len() > MAX_UPLOAD_BYTES {
                    return Err(AvatarError::TooLarge);
                }
                out.extend_from_slice(&chunk);
            }
        }
    }
}

fn own_state(store: &AvatarStore, user: &str) -> Response {
    let meta = store.meta(user);
    no_store(
        Json(serde_json::json!({
            "enabled": store.enabled(),
            "avatar": meta.as_ref().map(|m| serde_json::json!({ "t": m.token, "v": m.v })),
            "visible": meta.as_ref().map_or(true, |m| m.visible),
            "share": meta.as_ref().map_or(false, |m| m.share),
            "share_available": store.public_base().is_some(),
            "public_url": store.public_url(user),
            "max_bytes": MAX_UPLOAD_BYTES,
        }))
        .into_response(),
    )
}

/// Publish / clear the owner's metadata value after a change (remote::republish).
async fn republish(state: &AvatarRouteState, owner: &str) {
    remote::republish(&state.auth, &state.store, &state.connections, &state.conn_owners, owner).await;
}

/// GET /api/avatar/me — the caller's own avatar state.
pub async fn route_me_get(State(state): State<AvatarRouteState>, headers: HeaderMap) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    own_state(&state.store, &user)
}

/// POST /api/avatar/me[?share=1] — upload or replace (the raw image is the body). The session
/// is checked before the body is read. `share=1`: the owner agreed (in the upload flow) that a
/// FIRST avatar is shared with other CryptIRC servers; without it a first avatar is not.
pub async fn route_me_upload(State(state): State<AvatarRouteState>, Query(params): Query<HashMap<String, String>>, headers: HeaderMap, body: Body) -> Response {
    let share_first = params.get("share").map(String::as_str) == Some("1");
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    // The account generation this upload belongs to (see AvatarStore::save).
    let epoch = state.auth.account_epoch(&user);
    if !state.store.enabled() {
        return json_message(StatusCode::FORBIDDEN, "Avatars are turned off on this server.");
    }
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.map_or(false, |n| n > MAX_UPLOAD_BYTES as u64) {
        return json_message(StatusCode::PAYLOAD_TOO_LARGE, AvatarError::TooLarge.message());
    }
    if state.auth.check_user_create_rate_limit(&user, "avatar").is_err() {
        return json_message(StatusCode::TOO_MANY_REQUESTS, "Too many avatar changes — try again in a minute.");
    }
    // One body in flight per account, a few process-wide; each is bounded in size and time.
    if state.store.uploading.insert(user.clone(), ()).is_some() {
        return json_message(StatusCode::TOO_MANY_REQUESTS, "An avatar upload is already in progress.");
    }
    let slot = match state.store.upload_bodies.clone().try_acquire_owned() {
        Ok(permit) => UploadSlot { _body: permit, user: user.clone(), uploading: state.store.uploading.clone() },
        Err(_) => {
            state.store.uploading.remove(&user);
            return json_message(AvatarError::Busy.status(), AvatarError::Busy.message());
        }
    };
    let bytes = match read_upload(body).await {
        Ok(b) => b,
        Err(e) => return json_message(e.status(), e.message()),
    };
    drop(slot);
    let processed = match process_in_background(&state.store.slots, bytes).await {
        Ok(p) => p,
        Err(e) => return json_message(e.status(), e.message()),
    };
    match state.store.save(&state.auth, &user, epoch, processed, share_first).await {
        Ok(_) => {
            republish(&state, &user).await;
            own_state(&state.store, &user)
        }
        Err(e) => json_message(e.status(), e.message()),
    }
}

/// DELETE /api/avatar/me — remove the caller's avatar (allowed while avatars are off).
pub async fn route_me_delete(State(state): State<AvatarRouteState>, headers: HeaderMap) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    state.store.remove(&user).await;
    republish(&state, &user).await;
    own_state(&state.store, &user)
}

#[derive(Deserialize)]
pub struct SettingsBody {
    #[serde(default)]
    visible: Option<bool>,
    #[serde(default)]
    share: Option<bool>,
}

/// PUT /api/avatar/me {"visible"?: bool, "share"?: bool} — "Show my avatar to other CryptIRC
/// users" / "Share my avatar with people on other CryptIRC servers".
pub async fn route_me_settings(
    State(state): State<AvatarRouteState>,
    headers: HeaderMap,
    Json(body): Json<SettingsBody>,
) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    if state.store.meta(&user).is_none() {
        return json_message(StatusCode::NOT_FOUND, "You have no avatar.");
    }
    if let Some(v) = body.visible {
        if state.store.set_visible(&user, v).await.is_none() {
            return json_message(StatusCode::INTERNAL_SERVER_ERROR, "Not saved.");
        }
    }
    if let Some(s) = body.share {
        if state.store.set_share(&user, s).await.is_none() {
            return json_message(StatusCode::INTERNAL_SERVER_ERROR, "Not saved.");
        }
    }
    republish(&state, &user).await;
    own_state(&state.store, &user)
}

#[derive(Deserialize)]
pub struct LookupBody {
    conn_id: String,
    nicks: Vec<String>,
    /// Nicks the user explicitly opened (nick menu / WHOIS): may be queried on IRC when
    /// nothing is known about them (remote::resolve).
    #[serde(default)]
    probe: Vec<String>,
}

/// POST /api/avatar/lookup {"conn_id", "nicks": [...]} — see `discover`.
pub async fn route_lookup(
    State(state): State<AvatarRouteState>,
    headers: HeaderMap,
    Json(body): Json<LookupBody>,
) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    if body.nicks.len() > LOOKUP_MAX_NICKS || body.probe.len() > LOOKUP_MAX_NICKS {
        return json_message(StatusCode::BAD_REQUEST, "Too many nicks in one lookup.");
    }
    if !state.store.lookup_rate_ok(&user) {
        let mut r = json_message(StatusCode::TOO_MANY_REQUESTS, "Too many lookups.");
        r.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        return r;
    }
    let found = match discover(&state.connections, &state.conn_owners, &state.store, &state.auth, (state.link)(), &user, &body.conn_id, &body.nicks).await {
        Ok(f) => f,
        Err(LookupError::NotYourConnection) => return not_found(),
    };
    // Same-instance answers come first; other servers' announces only for the rest.
    let local: HashSet<String> = found.keys().map(|n| cryptirc::ircproto::strip_pfx(n).to_ascii_lowercase()).collect();
    let remote = remote::resolve(&state, &user, &body.conn_id, &body.nicks, &body.probe, &local).await;
    let mut avatars: serde_json::Map<String, serde_json::Value> = found
        .into_iter()
        .map(|(nick, m)| (nick, serde_json::json!({ "t": m.token, "v": m.v })))
        .collect();
    for (nick, (rid, v, host)) in remote.found {
        avatars.entry(nick).or_insert_with(|| serde_json::json!({ "r": rid, "v": v, "h": host }));
    }
    no_store(
        Json(serde_json::json!({
            "enabled": state.store.enabled(),
            "avatars": avatars,
            "pending": remote.pending,
            "ttl": LOOKUP_TTL_SECS,
        }))
        .into_response(),
    )
}

/// GET /avatar/pub/<pub_id>-<version>.png — the 128 px picture an owner shares with people on
/// other CryptIRC servers. Public (no session): only while avatars are on and the owner has
/// this avatar, keeps it visible, shares it under this id, and the account exists and is
/// neither disabled nor being deleted; otherwise 404 (no-store). `nosniff`, a short public
/// cache and an ETag.
pub async fn route_public_image(State(state): State<AvatarRouteState>, UrlPath(file): UrlPath<String>, headers: HeaderMap) -> Response {
    let gone = || {
        let mut r = StatusCode::NOT_FOUND.into_response();
        r.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        r.headers_mut().insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
        r
    };
    let Some((pid, v)) = file.strip_suffix(".png").and_then(|n| n.split_once('-')) else { return gone() };
    if !state.store.enabled() || !valid_token(pid) || !valid_version(v) {
        return gone();
    }
    let Some(owner) = state.store.owner_of_pub(pid) else { return gone() };
    let Some(meta) = state.store.meta(&owner) else { return gone() };
    if !(meta.visible && meta.share && meta.pub_id == pid && meta.v == v) || !owner_shown(&state.auth, &owner).await {
        return gone();
    }
    let etag = format!("\"{}\"", v);
    let revalidated = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|h| h.to_str().ok())
        .map_or(false, |h| h.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    let mut r = if revalidated {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let Some(bytes) = state.store.read_image(&owner, &meta.v, SIZE_LARGE).await else { return gone() };
        let mut r = Response::new(Body::from(bytes));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        r
    };
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("public, max-age=300"));
    h.insert(header::HeaderName::from_static("x-content-type-options"), HeaderValue::from_static("nosniff"));
    h.insert(header::HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("cross-origin"));
    h.insert(header::HeaderName::from_static("content-security-policy"), HeaderValue::from_static("default-src 'none'; sandbox"));
    h.insert(header::HeaderName::from_static("referrer-policy"), HeaderValue::from_static("no-referrer"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    r
}

/// GET /avatar/<token>?v=<version>[&s=48] — the picture, for sessions of this instance
/// (Authorization header). 404 (never the picture) when avatars are off, the token or
/// version is not the current one, the owner's account is gone, being deleted or disabled
/// (admins still see a disabled one), or the owner opted out (except for the owner and
/// admins). `private, no-store`: every use comes back here, so logout, opt-out, removal,
/// a ban or the admin switch take effect at once (the app keeps the bytes in memory).
pub async fn route_image(
    State(state): State<AvatarRouteState>,
    UrlPath(token): UrlPath<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    if !state.store.enabled() || !valid_token(&token) {
        return not_found();
    }
    let Some(owner) = state.store.owner_of(&token) else { return not_found() };
    let Some(meta) = state.store.meta(&owner) else { return not_found() };
    if meta.token != token || params.get("v").map(String::as_str) != Some(meta.v.as_str()) {
        return not_found();
    }
    let size = match params.get("s").map(String::as_str) {
        None | Some("128") => SIZE_LARGE,
        Some("48") => SIZE_SMALL,
        Some(_) => return not_found(),
    };
    if state.auth.is_being_deleted(&owner) || !state.auth.account_exists(&owner).await {
        return not_found();
    }
    let disabled = state.auth.get_user(&owner).await.map_or(false, |u| u.disabled);
    if (disabled || (!meta.visible && owner != user)) && !state.auth.is_admin(&user).await {
        return not_found();
    }
    let etag = format!("\"{}-{}\"", meta.v, size);
    let revalidated = headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map_or(false, |v| v.split(',').any(|t| t.trim() == etag));
    let mut r = if revalidated {
        let mut r = Response::new(Body::empty());
        *r.status_mut() = StatusCode::NOT_MODIFIED;
        r
    } else {
        let Some(bytes) = state.store.read_image(&owner, &meta.v, size).await else { return not_found() };
        let mut r = Response::new(Body::from(bytes));
        r.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
        r
    };
    let h = r.headers_mut();
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(PRIVATE_NO_STORE));
    h.insert(header::HeaderName::from_static("cross-origin-resource-policy"), HeaderValue::from_static("same-origin"));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        h.insert(header::ETAG, v);
    }
    r
}

/// DELETE /admin/user/<name>/avatar — an admin removes anyone's avatar.
pub async fn route_admin_remove(
    State(state): State<AvatarRouteState>,
    headers: HeaderMap,
    UrlPath(target): UrlPath<String>,
) -> Response {
    let Some(user) = api_user(&state, &headers) else { return unauthorized() };
    if !state.auth.is_admin(&user).await {
        return no_store(StatusCode::FORBIDDEN.into_response());
    }
    let target = target.trim().to_lowercase();
    if !crate::auth::is_safe_username(&target) {
        return json_message(StatusCode::BAD_REQUEST, "Invalid username.");
    }
    if state.store.remove(&target).await {
        republish(&state, &target).await;
        json_message(StatusCode::OK, "Avatar removed.")
    } else {
        json_message(StatusCode::NOT_FOUND, "That user has no avatar.")
    }
}

/// The avatar of each listed account for the admin roster ({"t","v","visible"} or null).
pub fn admin_roster_info(store: &AvatarStore, username: &str) -> serde_json::Value {
    match store.meta(&username.to_lowercase()) {
        Some(m) => serde_json::json!({ "t": m.token, "v": m.v, "visible": m.visible }),
        None => serde_json::Value::Null,
    }
}

pub mod remote;

#[cfg(test)]
mod tests;
