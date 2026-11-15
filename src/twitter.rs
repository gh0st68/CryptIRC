//! Bounded, viewer-authorized X previews. Provider data never becomes HTML.
//!
//! Ported from the community "rich X previews" reference (see docs/x-preview-verification.md).
//! Every provider is OFF unless its startup flag is set; with no flag set nothing in this
//! module opens a socket (`TwitterClient::enabled()` / `thread_enabled()` are false and the
//! service answers `provider_disabled` locally).

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    future::Future,
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

pub const SCHEMA_VERSION: u8 = 1;
pub const MAX_URL_BYTES: usize = 2048;
pub const X_HOSTS: &[&str] = &[
    "x.com",
    "www.x.com",
    "mobile.x.com",
    "twitter.com",
    "www.twitter.com",
    "mobile.twitter.com",
    "m.twitter.com",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TweetIdentity {
    pub id: String,
    pub url: String,
}

pub fn valid_id(value: &str) -> bool {
    (1..=20).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|b| b.is_ascii_digit())
}

fn valid_handle(value: &str) -> bool {
    (1..=15).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn has_controls(value: &str) -> bool {
    value.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

// Validate the raw spelling before URL parsing can strip controls, resolve dot
// segments, normalize backslashes, or discard empty userinfo.
fn strict_https(value: &str) -> Option<reqwest::Url> {
    if value.len() > MAX_URL_BYTES || has_controls(value) || value.contains('\\') {
        return None;
    }
    let (scheme, rest) = value.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains(['@', '%']) || authority.ends_with('.') {
        return None;
    }
    let parsed = reqwest::Url::parse(value).ok()?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port_or_known_default() != Some(443)
    {
        return None;
    }
    Some(parsed)
}

pub fn parse_tweet_url(value: &str) -> Option<TweetIdentity> {
    let parsed = strict_https(value)?;
    if !X_HOSTS.contains(&parsed.host_str()?) {
        return None;
    }
    let rest = value.split_once("://")?.1;
    let path_start = rest.find(['/', '?', '#'])?;
    let path = rest[path_start..].split(['?', '#']).next()?;
    if !path.is_ascii() || path.contains('%') {
        return None;
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    let parts: Vec<_> = path.strip_prefix('/')?.split('/').collect();
    let (id, suffix) = match parts.as_slice() {
        ["i", "web", "status", id, tail @ ..] => (*id, tail),
        [handle, "status", id, tail @ ..] if valid_handle(handle) => (*id, tail),
        _ => return None,
    };
    if !valid_id(id) {
        return None;
    }
    match suffix {
        [] => (),
        ["photo" | "video", n]
            if !n.is_empty()
                && n.bytes().any(|b| b != b'0')
                && n.bytes().all(|b| b.is_ascii_digit()) => {}
        _ => return None,
    }
    Some(TweetIdentity {
        id: id.into(),
        url: format!("https://x.com/i/status/{id}"),
    })
}

pub fn validate_media_url(value: &str, video: bool) -> Option<String> {
    let parsed = strict_https(value)?;
    let host = if video {
        "video.twimg.com"
    } else {
        "pbs.twimg.com"
    };
    if parsed.host_str() != Some(host) || parsed.fragment().is_some() {
        return None;
    }
    let path = parsed.path().to_ascii_lowercase();
    if path.ends_with(".svg")
        || path.ends_with(".svgz")
        || path.contains('%')
        || parsed.query_pairs().any(|(k, v)| {
            k == "format" && (v.eq_ignore_ascii_case("svg") || v.eq_ignore_ascii_case("html"))
        })
    {
        return None;
    }
    Some(parsed.to_string())
}

pub fn validate_navigation_url(value: &str) -> Option<String> {
    if value.len() > MAX_URL_BYTES || has_controls(value) || value.contains('\\') {
        return None;
    }
    let (_, rest) = value.split_once("://")?;
    if rest.split(['/', '?', '#']).next()?.contains('@') {
        return None;
    }
    let parsed = reqwest::Url::parse(value).ok()?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str()?.is_empty()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return None;
    }
    Some(parsed.to_string())
}

// ─── Signed same-origin media fallback (port hardening) ──────────────────────
// The fallback serves third-party bytes on CryptIRC's own origin, so it accepts far less
// than `validate_media_url` (which only gates what a browser loads directly from the CDN):
// recognized asset paths, a tiny query vocabulary, raster images / MP4 only — no SVG, no
// HTML, no HLS playlists or segments — and, at response time, an explicit MIME allowlist.

/// What a signed media-fallback URL may serve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyMediaKind {
    Image,
    Mp4,
}

const PROXY_IMAGE_PREFIXES: &[&str] = &[
    "/media/",
    "/profile_images/",
    "/ext_tw_video_thumb/",
    "/amplify_video_thumb/",
    "/tweet_video_thumb/",
    "/card_img/",
];
const PROXY_VIDEO_PREFIXES: &[&str] = &["/ext_tw_video/", "/amplify_video/", "/tweet_video/"];

/// Validate a CDN URL for the signed fallback: exact host, recognized asset path, allowed
/// query keys, and an image/MP4 file type. Returns the normalized URL and its media kind.
pub fn validate_proxy_media_url(value: &str) -> Option<(String, ProxyMediaKind)> {
    // URL parsing silently resolves dot segments; refuse them in the raw spelling.
    let raw_path = value.split(['?', '#']).next().unwrap_or(value);
    if raw_path.contains("/./") || raw_path.contains("/../") || raw_path.ends_with("/.") || raw_path.ends_with("/..") {
        return None;
    }
    let host = strict_https(value)?.host_str()?.to_owned();
    let kind = match host.as_str() {
        "pbs.twimg.com" => ProxyMediaKind::Image,
        "video.twimg.com" => ProxyMediaKind::Mp4,
        _ => return None,
    };
    let normalized = validate_media_url(value, kind == ProxyMediaKind::Mp4)?;
    let parsed = reqwest::Url::parse(&normalized).ok()?;
    let path = parsed.path();
    if path.len() > 512
        || path.contains("//")
        || path.split('/').any(|s| s == "." || s == "..")
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'-' | b'.'))
    {
        return None;
    }
    let prefixes = match kind {
        ProxyMediaKind::Image => PROXY_IMAGE_PREFIXES,
        ProxyMediaKind::Mp4 => PROXY_VIDEO_PREFIXES,
    };
    if !prefixes
        .iter()
        .any(|p| path.len() > p.len() && path.starts_with(p))
    {
        return None;
    }
    let file = path.rsplit('/').next().unwrap_or("");
    let extension = file
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase());
    let mut format = None;
    for (key, value) in parsed.query_pairs() {
        let token = !value.is_empty()
            && value.len() <= 32
            && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_');
        match (kind, key.as_ref()) {
            (ProxyMediaKind::Image, "name") if token => {}
            (ProxyMediaKind::Image, "format") if token => format = Some(value.to_ascii_lowercase()),
            (ProxyMediaKind::Mp4, "tag") if token => {}
            _ => return None,
        }
    }
    let raster = |e: &str| matches!(e, "jpg" | "jpeg" | "png" | "webp" | "gif");
    let ok = match kind {
        ProxyMediaKind::Image => {
            (extension.is_some() || format.is_some())
                && extension.as_deref().map_or(true, raster)
                && format.as_deref().map_or(true, raster)
        }
        ProxyMediaKind::Mp4 => extension.as_deref() == Some("mp4"),
    };
    ok.then_some((normalized, kind))
}

/// The Content-Type the fallback will send for an upstream response, or `None` when the
/// upstream type is absent or not allowed for this kind (HTML, SVG, playlists, mismatches).
pub fn proxy_content_type(kind: ProxyMediaKind, upstream: Option<&str>) -> Option<&'static str> {
    let main = upstream?.split(';').next()?.trim().to_ascii_lowercase();
    match (kind, main.as_str()) {
        (ProxyMediaKind::Image, "image/jpeg" | "image/jpg") => Some("image/jpeg"),
        (ProxyMediaKind::Image, "image/png") => Some("image/png"),
        (ProxyMediaKind::Image, "image/webp") => Some("image/webp"),
        (ProxyMediaKind::Image, "image/gif") => Some("image/gif"),
        (ProxyMediaKind::Mp4, "video/mp4") => Some("video/mp4"),
        _ => None,
    }
}

/// One syntactically valid byte range (`bytes=a-b`, `bytes=a-`, `bytes=-n`); no lists.
pub fn valid_media_range(value: &str) -> bool {
    let Some(spec) = value.strip_prefix("bytes=") else {
        return false;
    };
    let Some((first, last)) = spec.split_once('-') else {
        return false;
    };
    let number = |s: &str| {
        (1..=20).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok()
    };
    match (first.is_empty(), last.is_empty()) {
        (false, true) => number(first),
        (false, false) => {
            number(first)
                && number(last)
                && first.parse::<u64>().ok() <= last.parse::<u64>().ok()
        }
        (true, false) => number(last) && last.parse::<u64>().is_ok_and(|n| n > 0),
        (true, true) => false,
    }
}

/// Size-independent identity of a CDN asset (host + path). The `name=` size and `tag=`
/// query values vary between the card, the lightbox and the provider's own spelling.
pub fn media_asset_key(value: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(value).ok()?;
    let host = parsed.host_str()?;
    matches!(host, "pbs.twimg.com" | "video.twimg.com").then(|| format!("{host}{}", parsed.path()))
}

/// Every validated CDN asset referenced by a normalized preview or thread result, so the
/// media fallback can be limited to assets this viewer actually retrieved.
pub fn collect_media_keys(value: &Value, out: &mut HashSet<String>) {
    fn walk(value: &Value, depth: usize, out: &mut HashSet<String>) {
        if depth > 12 || out.len() >= 512 {
            return;
        }
        match value {
            Value::String(s) if s.starts_with("https://pbs.twimg.com/") => {
                if let Some(key) = validate_media_url(s, false).and_then(|u| media_asset_key(&u)) {
                    out.insert(key);
                }
            }
            Value::String(s) if s.starts_with("https://video.twimg.com/") => {
                if let Some(key) = validate_media_url(s, true).and_then(|u| media_asset_key(&u)) {
                    out.insert(key);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| walk(v, depth + 1, out)),
            Value::Object(map) => map.values().for_each(|v| walk(v, depth + 1, out)),
            _ => {}
        }
    }
    walk(value, 0, out);
}

macro_rules! string_enum {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
    };
}
string_enum!(AvailabilityState {
    Available,
    Unavailable
});
string_enum!(UnavailableReason {
    Deleted,
    NotFound,
    Private,
    Restricted,
    Suspended,
    Unknown,
    ProviderDisabled
});
string_enum!(TextSource {
    Legacy,
    Note,
    Unavailable
});
string_enum!(EntityKind {
    Url,
    Mention,
    Hashtag,
    Media
});
string_enum!(MetricState {
    Available,
    Unavailable,
    Unsupported
});
string_enum!(MediaKind {
    Photo,
    Video,
    AnimatedGif
});
string_enum!(QuoteState {
    None,
    Available,
    Unavailable,
    Omitted
});
string_enum!(ThreadState {
    Disabled,
    Unknown,
    Available,
    Unavailable
});

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TweetPreview {
    pub schema_version: u8,
    pub id: String,
    pub url: String,
    pub availability: Availability,
    pub author: Option<Author>,
    pub created_at: Option<String>,
    pub text: String,
    pub text_source: TextSource,
    pub text_complete: bool,
    pub entities: Vec<TextEntity>,
    pub metrics: Metrics,
    pub media: Vec<Media>,
    pub media_complete: bool,
    pub quote: Quote,
    pub reply: Option<ReplyContext>,
    pub thread: ThreadHint,
    pub fetched_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Availability {
    pub state: AvailabilityState,
    pub reason: Option<UnavailableReason>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Author {
    pub id: Option<String>,
    pub name: String,
    pub handle: Option<String>,
    pub avatar_url: Option<String>,
    pub verification: Verification,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Verification {
    pub legacy_verified: Option<bool>,
    pub blue_verified: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TextEntity {
    pub kind: EntityKind,
    pub start: u32,
    pub end: u32,
    pub url: String,
    pub display: String,
    pub media_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metric {
    pub state: MetricState,
    pub value: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Metrics {
    pub likes: Metric,
    pub reposts: Metric,
    pub replies: Metric,
    pub quotes: Metric,
    pub bookmarks: Metric,
    pub views: Metric,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Media {
    pub id: String,
    pub kind: MediaKind,
    pub thumbnail_url: Option<String>,
    pub original_url: Option<String>,
    pub alt_text: Option<String>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub duration_ms: Option<u64>,
    pub mp4: Vec<VideoVariant>,
    pub hls_url: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VideoVariant {
    pub url: String,
    pub content_type: String,
    pub bitrate: Option<u64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Quote {
    pub state: QuoteState,
    pub id: Option<String>,
    pub url: Option<String>,
    pub post: Option<Box<TweetPreview>>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplyContext {
    pub id: Option<String>,
    pub author_handle: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadHint {
    pub state: ThreadState,
    pub provider: Option<String>,
    pub count: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadPreview {
    pub schema_version: u8,
    pub root_id: String,
    pub provider: String,
    pub availability: Availability,
    pub entries: Vec<ThreadEntry>,
    pub partial: bool,
    pub reported_count: Option<u64>,
    pub continuation_url: String,
    pub fetched_at: String,
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreadEntry {
    pub key: String,
    pub id: Option<String>,
    pub url: Option<String>,
    pub author: Option<Author>,
    pub created_at: Option<String>,
    pub text: String,
    pub entities: Vec<TextEntity>,
    pub media: Vec<Media>,
    pub metrics: Metrics,
}

impl ThreadPreview {
    pub fn unavailable(id: &str, reason: UnavailableReason, now: DateTime<Utc>) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            root_id: id.into(),
            provider: "threadreader".into(),
            availability: Availability {
                state: AvailabilityState::Unavailable,
                reason: Some(reason),
            },
            entries: vec![],
            partial: false,
            reported_count: None,
            continuation_url: format!("https://x.com/i/status/{id}"),
            fetched_at: utc_string(now),
            expires_at: utc_string(
                now + chrono::Duration::seconds(if reason == UnavailableReason::ProviderDisabled {
                    30
                } else {
                    60
                }),
            ),
        }
    }
}

const MAX_TEXT_BYTES: usize = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PreviewError {
    InvalidUrl,
    Busy,
    Timeout,
    ProviderChanged,
    RateLimited(u64),
    UpstreamFailure,
}

fn utc_string(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

impl Metric {
    fn unknown(state: MetricState) -> Self {
        Self { state, value: None }
    }

    fn parse(value: &Value) -> Self {
        let count = value.as_u64().or_else(|| {
            let s = value.as_str()?;
            if s != "0" && !valid_id(s) {
                return None;
            }
            s.parse::<u64>().ok()
        });
        match count {
            Some(count) => Self {
                state: MetricState::Available,
                value: Some(count.to_string()),
            },
            None => Self::unknown(MetricState::Unavailable),
        }
    }
}

impl Metrics {
    fn unknown(state: MetricState) -> Self {
        Self {
            likes: Metric::unknown(state),
            reposts: Metric::unknown(state),
            replies: Metric::unknown(state),
            quotes: Metric::unknown(state),
            bookmarks: Metric::unknown(state),
            views: Metric::unknown(state),
        }
    }

    fn parse(post: &Value) -> Self {
        let legacy = &post["legacy"];
        Self {
            likes: Metric::parse(&legacy["favorite_count"]),
            reposts: Metric::parse(&legacy["retweet_count"]),
            replies: Metric::parse(&legacy["reply_count"]),
            quotes: Metric::parse(&legacy["quote_count"]),
            bookmarks: Metric::parse(&legacy["bookmark_count"]),
            views: Metric::parse(&post["views"]["count"]),
        }
    }
}

impl TweetPreview {
    pub fn unavailable(id: &str, reason: UnavailableReason, now: DateTime<Utc>) -> Self {
        let ttl = if reason == UnavailableReason::ProviderDisabled {
            30
        } else {
            60
        };
        Self {
            schema_version: SCHEMA_VERSION,
            id: id.into(),
            url: format!("https://x.com/i/status/{id}"),
            availability: Availability {
                state: AvailabilityState::Unavailable,
                reason: Some(reason),
            },
            author: None,
            created_at: None,
            text: String::new(),
            text_source: TextSource::Unavailable,
            text_complete: false,
            entities: vec![],
            metrics: Metrics::unknown(MetricState::Unavailable),
            media: vec![],
            media_complete: false,
            quote: Quote {
                state: QuoteState::None,
                id: None,
                url: None,
                post: None,
                reason: None,
            },
            reply: None,
            thread: ThreadHint {
                state: ThreadState::Disabled,
                provider: None,
                count: None,
            },
            fetched_at: utc_string(now),
            expires_at: utc_string(now + chrono::Duration::seconds(ttl)),
        }
    }
}

fn clipped(value: &str, chars: usize) -> String {
    value.chars().take(chars).collect()
}

fn optional_id(value: &Value) -> Option<String> {
    value.as_str().filter(|s| valid_id(s)).map(String::from)
}

fn optional_handle(value: &Value) -> Option<String> {
    value.as_str().filter(|s| valid_handle(s)).map(String::from)
}

fn parse_author(post: &Value) -> Option<Author> {
    let user = post.pointer("/core/user_results/result")?;
    if !user.is_object() || matches!(user["__typename"].as_str(), Some("UserUnavailable")) {
        return None;
    }
    let field = |name: &str| {
        user["core"][name]
            .as_str()
            .or_else(|| user["legacy"][name].as_str())
    };
    let avatar = user
        .pointer("/avatar/image_url")
        .and_then(Value::as_str)
        .or_else(|| user["legacy"]["profile_image_url_https"].as_str());
    Some(Author {
        id: optional_id(&user["rest_id"]),
        name: clipped(field("name").unwrap_or(""), 256),
        handle: field("screen_name")
            .filter(|s| valid_handle(s))
            .map(String::from),
        avatar_url: avatar.and_then(|s| validate_media_url(s, false)),
        verification: Verification {
            legacy_verified: user["legacy"]["verified"].as_bool(),
            blue_verified: user["is_blue_verified"].as_bool(),
        },
    })
}

fn unwrap_post(mut post: &Value) -> Result<&Value, PreviewError> {
    for depth in 0..=3 {
        if post["__typename"] != "TweetWithVisibilityResults" {
            return Ok(post);
        }
        if depth == 3 {
            return Err(PreviewError::UpstreamFailure);
        }
        post = post
            .get("tweet")
            .filter(|v| v.is_object())
            .ok_or(PreviewError::UpstreamFailure)?;
    }
    Err(PreviewError::UpstreamFailure)
}

// A specific reason must be supplied in structured data. HTTP status and vague
// tombstone prose alone never establish deletion, protection, or suspension.
fn unavailable_reason(post: &Value) -> Option<UnavailableReason> {
    let reason = post["reason"]
        .as_str()
        .or_else(|| post.pointer("/tombstone/reason").and_then(Value::as_str));
    let mapped = match reason {
        Some("deleted" | "Deleted") => Some(UnavailableReason::Deleted),
        Some("not_found" | "NotFound") => Some(UnavailableReason::NotFound),
        Some("private" | "Protected") => Some(UnavailableReason::Private),
        Some("restricted" | "Restricted") => Some(UnavailableReason::Restricted),
        Some("suspended" | "Suspended") => Some(UnavailableReason::Suspended),
        _ => None,
    };
    if mapped.is_some() {
        return mapped;
    }
    match post["__typename"].as_str() {
        Some("TweetTombstone" | "TweetUnavailable") => Some(UnavailableReason::Unknown),
        _ => None,
    }
}

pub fn parse_tweet_response(
    body: &[u8],
    id: &str,
    now: DateTime<Utc>,
) -> Result<TweetPreview, PreviewError> {
    parse_tweet_response_at(body, id, now, 0, &[id.to_string()])
}

fn parse_tweet_response_at(
    body: &[u8],
    id: &str,
    now: DateTime<Utc>,
    depth: usize,
    seen: &[String],
) -> Result<TweetPreview, PreviewError> {
    if !valid_id(id) || body.len() > 1024 * 1024 {
        return Err(PreviewError::UpstreamFailure);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| PreviewError::UpstreamFailure)?;
    let post = root
        .pointer("/data/tweetResult/result")
        .filter(|v| v.is_object())
        .ok_or(PreviewError::UpstreamFailure)?;
    let post = unwrap_post(post)?;
    if let Some(other) = post.get("rest_id") {
        if other.as_str() != Some(id) {
            return Err(PreviewError::UpstreamFailure);
        }
    }
    if let Some(reason) = unavailable_reason(post) {
        return Ok(TweetPreview::unavailable(id, reason, now));
    }
    if post["rest_id"].as_str() != Some(id)
        || !matches!(post["__typename"].as_str(), None | Some("Tweet"))
    {
        return Err(PreviewError::UpstreamFailure);
    }
    let mut result = TweetPreview::unavailable(id, UnavailableReason::Unknown, now);
    let (media, media_complete) = parse_media(post);
    let (text, source, complete, entity_source) = select_text(post);
    if text.is_empty() && media.is_empty() {
        return Ok(result);
    }
    result.availability = Availability {
        state: AvailabilityState::Available,
        reason: None,
    };
    result.author = parse_author(post);
    result.created_at = post["legacy"]["created_at"].as_str().and_then(|s| {
        DateTime::parse_from_rfc3339(s)
            .or_else(|_| DateTime::parse_from_str(s, "%a %b %d %H:%M:%S %z %Y"))
            .ok()
            .map(|t| utc_string(t.with_timezone(&Utc)))
    });
    result.entities = normalize_entities(&text, entity_source, &media);
    result.text = text;
    result.text_source = source;
    result.text_complete = complete;
    result.metrics = Metrics::parse(post);
    result.media = media;
    result.media_complete = media_complete;
    let reply_id = optional_id(&post["legacy"]["in_reply_to_status_id_str"]);
    let handle = optional_handle(&post["legacy"]["in_reply_to_screen_name"]);
    if reply_id.is_some() || handle.is_some() {
        result.reply = Some(ReplyContext {
            id: reply_id,
            author_handle: handle,
        });
    }
    result.expires_at = utc_string(now + chrono::Duration::minutes(10));
    result.quote = parse_quote(post, now, depth, seen);
    if serde_json::to_vec(&result)
        .map_err(|_| PreviewError::UpstreamFailure)?
        .len()
        > 256 * 1024
    {
        return Err(PreviewError::UpstreamFailure);
    }
    Ok(result)
}

fn parse_quote(post: &Value, now: DateTime<Utc>, depth: usize, seen: &[String]) -> Quote {
    let supplied = post.pointer("/quoted_status_result/result");
    let nested = supplied.and_then(|p| unwrap_post(p).ok());
    let id = optional_id(&post["legacy"]["quoted_status_id_str"])
        .or_else(|| nested.and_then(|p| optional_id(&p["rest_id"])));
    let mut quote = Quote {
        state: QuoteState::None,
        id: id.clone(),
        url: id.as_ref().map(|id| format!("https://x.com/i/status/{id}")),
        post: None,
        reason: None,
    };
    if id.is_none() && supplied.is_none() {
        return quote;
    }
    quote.state = QuoteState::Unavailable;
    quote.reason = Some("unknown".into());
    let Some(id) = id else {
        if let Some(reason) = nested.and_then(unavailable_reason) {
            quote.reason = serde_json::to_value(reason)
                .ok()
                .and_then(|v| v.as_str().map(String::from));
        }
        return quote;
    };
    if seen.contains(&id) || depth >= 1 {
        quote.state = QuoteState::Omitted;
        quote.reason = Some(
            if seen.contains(&id) {
                "cycle"
            } else {
                "depth_limit"
            }
            .into(),
        );
        return quote;
    }
    if let Some(supplied) = supplied {
        let body =
            serde_json::to_vec(&serde_json::json!({"data":{"tweetResult":{"result":supplied}}}));
        let mut ancestors = seen.to_vec();
        ancestors.push(id.clone());
        if let Ok(preview) = body
            .map_err(|_| PreviewError::UpstreamFailure)
            .and_then(|body| parse_tweet_response_at(&body, &id, now, depth + 1, &ancestors))
        {
            if preview.availability.state == AvailabilityState::Available {
                quote.state = QuoteState::Available;
                quote.reason = None;
                quote.post = Some(Box::new(preview));
            } else {
                quote.reason = preview
                    .availability
                    .reason
                    .and_then(|r| serde_json::to_value(r).ok())
                    .and_then(|v| v.as_str().map(String::from));
            }
        }
    }
    quote
}

fn select_text(post: &Value) -> (String, TextSource, bool, &Value) {
    let note = post
        .pointer("/note_tweet/note_tweet_results/result")
        .unwrap_or(&Value::Null);
    let (text, source, complete, entities) = if let Some(text) = note["text"]
        .as_str()
        .filter(|_| note["is_restricted"] != true && note["is_gated"] != true)
    {
        (
            text,
            TextSource::Note,
            note["truncated"] != true,
            &note["entity_set"],
        )
    } else if let Some(text) = post["legacy"]["full_text"].as_str() {
        (
            text,
            TextSource::Legacy,
            post["legacy"]["truncated"] != true && !note.is_object(),
            &post["legacy"]["entities"],
        )
    } else {
        ("", TextSource::Unavailable, false, &Value::Null)
    };
    let mut end = text.len().min(MAX_TEXT_BYTES);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    (
        text[..end].into(),
        source,
        complete && end == text.len(),
        entities,
    )
}

fn dimension(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .filter(|v| (1..=32768).contains(v))
        .map(|v| v as u32)
}

fn media_dimensions(value: &Value) -> (Option<u32>, Option<u32>) {
    let original = &value["original_info"];
    let fallback = value["sizes"].as_object().and_then(|sizes| {
        sizes
            .values()
            .filter_map(|s| Some((dimension(&s["w"])?, dimension(&s["h"])?)))
            .max_by_key(|(w, h)| u64::from(*w) * u64::from(*h))
    });
    let original = (
        dimension(&original["width"]),
        dimension(&original["height"]),
    );
    match original {
        (Some(_), Some(_)) => original,
        _ => fallback
            .map(|(width, height)| (Some(width), Some(height)))
            .unwrap_or(original),
    }
}

fn parse_one_media(value: &Value, index: usize) -> Option<Media> {
    let kind = match value["type"].as_str()? {
        "photo" => MediaKind::Photo,
        "video" => MediaKind::Video,
        "animated_gif" => MediaKind::AnimatedGif,
        _ => return None,
    };
    let image = value["media_url_https"]
        .as_str()
        .and_then(|s| validate_media_url(s, false));
    if kind == MediaKind::Photo && image.is_none() {
        return None;
    }
    let (width, height) = media_dimensions(value);
    let mut mp4 = Vec::new();
    let mut hls_url = None;
    if let Some(variants) = value
        .pointer("/video_info/variants")
        .and_then(Value::as_array)
    {
        for variant in variants.iter().take(8) {
            let Some(url) = variant["url"]
                .as_str()
                .and_then(|s| validate_media_url(s, true))
            else {
                continue;
            };
            match variant["content_type"].as_str() {
                Some("video/mp4") => mp4.push(VideoVariant {
                    url,
                    content_type: "video/mp4".into(),
                    bitrate: variant["bitrate"].as_u64(),
                    width: dimension(&variant["width"]),
                    height: dimension(&variant["height"]),
                }),
                Some("application/x-mpegURL" | "application/vnd.apple.mpegurl")
                    if hls_url.is_none() =>
                {
                    hls_url = Some(url)
                }
                _ => (),
            }
        }
    }
    let id = value["media_key"]
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(String::from)
        .or_else(|| optional_id(&value["id_str"]))
        .unwrap_or_else(|| format!("media:{index}"));
    Some(Media {
        id,
        kind,
        thumbnail_url: image.clone(),
        original_url: image,
        alt_text: value["ext_alt_text"].as_str().map(|s| clipped(s, 1000)),
        width,
        height,
        duration_ms: value
            .pointer("/video_info/duration_millis")
            .and_then(Value::as_u64)
            .filter(|v| *v <= 86_400_000),
        mp4,
        hls_url,
    })
}

pub fn parse_media(post: &Value) -> (Vec<Media>, bool) {
    let source = post
        .pointer("/legacy/extended_entities/media")
        .or_else(|| post.pointer("/legacy/entities/media"));
    let Some(source) = source else {
        return (vec![], true);
    };
    let Some(items) = source.as_array() else {
        return (vec![], false);
    };
    let media: Vec<_> = items
        .iter()
        .take(16)
        .enumerate()
        .filter_map(|(i, v)| parse_one_media(v, i))
        .collect();
    let complete = media.len() == items.len();
    (media, complete)
}

// ─── Optional secret-free provider: FixTweet (api.fxtwitter.com) ─────────────
// Port addition ("better solution" evaluation): a public JSON API that needs no operator
// credential and no rotating GraphQL operation IDs. Same fixed-host transport, DNS
// pinning, public-address check, no redirects, 5 s / 1 MiB bounds as the guest provider,
// and the same normalized TweetPreview. It supplies no text entities and no trustworthy
// verification flags, so those stay empty/unknown; unsupported counts stay "unsupported".
// Its response shape follows the provider's public documentation; live compatibility is
// unverified (offline fixture only).

fn fx_metric(post: &Value, field: &str) -> Metric {
    match post.get(field) {
        None => Metric::unknown(MetricState::Unsupported),
        Some(value) => Metric::parse(value),
    }
}

fn fx_author(post: &Value) -> Option<Author> {
    let author = post.get("author").filter(|v| v.is_object())?;
    Some(Author {
        id: optional_id(&author["id"]),
        name: clipped(author["name"].as_str().unwrap_or(""), 256),
        handle: optional_handle(&author["screen_name"]),
        avatar_url: author["avatar_url"].as_str().and_then(|s| validate_media_url(s, false)),
        verification: Verification { legacy_verified: None, blue_verified: None },
    })
}

fn fx_media(post: &Value) -> (Vec<Media>, bool) {
    let Some(items) = post.pointer("/media/all") else {
        return (vec![], true);
    };
    let Some(items) = items.as_array() else {
        return (vec![], false);
    };
    let mut media = Vec::new();
    for (index, item) in items.iter().take(16).enumerate() {
        let kind = match item["type"].as_str() {
            Some("photo") => MediaKind::Photo,
            Some("video") => MediaKind::Video,
            Some("gif") => MediaKind::AnimatedGif,
            _ => continue,
        };
        let image = if kind == MediaKind::Photo { &item["url"] } else { &item["thumbnail_url"] };
        let image = image.as_str().and_then(|s| validate_media_url(s, false));
        if kind == MediaKind::Photo && image.is_none() {
            continue;
        }
        let (mut mp4, mut hls_url) = (Vec::new(), None);
        for variant in item["variants"].as_array().into_iter().flatten().take(8) {
            let Some(url) = variant["url"].as_str().and_then(|s| validate_media_url(s, true)) else {
                continue;
            };
            match variant["content_type"].as_str() {
                Some("video/mp4") => mp4.push(VideoVariant {
                    url,
                    content_type: "video/mp4".into(),
                    bitrate: variant["bitrate"].as_u64(),
                    width: None,
                    height: None,
                }),
                Some("application/x-mpegURL" | "application/vnd.apple.mpegurl") if hls_url.is_none() => hls_url = Some(url),
                _ => (),
            }
        }
        if kind != MediaKind::Photo && mp4.is_empty() && item["format"].as_str() == Some("video/mp4") {
            if let Some(url) = item["url"].as_str().and_then(|s| validate_media_url(s, true)) {
                mp4.push(VideoVariant { url, content_type: "video/mp4".into(), bitrate: None, width: None, height: None });
            }
        }
        media.push(Media {
            id: format!("fx-media:{index}"),
            kind,
            thumbnail_url: image.clone(),
            original_url: image,
            alt_text: item["altText"].as_str().filter(|s| !s.is_empty()).map(|s| clipped(s, 1000)),
            width: dimension(&item["width"]),
            height: dimension(&item["height"]),
            duration_ms: item["duration"].as_f64().filter(|d| (0.0..=86_400.0).contains(d)).map(|d| (d * 1000.0) as u64),
            mp4,
            hls_url,
        });
    }
    let complete = media.len() == items.len();
    (media, complete)
}

fn fx_post(post: &Value, id: &str, now: DateTime<Utc>, depth: usize) -> Result<TweetPreview, PreviewError> {
    if post["id"].as_str() != Some(id) {
        return Err(PreviewError::UpstreamFailure);
    }
    let mut result = TweetPreview::unavailable(id, UnavailableReason::Unknown, now);
    let full = post["text"].as_str().unwrap_or("");
    let mut end = full.len().min(MAX_TEXT_BYTES);
    while !full.is_char_boundary(end) {
        end -= 1;
    }
    let (media, media_complete) = fx_media(post);
    if end == 0 && media.is_empty() {
        return Ok(result);
    }
    result.availability = Availability { state: AvailabilityState::Available, reason: None };
    result.author = fx_author(post);
    result.created_at = post["created_timestamp"]
        .as_i64()
        .and_then(|t| DateTime::from_timestamp(t, 0))
        .or_else(|| {
            post["created_at"].as_str().and_then(|s| {
                DateTime::parse_from_str(s, "%a %b %d %H:%M:%S %z %Y").ok().map(|t| t.with_timezone(&Utc))
            })
        })
        .map(utc_string);
    result.text = full[..end].into();
    result.text_source = if post["is_note_tweet"] == true { TextSource::Note } else { TextSource::Legacy };
    result.text_complete = end == full.len();
    result.metrics = Metrics {
        likes: fx_metric(post, "likes"),
        reposts: fx_metric(post, "retweets"),
        replies: fx_metric(post, "replies"),
        quotes: fx_metric(post, "quotes"),
        bookmarks: fx_metric(post, "bookmarks"),
        views: fx_metric(post, "views"),
    };
    result.media = media;
    result.media_complete = media_complete;
    let reply_id = optional_id(&post["replying_to_status"]);
    let handle = optional_handle(&post["replying_to"]);
    if reply_id.is_some() || handle.is_some() {
        result.reply = Some(ReplyContext { id: reply_id, author_handle: handle });
    }
    result.expires_at = utc_string(now + chrono::Duration::minutes(10));
    if let Some(quoted) = post.get("quote").filter(|v| v.is_object()) {
        let quote_id = optional_id(&quoted["id"]);
        result.quote = Quote {
            state: QuoteState::Unavailable,
            id: quote_id.clone(),
            url: quote_id.as_ref().map(|q| format!("https://x.com/i/status/{q}")),
            post: None,
            reason: Some("unknown".into()),
        };
        match quote_id {
            Some(q) if q == id => result.quote.reason = Some("cycle".into()),
            Some(_) if depth >= 1 => {
                result.quote.state = QuoteState::Omitted;
                result.quote.reason = Some("depth_limit".into());
            }
            Some(q) => {
                if let Ok(preview) = fx_post(quoted, &q, now, depth + 1) {
                    if preview.availability.state == AvailabilityState::Available {
                        result.quote.state = QuoteState::Available;
                        result.quote.reason = None;
                        result.quote.post = Some(Box::new(preview));
                    }
                }
            }
            None => {}
        }
        if result.quote.reason.as_deref() == Some("cycle") {
            result.quote.state = QuoteState::Omitted;
        }
    }
    Ok(result)
}

/// Normalize one FixTweet `/status/<id>` response (HTTP 200 body) for the requested ID.
pub fn parse_fx_response(body: &[u8], id: &str, now: DateTime<Utc>) -> Result<TweetPreview, PreviewError> {
    if !valid_id(id) || body.len() > 1024 * 1024 {
        return Err(PreviewError::UpstreamFailure);
    }
    let root: Value = serde_json::from_slice(body).map_err(|_| PreviewError::UpstreamFailure)?;
    if root["code"].as_u64() != Some(200) {
        return Err(PreviewError::UpstreamFailure);
    }
    let post = root.get("tweet").filter(|v| v.is_object()).ok_or(PreviewError::UpstreamFailure)?;
    let result = fx_post(post, id, now, 0)?;
    if serde_json::to_vec(&result).map_err(|_| PreviewError::UpstreamFailure)?.len() > 256 * 1024 {
        return Err(PreviewError::UpstreamFailure);
    }
    Ok(result)
}

/// A FixTweet error body is evidence only when its own code matches the HTTP status.
fn fx_unavailable_reason(status: u16, body: &[u8]) -> UnavailableReason {
    let data: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    match (status, data["code"].as_u64(), data["message"].as_str()) {
        (404, Some(404), Some("NOT_FOUND")) => UnavailableReason::NotFound,
        (401, Some(401), Some("PRIVATE_TWEET")) => UnavailableReason::Private,
        _ => UnavailableReason::Unknown,
    }
}

fn utf16_byte(text: &str, offset: usize) -> Option<usize> {
    let mut units = 0;
    for (byte, ch) in text.char_indices() {
        if units == offset {
            return Some(byte);
        }
        units += ch.len_utf16();
    }
    (units == offset).then_some(text.len())
}

fn entity_span(text: &str, token: &str, entity: &Value) -> Option<(u32, u32)> {
    if token.is_empty() {
        return None;
    }
    let mut candidates = Vec::new();
    if let Some(indices) = entity["indices"].as_array().filter(|v| v.len() == 2) {
        if let (Some(start), Some(end)) = (indices[0].as_u64(), indices[1].as_u64()) {
            if start < end && end <= text.len() as u64 {
                let (start, end) = (start as usize, end as usize);
                candidates.push(utf16_byte(text, start).zip(utf16_byte(text, end)));
                let scalar_byte = |i| {
                    text.char_indices()
                        .map(|(b, _)| b)
                        .chain([text.len()])
                        .nth(i)
                };
                candidates.push(scalar_byte(start).zip(scalar_byte(end)));
            }
        }
    }
    let mut matches: Vec<_> = candidates
        .into_iter()
        .flatten()
        .filter(|(a, b)| text.get(*a..*b) == Some(token))
        .collect();
    matches.sort_unstable();
    matches.dedup();
    let (start, end) = match matches.as_slice() {
        [span] => *span,
        [] => {
            let mut found = text.match_indices(token);
            let (start, _) = found.next()?;
            if found.next().is_some() {
                return None;
            }
            (start, start + token.len())
        }
        _ => return None,
    };
    Some((
        text[..start].encode_utf16().count() as u32,
        text[..end].encode_utf16().count() as u32,
    ))
}

fn normalize_entities(text: &str, source: &Value, media: &[Media]) -> Vec<TextEntity> {
    let mut entities = Vec::new();
    for (field, kind) in [
        ("media", EntityKind::Media),
        ("urls", EntityKind::Url),
        ("user_mentions", EntityKind::Mention),
        ("hashtags", EntityKind::Hashtag),
    ] {
        let Some(items) = source[field].as_array() else {
            continue;
        };
        for item in items.iter().take(100) {
            let (token, destination, display, media_id) = match kind {
                EntityKind::Mention => {
                    let Some(handle) = optional_handle(&item["screen_name"]) else {
                        continue;
                    };
                    (
                        format!("@{handle}"),
                        format!("https://x.com/{handle}"),
                        format!("@{handle}"),
                        None,
                    )
                }
                EntityKind::Hashtag => {
                    let Some(tag) = item["text"]
                        .as_str()
                        .filter(|s| !s.is_empty() && s.chars().count() <= 256)
                    else {
                        continue;
                    };
                    let mut url = reqwest::Url::parse("https://x.com/hashtag/").unwrap();
                    url.path_segments_mut().unwrap().pop_if_empty().push(tag);
                    (format!("#{tag}"), url.to_string(), format!("#{tag}"), None)
                }
                _ => {
                    let Some(token) = item["url"].as_str() else {
                        continue;
                    };
                    let Some(url) = item["expanded_url"]
                        .as_str()
                        .and_then(validate_navigation_url)
                    else {
                        continue;
                    };
                    let known = item["media_key"]
                        .as_str()
                        .or_else(|| item["id_str"].as_str())
                        .and_then(|id| media.iter().find(|m| m.id == id))
                        .map(|m| m.id.clone());
                    if kind == EntityKind::Media && known.is_none() {
                        continue;
                    }
                    (
                        token.into(),
                        url.clone(),
                        item["display_url"].as_str().unwrap_or(&url).into(),
                        known,
                    )
                }
            };
            let Some((start, end)) = entity_span(text, &token, item) else {
                continue;
            };
            entities.push(TextEntity {
                kind,
                start,
                end,
                url: destination,
                display: clipped(&display, 512),
                media_id,
            });
        }
    }
    // Stable ordering preserves media precedence for the same source span.
    entities.sort_by_key(|e| (e.start, if e.kind == EntityKind::Media { 0 } else { 1 }));
    let mut end = 0;
    entities
        .into_iter()
        .filter(|e| {
            if e.start < end {
                return false;
            }
            end = e.end;
            true
        })
        .take(100)
        .collect()
}

#[derive(Default)]
struct ThreadFragment {
    text: String,
    media: Vec<Media>,
    stack: Vec<String>,
    skipped: Vec<String>,
    tokens: usize,
    exceeded: bool,
    malformed: bool,
    /// Wall-clock deadline of the whole document's normalization; past it the sink stops
    /// the tokenizer (`timed_out`).
    deadline: Option<Instant>,
    timed_out: bool,
}

impl ThreadFragment {
    fn newline(&mut self) {
        if !self.text.is_empty() && !self.text.ends_with('\n') {
            self.text.push('\n');
        }
    }

    fn tag(&mut self, tag: html5ever::tokenizer::Tag) -> html5ever::tokenizer::TokenSinkResult<()> {
        use html5ever::tokenizer::{states::RawKind, EndTag, TokenSinkResult};
        let name = tag.name.as_ref();
        let blocked = matches!(
            name,
            "script" | "style" | "template" | "iframe" | "object" | "embed" | "noscript"
        );
        if tag.kind == EndTag {
            if !self.skipped.is_empty() {
                if self.skipped.last().is_some_and(|n| n == name) {
                    self.skipped.pop();
                }
            } else {
                if let Some(index) = self.stack.iter().rposition(|n| n == name) {
                    self.stack.truncate(index);
                }
                if matches!(
                    name,
                    "p" | "div" | "li" | "ul" | "ol" | "blockquote" | "h1" | "h2" | "h3"
                ) {
                    self.newline();
                }
            }
            return TokenSinkResult::Continue;
        }
        if name == "embed" {
            return TokenSinkResult::Continue;
        }
        if blocked {
            self.skipped.push(name.to_string());
            return match name {
                "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                "style" | "iframe" | "noscript" => TokenSinkResult::RawData(RawKind::Rawtext),
                _ => TokenSinkResult::Continue,
            };
        }
        if !self.skipped.is_empty() {
            return TokenSinkResult::Continue;
        }
        if name == "br" {
            self.text.push('\n');
        }
        if matches!(
            name,
            "p" | "div" | "li" | "ul" | "ol" | "blockquote" | "h1" | "h2" | "h3"
        ) {
            self.newline();
        }
        if name == "img" {
            let attribute = |name: &str| {
                tag.attrs
                    .iter()
                    .find(|a| &*a.name.local == name)
                    .map(|a| a.value.as_ref())
            };
            if let Some(url) = attribute("src").and_then(|s| validate_media_url(s, false)) {
                self.media.push(Media {
                    id: format!("tra-media:{}", self.media.len()),
                    kind: MediaKind::Photo,
                    thumbnail_url: Some(url.clone()),
                    original_url: Some(url),
                    alt_text: attribute("alt").map(|s| clipped(s, 1000)),
                    width: None,
                    height: None,
                    duration_ms: None,
                    mp4: vec![],
                    hls_url: None,
                });
            }
        }
        if !tag.self_closing
            && !matches!(
                name,
                "area"
                    | "base"
                    | "br"
                    | "col"
                    | "embed"
                    | "hr"
                    | "img"
                    | "input"
                    | "link"
                    | "meta"
                    | "param"
                    | "source"
                    | "track"
                    | "wbr"
            )
        {
            self.stack.push(name.to_string());
        }
        TokenSinkResult::Continue
    }
}

struct ThreadSink<'a>(
    std::cell::RefCell<ThreadFragment>,
    &'a html5ever::tokenizer::BufferQueue,
);
impl html5ever::tokenizer::TokenSink for ThreadSink<'_> {
    type Handle = ();
    fn process_token(
        &self,
        token: html5ever::tokenizer::Token,
        _: u64,
    ) -> html5ever::tokenizer::TokenSinkResult<()> {
        use html5ever::tokenizer::{Token, TokenSinkResult};
        let mut fragment = self.0.borrow_mut();
        if fragment.deadline.is_some_and(|d| Instant::now() >= d) {
            fragment.timed_out = true;
            fragment.exceeded = true;
        }
        if fragment.tokens >= 10000 || fragment.exceeded {
            fragment.exceeded = true;
            self.1.replace_with(Default::default());
            return TokenSinkResult::Continue;
        }
        fragment.tokens += 1;
        let result = match token {
            Token::CharacterTokens(text) if fragment.skipped.is_empty() => {
                if fragment.text.len() + text.len() > MAX_TEXT_BYTES {
                    fragment.exceeded = true;
                } else {
                    fragment.text.push_str(&text);
                }
                TokenSinkResult::Continue
            }
            Token::TagToken(tag) => fragment.tag(tag),
            Token::ParseError(_) => {
                fragment.malformed = true;
                TokenSinkResult::Continue
            }
            _ => TokenSinkResult::Continue,
        };
        if fragment.stack.len() > 64
            || fragment.skipped.len() > 64
            || fragment.media.len() > 16
            || fragment.text.len() > MAX_TEXT_BYTES
        {
            fragment.exceeded = true;
        }
        if fragment.exceeded {
            self.1.replace_with(Default::default());
            TokenSinkResult::Continue
        } else {
            result
        }
    }
}

/// Audit fix (thread parser CPU), second form after review: html5ever's tokenizer checks
/// each new attribute against all earlier ones of the tag (quadratic), and that work happens
/// inside feed() before any token reaches the sink, so neither a sink limit nor an outer
/// timeout can interrupt it, and a byte pre-scan can always be desynchronised from the
/// tokenizer's states. The hard limit is cooperative instead: each fragment is fed to the
/// tokenizer in THREAD_FEED_CHUNK pieces with the deadline checked between pieces (and on
/// every token in the sink), so at most one small chunk's worth of work can run past the
/// deadline. The document parse runs in spawn_blocking, at most THREAD_PARSE_SLOTS at a time
/// (the slot is released only when the blocking work returns), and a deadline hit puts the
/// ThreadReader provider on cooldown.
const THREAD_FEED_CHUNK: usize = 1024;
const THREAD_PARSE_BUDGET: Duration = Duration::from_secs(2);
const THREAD_PARSE_SLOTS: usize = 2;
const THREAD_TIMEOUT_COOLDOWN: Duration = Duration::from_secs(60);
/// Self-review fix: a parse timeout is first evidence about ONE (attacker-controllable)
/// document, so it goes into a small per-ID negative cache; only timeouts on several
/// distinct IDs within a window trip the provider-wide cooldown.
const THREAD_BAD_ID_TTL: Duration = Duration::from_secs(15 * 60);
const THREAD_BAD_IDS_MAX: usize = 256;
const THREAD_TIMEOUT_WINDOW: Duration = Duration::from_secs(5 * 60);
const THREAD_TIMEOUT_TRIP: usize = 3;

#[derive(Default)]
struct ThreadTimeouts {
    /// Consecutive ThreadReader 5xx responses (provider-wide 30/60/120… s backoff, ≤5 min).
    failures: u32,
    /// id → until (ticks)
    bad: HashMap<String, Duration>,
    /// (when, id) of recent timeouts, distinct ids, within THREAD_TIMEOUT_WINDOW
    recent: Vec<(Duration, String)>,
}

fn tokenize_thread_fragment(html: &str, deadline: Instant) -> ThreadFragment {
    use html5ever::tokenizer::{BufferQueue, Tokenizer, TokenizerOpts};
    let input = BufferQueue::default();
    let fragment = ThreadFragment { deadline: Some(deadline), ..Default::default() };
    let tokenizer = Tokenizer::new(
        ThreadSink(std::cell::RefCell::new(fragment), &input),
        TokenizerOpts::default(),
    );
    let mut rest = html;
    while !rest.is_empty() {
        if Instant::now() >= deadline {
            let mut fragment = tokenizer.sink.0.borrow_mut();
            fragment.timed_out = true;
            fragment.exceeded = true;
        }
        if tokenizer.sink.0.borrow().exceeded {
            break;
        }
        let mut cut = rest.len().min(THREAD_FEED_CHUNK);
        while !rest.is_char_boundary(cut) {
            cut += 1;
        }
        input.push_back(rest[..cut].into());
        rest = &rest[cut..];
        let _ = tokenizer.feed(&input);
    }
    if !tokenizer.sink.0.borrow().exceeded {
        tokenizer.end();
    }
    tokenizer.sink.0.into_inner()
}

/// Test convenience: normalize with the default budget, without the timeout flag.
#[cfg(test)]
pub fn parse_thread_content(
    body: &[u8],
    id: &str,
    now: DateTime<Utc>,
) -> Result<ThreadPreview, PreviewError> {
    parse_thread_content_within(body, id, now, THREAD_PARSE_BUDGET).map(|(preview, _)| preview)
}

/// Normalize within a wall-clock budget. The flag is true when the budget ran out (the
/// result is then partial and the caller treats it as a timeout).
fn parse_thread_content_within(
    body: &[u8],
    id: &str,
    now: DateTime<Utc>,
    budget: Duration,
) -> Result<(ThreadPreview, bool), PreviewError> {
    let deadline = Instant::now() + budget;
    let mut timed_out = false;
    if !valid_id(id) || body.len() > 2 * 1024 * 1024 {
        return Err(PreviewError::UpstreamFailure);
    }
    let data: Value = serde_json::from_slice(body).map_err(|_| PreviewError::UpstreamFailure)?;
    if !data.is_object() {
        return Err(PreviewError::UpstreamFailure);
    }
    let mut result = ThreadPreview::unavailable(id, UnavailableReason::Unknown, now);
    if data["code"].as_i64().is_some_and(|code| code != 200)
        && data
            .get("content")
            .is_none_or(|v| v.is_null() || v.as_array().is_some_and(Vec::is_empty))
    {
        return Ok((result, false));
    }
    let root_id = optional_id(&data["id"]).or_else(|| data["id"].as_u64().map(|v| v.to_string()));
    if data["code"].as_i64() != Some(200) || root_id.as_deref() != Some(id) {
        return Err(PreviewError::UpstreamFailure);
    }
    let entries = data["content"]
        .as_array()
        .ok_or(PreviewError::UpstreamFailure)?;
    result.reported_count = data["size"].as_u64();
    result.partial = entries.len() > 20;
    for (index, html) in entries.iter().take(20).enumerate() {
        let Some(html) = html.as_str() else {
            result.partial = true;
            continue;
        };
        if Instant::now() >= deadline {
            timed_out = true;
            break;
        }
        let fragment = tokenize_thread_fragment(html, deadline);
        if fragment.timed_out {
            timed_out = true;
            break;
        }
        if fragment.exceeded {
            result.partial = true;
            continue;
        }
        let text = fragment.text.trim_matches('\n').to_string();
        if text.is_empty() && fragment.media.is_empty() {
            result.partial = true;
            continue;
        }
        // Audit fix: no content-based de-duplication. Entries carry no post identity here,
        // and equal text/media ("Yes.", a repeated image) does not prove the same post.
        result.entries.push(ThreadEntry {
            key: format!("tra:{id}:{index}"),
            id: None,
            url: None,
            author: None,
            created_at: None,
            text,
            entities: vec![],
            media: fragment.media,
            metrics: Metrics::unknown(MetricState::Unsupported),
        });
        result.partial = true; // This provider supplies no per-entry identities.
        if serde_json::to_vec(&result)
            .map_err(|_| PreviewError::UpstreamFailure)?
            .len()
            > 256 * 1024
        {
            result.entries.pop();
            result.partial = true;
        }
    }
    if result
        .reported_count
        .is_some_and(|count| count > result.entries.len() as u64)
    {
        result.partial = true;
    }
    if !result.entries.is_empty() {
        result.availability = Availability {
            state: AvailabilityState::Available,
            reason: None,
        };
        result.expires_at = utc_string(now + chrono::Duration::minutes(5));
    }
    if timed_out {
        result.partial = true;
    }
    Ok((result, timed_out))
}

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
    fn ticks(&self) -> Duration;
}

pub struct SystemClock(Instant);
impl Default for SystemClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
    fn ticks(&self) -> Duration {
        self.0.elapsed()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperationConfig {
    tweet_query_id: String,
    tweet_features: BTreeMap<String, bool>,
}

struct GuestConfig {
    bearer: String,
    operation: OperationConfig,
}

impl GuestConfig {
    fn load(get: impl Fn(&str) -> Option<String>) -> Result<Option<Self>, ()> {
        if get("CRYPTIRC_X_GUEST_ENABLED").as_deref() != Some("1") {
            return Ok(None);
        }
        let bearer = get("CRYPTIRC_X_GUEST_BEARER")
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or(())?;
        let config = if let Some(path) = get("CRYPTIRC_X_GRAPHQL_CONFIG") {
            use std::io::Read;
            if !std::path::Path::new(&path).is_absolute() {
                return Err(());
            }
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .map_err(|_| ())?
                .take(16 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| ())?;
            if bytes.len() > 16 * 1024 {
                return Err(());
            }
            bytes
        } else {
            include_bytes!("twitter/provider-config.json").to_vec()
        };
        let operation: OperationConfig = serde_json::from_slice(&config).map_err(|_| ())?;
        if !(1..=128).contains(&operation.tweet_query_id.len())
            || !operation
                .tweet_query_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(());
        }
        Ok(Some(Self { bearer, operation }))
    }
}

enum ProviderOperation {
    Activate,
    Thread {
        id: String,
    },
    FixTweet {
        id: String,
    },
    Tweet {
        id: String,
        query_id: String,
        features: String,
        guest: String,
    },
}

struct ProviderRequest {
    bearer: Option<String>,
    operation: ProviderOperation,
}

struct ProviderResponse {
    status: u16,
    retry_after: Option<String>,
    json: bool,
    body: Vec<u8>,
}

type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderResponse, PreviewError>> + Send + 'a>>;
trait TwitterTransport: Send + Sync {
    fn execute(&self, request: ProviderRequest) -> TransportFuture<'_>;
}

struct HttpTransport;
impl TwitterTransport for HttpTransport {
    fn execute(&self, request: ProviderRequest) -> TransportFuture<'_> {
        Box::pin(async move {
            let thread = matches!(&request.operation, ProviderOperation::Thread { .. });
            let host = match &request.operation {
                ProviderOperation::Thread { .. } => "threadreaderapp.com",
                ProviderOperation::FixTweet { .. } => "api.fxtwitter.com",
                _ => "api.x.com",
            };
            let timeout = Duration::from_secs(if thread { 8 } else { 5 });
            tokio::time::timeout(timeout, async {
                let addresses = crate::preview::resolve_and_validate_host(host, Some(443))
                    .await
                    .map_err(|_| PreviewError::UpstreamFailure)?;
                let client = crate::preview::build_pinned_client(host, &addresses)
                    .map_err(|_| PreviewError::UpstreamFailure)?;
                let (builder, limit) = match request.operation {
                    ProviderOperation::Thread { id } => (
                        client.get(format!(
                            "https://threadreaderapp.com/api/v0/thread/{id}.json"
                        )),
                        2 * 1024 * 1024,
                    ),
                    ProviderOperation::FixTweet { id } => (
                        client.get(format!("https://api.fxtwitter.com/status/{id}")),
                        1024 * 1024,
                    ),
                    ProviderOperation::Activate => (
                        client
                            .post("https://api.x.com/1.1/guest/activate.json")
                            .header("content-type", "application/json"),
                        16 * 1024,
                    ),
                    ProviderOperation::Tweet {
                        id,
                        query_id,
                        features,
                        guest,
                    } => {
                        let mut url = reqwest::Url::parse(&format!(
                            "https://api.x.com/graphql/{query_id}/TweetResultByRestId"
                        ))
                        .map_err(|_| PreviewError::UpstreamFailure)?;
                        let variables = serde_json::json!({"tweetId":id,"withCommunity":false,
                            "includePromotedContent":false,"withVoice":false})
                        .to_string();
                        url.query_pairs_mut()
                            .append_pair("variables", &variables)
                            .append_pair("features", &features);
                        (client.get(url).header("x-guest-token", guest), 1024 * 1024)
                    }
                };
                let builder = if let Some(bearer) = request.bearer {
                    builder
                        .bearer_auth(bearer)
                        .header("x-twitter-active-user", "yes")
                        .header("x-twitter-client-language", "en")
                } else {
                    builder
                };
                let response = builder
                    .timeout(timeout)
                    .send()
                    .await
                    .map_err(|_| PreviewError::UpstreamFailure)?;
                let status = response.status().as_u16();
                if (300..400).contains(&status)
                    || response.content_length().is_some_and(|n| n > limit as u64)
                {
                    return Err(PreviewError::UpstreamFailure);
                }
                let retry_after = response
                    .headers()
                    .get("retry-after")
                    .and_then(|h| h.to_str().ok())
                    .map(String::from);
                let json = response
                    .headers()
                    .get("content-type")
                    .and_then(|h| h.to_str().ok())
                    .is_some_and(|h| {
                        h.split(';')
                            .next()
                            .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
                    });
                let body = crate::preview::read_capped_body(response, limit + 1)
                    .await
                    .map_err(|_| PreviewError::UpstreamFailure)?;
                if body.len() > limit {
                    return Err(PreviewError::UpstreamFailure);
                }
                Ok(ProviderResponse {
                    status,
                    retry_after,
                    json,
                    body,
                })
            })
            .await
            .map_err(|_| PreviewError::Timeout)?
        })
    }
}

struct GuestToken {
    value: String,
    expires: Duration,
}
#[derive(Default)]
struct ProviderHealth {
    until: Duration,
    failures: u32,
}
impl ProviderHealth {
    /// Cooldowns only ever extend: a concurrent shorter one never cuts a longer one short.
    fn extend(&mut self, until: Duration) {
        self.until = self.until.max(until);
    }
}

pub struct TwitterClient {
    config: Option<GuestConfig>,
    transport: Arc<dyn TwitterTransport>,
    pub clock: Arc<dyn Clock>,
    guest: Mutex<Option<GuestToken>>,
    health: std::sync::Mutex<ProviderHealth>,
    thread_enabled: bool,
    thread_until: std::sync::Mutex<Duration>,
    /// CRYPTIRC_X_FXTWITTER_ENABLED=1: the secret-free FixTweet provider (used only when
    /// the guest provider is not configured).
    fx_enabled: bool,
    /// At most THREAD_PARSE_SLOTS thread documents are parsed at once; a slot is held by the
    /// blocking task itself until it returns.
    thread_parses: Arc<tokio::sync::Semaphore>,
    thread_parse_budget: Duration,
    thread_timeouts: std::sync::Mutex<ThreadTimeouts>,
    /// The guest provider was requested (CRYPTIRC_X_GUEST_ENABLED=1) but its configuration
    /// is invalid. Audit fix: post previews are then OFF — never a silent switch to another
    /// provider whose flag happens to be set.
    guest_invalid: bool,
}

impl TwitterClient {
    pub fn from_environment() -> Self {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let (config, guest_invalid) = match GuestConfig::load(&get) {
            Ok(config) => (config, false),
            Err(()) => {
                tracing::warn!("X post previews disabled: invalid guest provider configuration");
                (None, true)
            }
        };
        let mut client = Self::new(
            config,
            Arc::new(HttpTransport),
            Arc::new(SystemClock::default()),
        );
        client.guest_invalid = guest_invalid;
        client.thread_enabled = get("CRYPTIRC_X_THREADREADER_ENABLED").as_deref() == Some("1");
        client.fx_enabled = get("CRYPTIRC_X_FXTWITTER_ENABLED").as_deref() == Some("1");
        client
    }

    fn new(
        config: Option<GuestConfig>,
        transport: Arc<dyn TwitterTransport>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            config,
            transport,
            clock,
            guest: Mutex::new(None),
            health: Default::default(),
            thread_enabled: false,
            thread_until: Default::default(),
            thread_parses: Arc::new(tokio::sync::Semaphore::new(THREAD_PARSE_SLOTS)),
            thread_parse_budget: THREAD_PARSE_BUDGET,
            thread_timeouts: Default::default(),
            fx_enabled: false,
            guest_invalid: false,
        }
    }

    pub fn enabled(&self) -> bool {
        !self.guest_invalid && (self.config.is_some() || self.fx_enabled)
    }

    pub fn thread_enabled(&self) -> bool {
        self.thread_enabled
    }

    pub async fn fetch_thread(&self, id: &str) -> Result<ThreadPreview, PreviewError> {
        if !valid_id(id) {
            return Err(PreviewError::InvalidUrl);
        }
        if !self.thread_enabled {
            return Ok(ThreadPreview::unavailable(
                id,
                UnavailableReason::ProviderDisabled,
                self.clock.now(),
            ));
        }
        let until = *self.thread_until.lock().unwrap_or_else(|e| e.into_inner());
        let now = self.clock.ticks();
        if until > now {
            return Err(PreviewError::RateLimited((until - now).as_secs().max(1)));
        }
        {
            let mut timeouts = self.thread_timeouts.lock().unwrap_or_else(|e| e.into_inner());
            timeouts.bad.retain(|_, until| *until > now);
            if let Some(until) = timeouts.bad.get(id) {
                return Err(PreviewError::RateLimited((*until - now).as_secs().max(1)));
            }
        }
        let response = tokio::time::timeout(
            Duration::from_secs(8),
            self.transport.execute(ProviderRequest {
                bearer: None,
                operation: ProviderOperation::Thread { id: id.into() },
            }),
        )
        .await
        .map_err(|_| PreviewError::Timeout)??;
        if response.status == 429 {
            let delay = retry_after_seconds(response.retry_after.as_deref(), self.clock.now());
            let mut until = self.thread_until.lock().unwrap_or_else(|e| e.into_inner());
            *until = (*until).max(self.clock.ticks() + Duration::from_secs(delay));
            return Err(PreviewError::RateLimited(delay));
        }
        if response.status == 404 {
            return Ok(ThreadPreview::unavailable(
                id,
                UnavailableReason::Unknown,
                self.clock.now(),
            ));
        }
        if response.status >= 500 {
            // Re-check fix: the same provider-wide 5xx backoff as the post providers.
            let delay = {
                let mut timeouts = self.thread_timeouts.lock().unwrap_or_else(|e| e.into_inner());
                timeouts.failures = timeouts.failures.saturating_add(1);
                30u64.saturating_mul(1u64 << timeouts.failures.saturating_sub(1).min(4)).min(300)
            };
            let mut until = self.thread_until.lock().unwrap_or_else(|e| e.into_inner());
            *until = (*until).max(self.clock.ticks() + Duration::from_secs(delay));
            return Err(PreviewError::UpstreamFailure);
        }
        if !(200..300).contains(&response.status) || !response.json {
            return Err(PreviewError::UpstreamFailure);
        }
        // Tokenizing is synchronous CPU work: it runs on the blocking pool, cooperatively
        // bounded by its own deadline, at most THREAD_PARSE_SLOTS at once (busy otherwise).
        // The slot moves into the blocking task, so it is released only when that work has
        // really returned — never by an outer timeout.
        let slot = self.thread_parses.clone().try_acquire_owned().map_err(|_| PreviewError::Busy)?;
        let key = id.to_owned();
        let (body, id, now, budget) = (response.body, id.to_owned(), self.clock.now(), self.thread_parse_budget);
        let parsed = tokio::task::spawn_blocking(move || {
            let _slot = slot;
            parse_thread_content_within(&body, &id, now, budget)
        })
        .await
        .map_err(|_| PreviewError::UpstreamFailure)?;
        match parsed {
            Ok((preview, false)) => {
                self.thread_timeouts.lock().unwrap_or_else(|e| e.into_inner()).failures = 0;
                Ok(preview)
            }
            Ok((_, true)) => {
                // An expensive document: don't re-fetch or re-parse THIS id for a while; trip
                // the provider-wide cooldown only after distinct ids keep timing out.
                let now = self.clock.ticks();
                let trip = {
                    let mut timeouts = self.thread_timeouts.lock().unwrap_or_else(|e| e.into_inner());
                    timeouts.bad.retain(|_, until| *until > now);
                    if timeouts.bad.len() >= THREAD_BAD_IDS_MAX {
                        let oldest = timeouts.bad.iter().min_by_key(|(_, until)| **until).map(|(k, _)| k.clone());
                        if let Some(oldest) = oldest {
                            timeouts.bad.remove(&oldest);
                        }
                    }
                    timeouts.bad.insert(key.clone(), now + THREAD_BAD_ID_TTL);
                    timeouts
                        .recent
                        .retain(|(at, other)| now.saturating_sub(*at) < THREAD_TIMEOUT_WINDOW && *other != key);
                    timeouts.recent.push((now, key));
                    let trip = timeouts.recent.len() >= THREAD_TIMEOUT_TRIP;
                    if trip {
                        timeouts.recent.clear();
                    }
                    trip
                };
                if trip {
                    let mut until = self.thread_until.lock().unwrap_or_else(|e| e.into_inner());
                    *until = (*until).max(now + THREAD_TIMEOUT_COOLDOWN);
                }
                Err(PreviewError::Timeout)
            }
            Err(error) => Err(error),
        }
    }

    fn cooldown(&self) -> Result<(), PreviewError> {
        let until = self.health.lock().unwrap_or_else(|e| e.into_inner()).until;
        let now = self.clock.ticks();
        if until > now {
            return Err(PreviewError::RateLimited((until - now).as_secs().max(1)));
        }
        Ok(())
    }

    fn check_status(&self, response: &ProviderResponse) -> Result<(), PreviewError> {
        let mut health = self.health.lock().unwrap_or_else(|e| e.into_inner());
        if response.status == 429 {
            let delay = retry_after_seconds(response.retry_after.as_deref(), self.clock.now());
            health.extend(self.clock.ticks() + Duration::from_secs(delay));
            return Err(PreviewError::RateLimited(delay));
        }
        if response.status >= 500 {
            health.failures = health.failures.saturating_add(1);
            let delay = 30u64
                .saturating_mul(1u64 << health.failures.saturating_sub(1).min(4))
                .min(300);
            health.extend(self.clock.ticks() + Duration::from_secs(delay));
            return Err(PreviewError::UpstreamFailure);
        }
        Ok(())
    }

    /// A success ends the consecutive-5xx streak. Audit fix: it must not erase a cooldown
    /// (Retry-After / drift / backoff) that another concurrent request established.
    fn mark_healthy(&self) {
        self.health.lock().unwrap_or_else(|e| e.into_inner()).failures = 0;
    }

    async fn token(&self, rejected: Option<&str>) -> Result<String, PreviewError> {
        let config = self.config.as_ref().ok_or(PreviewError::UpstreamFailure)?;
        // Holding this one token mutex coalesces activation, including concurrent
        // expiry responses. Cache/registry locks are never held during transport.
        let mut token = self.guest.lock().await;
        if let Some(current) = token
            .as_ref()
            .filter(|t| t.expires > self.clock.ticks() && rejected != Some(t.value.as_str()))
        {
            return Ok(current.value.clone());
        }
        *token = None;
        self.cooldown()?;
        let response = self
            .transport
            .execute(ProviderRequest {
                bearer: Some(config.bearer.clone()),
                operation: ProviderOperation::Activate,
            })
            .await?;
        self.check_status(&response)?;
        if !(200..300).contains(&response.status)
            || !response.json
            || response.body.len() > 16 * 1024
        {
            return Err(PreviewError::UpstreamFailure);
        }
        let data: Value =
            serde_json::from_slice(&response.body).map_err(|_| PreviewError::UpstreamFailure)?;
        let value = data["guest_token"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 512 && s.bytes().all(|b| b.is_ascii_graphic()))
            .ok_or(PreviewError::UpstreamFailure)?
            .to_string();
        *token = Some(GuestToken {
            value: value.clone(),
            expires: self.clock.ticks() + Duration::from_secs(90 * 60),
        });
        Ok(value)
    }

    pub async fn fetch_tweet(&self, id: &str) -> Result<TweetPreview, PreviewError> {
        if !valid_id(id) {
            return Err(PreviewError::InvalidUrl);
        }
        if !self.enabled() {
            return Ok(TweetPreview::unavailable(
                id,
                UnavailableReason::ProviderDisabled,
                self.clock.now(),
            ));
        }
        let work = async {
            if self.config.is_some() {
                self.fetch_tweet_inner(id).await
            } else {
                self.fetch_fx(id).await
            }
        };
        tokio::time::timeout(Duration::from_secs(12), work)
            .await
            .map_err(|_| PreviewError::Timeout)?
    }

    /// One FixTweet retrieval (no credentials, no retries); shares the 429/5xx backoff.
    async fn fetch_fx(&self, id: &str) -> Result<TweetPreview, PreviewError> {
        self.cooldown()?;
        let response = self
            .transport
            .execute(ProviderRequest { bearer: None, operation: ProviderOperation::FixTweet { id: id.into() } })
            .await?;
        self.check_status(&response)?;
        if matches!(response.status, 401 | 403 | 404) {
            return Ok(TweetPreview::unavailable(id, fx_unavailable_reason(response.status, &response.body), self.clock.now()));
        }
        if !(200..300).contains(&response.status) || !response.json {
            return Err(PreviewError::UpstreamFailure);
        }
        let mut preview = parse_fx_response(&response.body, id, self.clock.now())?;
        if self.thread_enabled {
            preview.thread = ThreadHint { state: ThreadState::Unknown, provider: Some("threadreader".into()), count: None };
        }
        self.mark_healthy();
        Ok(preview)
    }

    async fn fetch_tweet_inner(&self, id: &str) -> Result<TweetPreview, PreviewError> {
        self.cooldown()?;
        let config = self.config.as_ref().ok_or(PreviewError::UpstreamFailure)?;
        let mut guest = self.token(None).await?;
        for attempt in 0..=1 {
            self.cooldown()?;
            let response = self
                .transport
                .execute(ProviderRequest {
                    bearer: Some(config.bearer.clone()),
                    operation: ProviderOperation::Tweet {
                        id: id.into(),
                        query_id: config.operation.tweet_query_id.clone(),
                        features: serde_json::to_string(&config.operation.tweet_features)
                            .map_err(|_| PreviewError::UpstreamFailure)?,
                        guest: guest.clone(),
                    },
                })
                .await?;
            if response.status == 429 {
                self.check_status(&response)?;
            }
            let data: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
            if explicit_guest_expiry(&data) {
                if attempt == 0 {
                    guest = self.token(Some(&guest)).await?;
                    continue;
                }
                let mut cached = self.guest.lock().await;
                if cached.as_ref().is_some_and(|t| t.value == guest) {
                    *cached = None;
                }
                return Err(PreviewError::UpstreamFailure);
            }
            if provider_changed(&data) {
                self.health
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .extend(self.clock.ticks() + Duration::from_secs(60));
                return Err(PreviewError::ProviderChanged);
            }
            self.check_status(&response)?;
            if matches!(response.status, 403 | 404) {
                if let Ok(preview) = parse_tweet_response(&response.body, id, self.clock.now()) {
                    if preview.availability.state == AvailabilityState::Unavailable {
                        return Ok(preview);
                    }
                }
                return Ok(TweetPreview::unavailable(
                    id,
                    UnavailableReason::Unknown,
                    self.clock.now(),
                ));
            }
            if !(200..300).contains(&response.status) || !response.json {
                return Err(PreviewError::UpstreamFailure);
            }
            let mut preview = parse_tweet_response(&response.body, id, self.clock.now())?;
            if self.thread_enabled {
                preview.thread = ThreadHint {
                    state: ThreadState::Unknown,
                    provider: Some("threadreader".into()),
                    count: None,
                };
            }
            self.mark_healthy();
            return Ok(preview);
        }
        Err(PreviewError::UpstreamFailure)
    }
}

fn error_messages(data: &Value) -> impl Iterator<Item = String> + '_ {
    data["errors"]
        .as_array()
        .into_iter()
        .flatten()
        .take(100)
        .filter_map(|e| e["message"].as_str())
        .map(|m| m.trim().to_ascii_lowercase())
}

fn explicit_guest_expiry(data: &Value) -> bool {
    error_messages(data).any(|m| {
        matches!(
            m.as_str(),
            "bad guest token" | "invalid guest token" | "guest token expired"
        )
    })
}

fn provider_changed(data: &Value) -> bool {
    error_messages(data).any(|m| {
        matches!(
            m.as_str(),
            "persistedquerynotfound" | "persisted query not found" | "query not found"
        )
    })
}

fn retry_after_seconds(value: Option<&str>, now: DateTime<Utc>) -> u64 {
    let delay = value
        .and_then(|s| {
            s.trim().parse::<u64>().ok().or_else(|| {
                DateTime::parse_from_rfc2822(s)
                    .ok()
                    .map(|t| t.signed_duration_since(now).num_seconds().max(0) as u64)
            })
        })
        .unwrap_or(30);
    delay.clamp(30, 900)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-10-20T12:01:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }
    fn raw(name: &str) -> Value {
        let text = match name {
            "basic" => include_str!("twitter/fixtures/raw/basic.json"),
            "visibility" => include_str!("twitter/fixtures/raw/visibility.json"),
            "note" => include_str!("twitter/fixtures/raw/note.json"),
            "media" => include_str!("twitter/fixtures/raw/media.json"),
            "restricted" => include_str!("twitter/fixtures/raw/restricted.json"),
            _ => panic!("unknown fixture"),
        };
        serde_json::from_str(text).unwrap()
    }
    fn parse(value: &Value) -> Result<TweetPreview, PreviewError> {
        parse_tweet_response(&serde_json::to_vec(value).unwrap(), "123", now())
    }

    #[derive(Default)]
    pub(crate) struct FakeClock(std::sync::atomic::AtomicU64);
    impl FakeClock {
        pub(crate) fn advance(&self, seconds: u64) {
            self.0
                .fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
        }
    }
    impl Clock for FakeClock {
        fn now(&self) -> DateTime<Utc> {
            now() + chrono::Duration::seconds(self.ticks().as_secs() as i64)
        }
        fn ticks(&self) -> Duration {
            Duration::from_secs(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }
    struct FakeTransport {
        responses: std::sync::Mutex<std::collections::VecDeque<ProviderResponse>>,
        calls: std::sync::Mutex<Vec<&'static str>>,
    }
    impl TwitterTransport for FakeTransport {
        fn execute(&self, request: ProviderRequest) -> TransportFuture<'_> {
            let label = match request.operation {
                ProviderOperation::Activate => "activate",
                ProviderOperation::Tweet { .. } => "tweet",
                ProviderOperation::FixTweet { .. } => {
                    assert!(request.bearer.is_none(), "FixTweet never receives the operator bearer");
                    "fx"
                }
                ProviderOperation::Thread { .. } => {
                    assert!(request.bearer.is_none());
                    "thread"
                }
            };
            self.calls.lock().unwrap().push(label);
            let response = self
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or(PreviewError::UpstreamFailure);
            Box::pin(async move {
                tokio::task::yield_now().await;
                response
            })
        }
    }
    fn response(status: u16, body: Value) -> ProviderResponse {
        ProviderResponse {
            status,
            retry_after: None,
            json: true,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }
    fn activate() -> ProviderResponse {
        response(200, serde_json::json!({"guest_token":"synthetic-guest"}))
    }
    fn client(
        responses: Vec<ProviderResponse>,
    ) -> (Arc<TwitterClient>, Arc<FakeTransport>, Arc<FakeClock>) {
        let transport = Arc::new(FakeTransport {
            responses: std::sync::Mutex::new(responses.into()),
            calls: Default::default(),
        });
        let clock = Arc::new(FakeClock::default());
        let config = GuestConfig::load(|key| match key {
            "CRYPTIRC_X_GUEST_ENABLED" => Some("1".into()),
            "CRYPTIRC_X_GUEST_BEARER" => Some("synthetic-bearer".into()),
            _ => None,
        })
        .unwrap();
        (
            Arc::new(TwitterClient::new(config, transport.clone(), clock.clone())),
            transport,
            clock,
        )
    }

    pub(crate) fn fixture_client(
        calls: Arc<std::sync::atomic::AtomicUsize>,
        clock: Arc<FakeClock>,
    ) -> TwitterClient {
        struct FixtureTransport(Arc<std::sync::atomic::AtomicUsize>);
        impl TwitterTransport for FixtureTransport {
            fn execute(&self, request: ProviderRequest) -> TransportFuture<'_> {
                let response = match request.operation {
                    ProviderOperation::Activate | ProviderOperation::FixTweet { .. } => activate(),
                    ProviderOperation::Thread { id } => {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        response(
                            200,
                            serde_json::json!({"code":200,"id":id,"size":5,"content":["First","Second","Third","Fourth","Fifth"]}),
                        )
                    }
                    ProviderOperation::Tweet { id, .. } => {
                        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        let mut data = raw("basic");
                        data["data"]["tweetResult"]["result"]["rest_id"] = id.into();
                        response(200, data)
                    }
                };
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    Ok(response)
                })
            }
        }
        let mut client = client(vec![]).0;
        let client = Arc::get_mut(&mut client).unwrap();
        TwitterClient::new(
            client.config.take(),
            Arc::new(FixtureTransport(calls)),
            clock,
        )
    }

    pub(crate) fn fixture_thread_client(
        calls: Arc<std::sync::atomic::AtomicUsize>,
        clock: Arc<FakeClock>,
    ) -> TwitterClient {
        let mut client = fixture_client(calls, clock);
        client.thread_enabled = true;
        client
    }

    #[tokio::test(start_paused = true)]
    async fn transport_optional_thread_independent_disabled_limits_and_rate() {
        let body = serde_json::json!({"code":200,"id":"123","content":["First"]});
        let (mut client, transport, _) = client(vec![response(200, body)]);
        assert_eq!(
            client
                .fetch_thread("123")
                .await
                .unwrap()
                .availability
                .reason,
            Some(UnavailableReason::ProviderDisabled)
        );
        assert!(transport.calls.lock().unwrap().is_empty());
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.thread_enabled = true;
        assert_eq!(client.fetch_thread("123").await.unwrap().entries.len(), 1);
        assert_eq!(*transport.calls.lock().unwrap(), vec!["thread"]);
        for response in [
            response(200, Value::Null),
            response(302, Value::Null),
            ProviderResponse {
                status: 200,
                json: true,
                retry_after: None,
                body: vec![b' '; 2 * 1024 * 1024 + 1],
            },
        ] {
            let (mut client, transport, _) = self::client(vec![response]);
            Arc::get_mut(&mut client).unwrap().thread_enabled = true;
            assert!(client.fetch_thread("123").await.is_err());
            assert_eq!(transport.calls.lock().unwrap().len(), 1);
        }
        let mut rate = response(429, Value::Null);
        rate.retry_after = Some("60".into());
        let (mut client, transport, _) = self::client(vec![rate]);
        Arc::get_mut(&mut client).unwrap().thread_enabled = true;
        assert_eq!(
            client.fetch_thread("123").await.unwrap_err(),
            PreviewError::RateLimited(60)
        );
        assert_eq!(
            client.fetch_thread("123").await.unwrap_err(),
            PreviewError::RateLimited(60)
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn transport_absolute_deadline_and_configuration_caps() {
        struct NeverTransport;
        impl TwitterTransport for NeverTransport {
            fn execute(&self, _: ProviderRequest) -> TransportFuture<'_> {
                Box::pin(std::future::pending())
            }
        }
        let mut client = client(vec![]).0;
        Arc::get_mut(&mut client).unwrap().transport = Arc::new(NeverTransport);
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::Timeout
        );
        assert!(client.guest.try_lock().is_ok());
        Arc::get_mut(&mut client).unwrap().thread_enabled = true;
        assert_eq!(
            client.fetch_thread("123").await.unwrap_err(),
            PreviewError::Timeout
        );
        assert!(
            crate::preview::resolve_and_validate_host("localhost", Some(443))
                .await
                .is_err()
        );
        assert!(
            crate::preview::resolve_and_validate_host("127.0.0.1", Some(443))
                .await
                .is_err()
        );
        let path = std::env::temp_dir().join(format!("cryptirc-x-config-{}", uuid::Uuid::new_v4()));
        for bytes in [
            vec![b' '; 16 * 1024 + 1],
            b"{\"tweet_query_id\":\"../evil\",\"tweet_features\":{}}".to_vec(),
            b"{\"tweet_query_id\":\"valid\",\"tweet_features\":{\"flag\":1}}".to_vec(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(GuestConfig::load(|key| match key {
                "CRYPTIRC_X_GUEST_ENABLED" => Some("1".into()),
                "CRYPTIRC_X_GUEST_BEARER" => Some("synthetic".into()),
                "CRYPTIRC_X_GRAPHQL_CONFIG" => Some(path.to_str().unwrap().into()),
                _ => None,
            })
            .is_err());
        }
        std::fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn transport_disabled_invalid_and_coalesced_activation() {
        assert!(GuestConfig::load(|_| None).unwrap().is_none());
        for bearer in [None, Some(""), Some("bad\nheader"), Some("Bearer token")] {
            assert!(GuestConfig::load(|key| match key {
                "CRYPTIRC_X_GUEST_ENABLED" => Some("1".into()),
                "CRYPTIRC_X_GUEST_BEARER" => bearer.map(String::from),
                _ => None,
            })
            .is_err());
        }
        let (mut disabled, transport, clock) = client(vec![]);
        Arc::get_mut(&mut disabled).unwrap().config = None;
        assert_eq!(
            disabled
                .fetch_tweet("123")
                .await
                .unwrap()
                .availability
                .reason,
            Some(UnavailableReason::ProviderDisabled)
        );
        assert_eq!(
            disabled.fetch_tweet("bad").await.unwrap_err(),
            PreviewError::InvalidUrl
        );
        assert!(transport.calls.lock().unwrap().is_empty());
        let (client, transport, _) = client(vec![
            activate(),
            response(200, raw("basic")),
            response(200, raw("basic")),
        ]);
        let (a, b) = tokio::join!(client.fetch_tweet("123"), client.fetch_tweet("123"));
        assert!(a.is_ok() && b.is_ok());
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec!["activate", "tweet", "tweet"]
        );
        clock.advance(1);
    }

    #[tokio::test]
    async fn transport_expiry_retry_once_and_token_age() {
        let expired = || {
            response(
                403,
                serde_json::json!({"errors":[{"message":"  Invalid Guest Token "}]}),
            )
        };
        let (client, transport, clock) = client(vec![
            activate(),
            expired(),
            activate(),
            response(200, raw("basic")),
            activate(),
            response(200, raw("basic")),
        ]);
        assert!(client.fetch_tweet("123").await.is_ok());
        assert_eq!(
            *transport.calls.lock().unwrap(),
            vec!["activate", "tweet", "activate", "tweet"]
        );
        clock.advance(90 * 60);
        assert!(client.fetch_tweet("123").await.is_ok());
        assert_eq!(
            transport
                .calls
                .lock()
                .unwrap()
                .iter()
                .filter(|v| **v == "activate")
                .count(),
            3
        );
        let (client, transport, _) =
            self::client(vec![activate(), expired(), activate(), expired()]);
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::UpstreamFailure
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 4);
        assert!(client.guest.lock().await.is_none());
        for message in [
            "Forbidden",
            "Could not authenticate",
            "expired",
            "Invalid guest token extra",
        ] {
            assert!(!explicit_guest_expiry(
                &serde_json::json!({"errors":[{"code":239,"message":message}]})
            ));
        }
    }

    #[tokio::test]
    async fn transport_generic_auth_rate_change_and_backoff() {
        for status in [403, 404] {
            let (client, transport, _) = client(vec![
                activate(),
                response(
                    status,
                    serde_json::json!({"errors":[{"code":239,"message":"Forbidden"}]}),
                ),
            ]);
            assert_eq!(
                client.fetch_tweet("123").await.unwrap().availability.reason,
                Some(UnavailableReason::Unknown)
            );
            assert_eq!(*transport.calls.lock().unwrap(), vec!["activate", "tweet"]);
        }
        let mut rate = response(429, Value::Null);
        rate.retry_after = Some("9000".into());
        let (client, transport, clock) =
            client(vec![activate(), rate, response(200, raw("basic"))]);
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(900)
        );
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(900)
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 2);
        clock.advance(900);
        assert!(client.fetch_tweet("123").await.is_ok());
        let (client, transport, clock) = self::client(vec![
            activate(),
            response(500, Value::Null),
            response(503, Value::Null),
            response(200, raw("basic")),
            response(500, Value::Null),
        ]);
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::UpstreamFailure
        );
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(30)
        );
        clock.advance(30);
        assert!(client.fetch_tweet("123").await.is_err());
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(60)
        );
        clock.advance(60);
        assert!(client.fetch_tweet("123").await.is_ok());
        assert!(client.fetch_tweet("123").await.is_err());
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(30)
        );
        assert_eq!(transport.calls.lock().unwrap().len(), 5);
        let (client, _, _) = self::client(vec![
            activate(),
            response(
                400,
                serde_json::json!({"errors":[{"message":"PersistedQueryNotFound"}]}),
            ),
        ]);
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::ProviderChanged
        );
        assert_eq!(
            client.fetch_tweet("123").await.unwrap_err(),
            PreviewError::RateLimited(60)
        );
        for (value, expected) in [
            (None, 30),
            (Some("nonsense"), 30),
            (Some("1"), 30),
            (Some("120"), 120),
            (Some("Tue, 20 Oct 2026 12:03:00 GMT"), 120),
        ] {
            assert_eq!(retry_after_seconds(value, now()), expected);
        }
    }

    #[tokio::test]
    async fn transport_rejects_redirects_oversize_and_invalid_json() {
        for response in [
            response(302, Value::Null),
            ProviderResponse {
                status: 200,
                retry_after: None,
                json: false,
                body: b"<html>".to_vec(),
            },
            ProviderResponse {
                status: 200,
                retry_after: None,
                json: true,
                body: vec![b' '; 1024 * 1024 + 1],
            },
        ] {
            let (client, _, _) = client(vec![activate(), response]);
            assert_eq!(
                client.fetch_tweet("123").await.unwrap_err(),
                PreviewError::UpstreamFailure
            );
        }
        let (client, _, _) = client(vec![ProviderResponse {
            status: 200,
            retry_after: None,
            json: true,
            body: vec![b' '; 16 * 1024 + 1],
        }]);
        assert!(client.fetch_tweet("123").await.is_err());
    }

    #[test]
    fn parse_root_author_time_and_wrappers() {
        for name in ["basic", "visibility"] {
            let post = parse(&raw(name)).unwrap();
            assert_eq!(post.availability.state, AvailabilityState::Available);
            let author = post.author.unwrap();
            assert_eq!(author.name, "Core Name");
            assert_eq!(author.verification.legacy_verified, Some(false));
            assert_eq!(author.verification.blue_verified, Some(true));
            assert_eq!(post.created_at.as_deref(), Some("2026-10-20T12:00:00Z"));
        }
        let mut root = raw("basic");
        let post = &mut root["data"]["tweetResult"]["result"];
        post["core"]["user_results"]["result"]["core"] = Value::Null;
        assert_eq!(parse(&root).unwrap().author.unwrap().name, "Legacy Name");
        root["data"]["tweetResult"]["result"]["core"] = Value::Null;
        root["data"]["tweetResult"]["result"]["legacy"]["created_at"] = "bad".into();
        let post = parse(&root).unwrap();
        assert!(post.author.is_none());
        assert!(post.created_at.is_none());
        assert!(!post.text.is_empty());
        let mut wrapped = raw("basic")["data"]["tweetResult"]["result"].clone();
        for depth in 1..=4 {
            wrapped =
                serde_json::json!({"__typename":"TweetWithVisibilityResults", "tweet":wrapped});
            let result = parse(&serde_json::json!({"data":{"tweetResult":{"result":wrapped}}}));
            assert_eq!(result.is_ok(), depth <= 3);
        }
    }

    #[test]
    fn parse_availability_and_invalid_roots() {
        for (reason, expected) in [
            ("deleted", UnavailableReason::Deleted),
            ("not_found", UnavailableReason::NotFound),
            ("private", UnavailableReason::Private),
            ("restricted", UnavailableReason::Restricted),
            ("suspended", UnavailableReason::Suspended),
            ("vague", UnavailableReason::Unknown),
        ] {
            let mut root = raw("restricted");
            root["data"]["tweetResult"]["result"]["reason"] = reason.into();
            let parsed = parse(&root).unwrap();
            assert_eq!(parsed.availability.reason, Some(expected));
            assert!(parsed.author.is_none() && parsed.media.is_empty() && parsed.text.is_empty());
            assert!(!parsed.text_complete && !parsed.media_complete);
        }
        for text in [
            "{}",
            "null",
            "{\"data\":{\"tweetResult\":{\"result\":null}}}",
            "<html>",
            "not json",
        ] {
            assert!(parse_tweet_response(text.as_bytes(), "123", now()).is_err());
        }
        let mut root = raw("basic");
        root["data"]["tweetResult"]["result"]["rest_id"] = "124".into();
        assert!(parse(&root).is_err());
        root["data"]["tweetResult"]["result"]["rest_id"] = "123".into();
        root["data"]["tweetResult"]["result"]["__typename"] = "ChangedNesting".into();
        assert!(parse(&root).is_err());
        root["data"]["tweetResult"]["result"]["__typename"] = "Tweet".into();
        root["data"]["tweetResult"]["result"]["legacy"]["full_text"] = Value::Null;
        assert_eq!(
            parse(&root).unwrap().availability.reason,
            Some(UnavailableReason::Unknown)
        );
    }

    #[test]
    fn parse_supplied_quote_depth_cycle_and_unavailable() {
        let mut root: Value =
            serde_json::from_str(include_str!("twitter/fixtures/raw/quote.json")).unwrap();
        let preview = parse(&root).unwrap();
        assert_eq!(preview.quote.state, QuoteState::Available);
        let quote = preview.quote.post.unwrap();
        assert_eq!(quote.id, "124");
        assert_eq!(quote.quote.state, QuoteState::Omitted);
        assert_eq!(quote.quote.reason.as_deref(), Some("depth_limit"));
        assert_eq!(quote.fetched_at, preview.fetched_at);
        assert_eq!(quote.expires_at, preview.expires_at);
        root["data"]["tweetResult"]["result"]["legacy"]["quoted_status_id_str"] = "123".into();
        assert_eq!(parse(&root).unwrap().quote.reason.as_deref(), Some("cycle"));
        root["data"]["tweetResult"]["result"]["legacy"]["quoted_status_id_str"] = "124".into();
        root["data"]["tweetResult"]["result"]["quoted_status_result"]["result"] =
            serde_json::json!({"__typename":"TweetUnavailable","reason":"private"});
        assert_eq!(
            parse(&root).unwrap().quote.reason.as_deref(),
            Some("private")
        );
        root["data"]["tweetResult"]["result"]["quoted_status_result"] = Value::Null;
        assert_eq!(parse(&root).unwrap().quote.state, QuoteState::Unavailable);
    }

    #[test]
    fn parse_thread_hostile_html_order_and_unknown_identity() {
        let body = serde_json::json!({"code":200,"id":"123","size":5,"content":[
            "<p>First &amp; second<br>שלום 😀</p><script>evil()</script><template><img src='https://pbs.twimg.com/hidden.jpg'>hidden</template><iframe src='https://evil.test'>hidden</iframe><img src='https://pbs.twimg.com/media/one.jpg' alt='A &amp; B' onerror='evil()'><img src='https://evil.test/a.jpg'>",
            "<p>Next <a href='https://x.com/person/status/999'>a link</a></p><img src='https://pbs.twimg.com/media/two.jpg'>",
            "<p>Next <a href='https://x.com/person/status/999'>a link</a></p><img src='https://pbs.twimg.com/media/two.jpg'>",
            "&amp;lt;script&amp;gt;", "<style>bad</style><object>hidden</object><p>Last</p>"
        ]});
        let parsed =
            parse_thread_content(&serde_json::to_vec(&body).unwrap(), "123", now()).unwrap();
        assert_eq!(parsed.entries.len(), 5, "equal content is not proof of the same post");
        assert!(parsed.partial);
        assert_eq!(parsed.entries[0].text, "First & second\nשלום 😀");
        assert_eq!(parsed.entries[0].media.len(), 1);
        assert_eq!(
            parsed.entries[0].media[0].alt_text.as_deref(),
            Some("A & B")
        );
        assert_eq!(parsed.entries[1].text, "Next a link");
        assert_eq!(parsed.entries[2].text, "Next a link");
        assert_ne!(parsed.entries[1].key, parsed.entries[2].key);
        assert_eq!(parsed.entries[3].text, "&lt;script&gt;");
        assert_eq!(parsed.entries[4].text, "Last");
        for entry in parsed.entries {
            assert!(
                entry.id.is_none()
                    && entry.url.is_none()
                    && entry.author.is_none()
                    && entry.created_at.is_none()
            );
            assert_eq!(entry.metrics.likes.state, MetricState::Unsupported);
        }
    }

    #[test]
    fn parse_thread_limits_dedup_and_contract() {
        for count in [1, 5, 20, 21] {
            let body = serde_json::json!({"code":200,"id":"123","size":count,"content":(0..count).map(|i|format!("<p>Entry {i}</p>")).collect::<Vec<_>>()});
            let parsed =
                parse_thread_content(&serde_json::to_vec(&body).unwrap(), "123", now()).unwrap();
            assert_eq!(parsed.entries.len(), count.min(20));
            assert!(parsed.partial);
            assert_eq!(parsed.entries[0].key, "tra:123:0");
        }
        for html in [
            "x".repeat(32769),
            "<b></b>".repeat(5001),
            format!("{}text{}", "<div>".repeat(65), "</div>".repeat(65)),
            "<img src='https://pbs.twimg.com/a.jpg'>".repeat(17),
        ] {
            let body = serde_json::json!({"code":200,"id":"123","content":[html,"safe"]});
            let parsed =
                parse_thread_content(&serde_json::to_vec(&body).unwrap(), "123", now()).unwrap();
            assert_eq!(parsed.entries.len(), 1);
            assert_eq!(parsed.entries[0].text, "safe");
            assert!(parsed.partial);
        }
        let body = serde_json::json!({"code":200,"id":"123","content":(0..20).map(|i|format!("{i}{}","x".repeat(32000))).collect::<Vec<_>>()});
        let parsed =
            parse_thread_content(&serde_json::to_vec(&body).unwrap(), "123", now()).unwrap();
        assert!(
            parsed.entries.len() < 20 && serde_json::to_vec(&parsed).unwrap().len() <= 256 * 1024
        );
        assert!(parse_thread_content(b"{}", "123", now()).is_err());
        assert!(parse_thread_content(
            b"{\"code\":200,\"id\":\"124\",\"content\":[]}",
            "123",
            now()
        )
        .is_err());
        assert_eq!(
            parse_thread_content(b"{\"code\":404}", "123", now())
                .unwrap()
                .availability
                .state,
            AvailabilityState::Unavailable
        );
    }

    #[test]
    fn parse_note_unicode_wrappers_gating_and_partial_legacy() {
        let wrapped: Value = serde_json::from_str(include_str!(
            "twitter/fixtures/raw/note-unicode-wrapped.json"
        ))
        .unwrap();
        let note = parse(&wrapped).unwrap();
        assert_eq!(note.text_source, TextSource::Note);
        assert!(note.text_complete);
        assert!(
            note.text.contains("e\u{301} שלום\n") && note.text.contains("<img onerror=evil()>")
        );
        assert_eq!(note.entities.len(), 1);
        assert_eq!(note.entities[0].kind, EntityKind::Url);
        let mut gated = raw("note");
        gated["data"]["tweetResult"]["result"]["note_tweet"]["note_tweet_results"]["result"]
            ["is_gated"] = true.into();
        let preview = parse(&gated).unwrap();
        assert_eq!(preview.text_source, TextSource::Legacy);
        assert!(!preview.text_complete);
        let mut legacy = raw("basic");
        legacy["data"]["tweetResult"]["result"]["legacy"]["truncated"] = true.into();
        assert!(!parse(&legacy).unwrap().text_complete);
        let mut absent = raw("basic");
        absent["data"]["tweetResult"]["result"]["legacy"]
            .as_object_mut()
            .unwrap()
            .remove("truncated");
        assert!(parse(&absent).unwrap().text_complete);
        let oversized = "😀\u{301}".repeat(10000);
        gated["data"]["tweetResult"]["result"]["note_tweet"]["note_tweet_results"]["result"]
            ["is_gated"] = false.into();
        gated["data"]["tweetResult"]["result"]["note_tweet"]["note_tweet_results"]["result"]
            ["text"] = oversized.into();
        let clipped = parse(&gated).unwrap();
        assert!(clipped.text.len() <= 32768 && !clipped.text_complete);
    }

    #[test]
    fn parse_metrics_and_selected_entities() {
        let basic = parse(&raw("basic")).unwrap();
        assert_eq!(basic.metrics.likes.value.as_deref(), Some("0"));
        assert_eq!(
            basic.metrics.reposts.value.as_deref(),
            Some("18446744073709551615")
        );
        assert_eq!(basic.metrics.views.state, MetricState::Unavailable);
        assert_eq!(basic.entities.len(), 3);
        assert_eq!(basic.entities[0].start, 9);
        for bad in [
            serde_json::json!(true),
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("18446744073709551616"),
            serde_json::json!("01"),
            serde_json::json!("+1"),
        ] {
            assert_eq!(Metric::parse(&bad).state, MetricState::Unavailable);
        }
        let mut note = raw("note");
        let parsed = parse(&note).unwrap();
        assert_eq!(parsed.text_source, TextSource::Note);
        assert_eq!(parsed.entities.len(), 1);
        assert!(parsed.text.contains("<script>"));
        note["data"]["tweetResult"]["result"]["note_tweet"]["note_tweet_results"]["result"]
            ["entity_set"] = Value::Null;
        assert!(parse(&note).unwrap().entities.is_empty());
        let mut root = raw("basic");
        root["data"]["tweetResult"]["result"]["legacy"]["full_text"] = "😀".repeat(10000).into();
        let capped = parse(&root).unwrap();
        assert!(capped.text.len() <= MAX_TEXT_BYTES && !capped.text_complete);
        assert_eq!(
            entity_span("😀 @x", "@x", &serde_json::json!({"indices":[2,4]})),
            Some((3, 5))
        );
        assert!(entity_span("@x @x", "@x", &serde_json::json!({})).is_none());
        assert_eq!(
            entity_span("@x @x", "@x", &serde_json::json!({"indices":[3,5]})),
            Some((3, 5))
        );
        assert!(entity_span("😀", "😀", &serde_json::json!({"indices":[1,2]})).is_some());
    }

    #[test]
    fn parse_media_order_types_limits_and_optional_fields() {
        let mut root = raw("media");
        let parsed = parse(&root).unwrap();
        assert_eq!(parsed.media.len(), 3);
        assert!(parsed.media_complete);
        assert_eq!(parsed.media[0].width, Some(1600));
        assert_eq!(parsed.media[1].kind, MediaKind::AnimatedGif);
        assert!(parsed.media[1].mp4.is_empty());
        assert_eq!(parsed.media[2].mp4.len(), 1);
        assert!(parsed.media[2].mp4[0].width.is_none());
        assert!(parsed.media[2].hls_url.is_some());
        root["data"]["tweetResult"]["result"]["legacy"]["entities"]["media"] =
            serde_json::json!([{"type":"photo"}]);
        assert_eq!(parse(&root).unwrap().media.len(), 3);
        let post = &mut root["data"]["tweetResult"]["result"];
        post["legacy"]["extended_entities"]["media"][0]["media_url_https"] =
            "https://evil.test/a".into();
        let partial = parse(&root).unwrap();
        assert_eq!(partial.media.len(), 2);
        assert!(!partial.media_complete);
        let item = raw("media")["data"]["tweetResult"]["result"]["legacy"]["extended_entities"]
            ["media"][2]
            .clone();
        root["data"]["tweetResult"]["result"]["legacy"]["extended_entities"]["media"] =
            vec![item; 17].into();
        let capped = parse(&root).unwrap();
        assert_eq!(capped.media.len(), 16);
        assert!(!capped.media_complete);
        assert_eq!(dimension(&serde_json::json!(0)), None);
        assert_eq!(dimension(&serde_json::json!(32769)), None);
    }

    #[test]
    fn url_shared_table() {
        let table: Value =
            serde_json::from_str(include_str!("../scripts/fixtures/x-urls.json")).unwrap();
        for row in table.as_array().unwrap() {
            let input = row["url"].as_str().unwrap();
            let result = parse_tweet_url(input);
            assert_eq!(
                result.as_ref().map(|r| r.id.as_str()),
                row["id"].as_str(),
                "{input:?}"
            );
            if let Some(result) = result {
                assert_eq!(result.url, format!("https://x.com/i/status/{}", result.id));
            }
        }
    }

    #[test]
    fn url_media_and_navigation() {
        assert!(
            validate_media_url("https://pbs.twimg.com/media/a.jpg?name=small", false).is_some()
        );
        assert!(validate_media_url("https://video.twimg.com/a.mp4", true).is_some());
        for url in [
            "http://pbs.twimg.com/a.jpg",
            "https://pbs.twimg.com.evil/a.jpg",
            "https://pbs.twimg.com./a.jpg",
            "https://@pbs.twimg.com/a.jpg",
            "https://127.0.0.1/a",
            "https://pbs.twimg.com/a.svg",
            "https://pbs.twimg.com/a#x",
            "https://pbs.twimg.com:444/a",
            "https://pbs.twimg.com/a\n.jpg",
            "data:image/jpeg;base64,abc",
        ] {
            assert!(validate_media_url(url, false).is_none(), "{url:?}");
        }
        assert!(validate_navigation_url("https://example.org/a?q=x#fragment").is_some());
        assert!(validate_navigation_url("http://example.org/").is_some());
        for url in [
            "javascript:alert(1)",
            "//example.org/a",
            "https://u:p@example.org/",
            "https://@example.org/",
            "https://example.org/\n",
        ] {
            assert!(validate_navigation_url(url).is_none());
        }
    }

    #[test]
    fn proxy_media_paths_types_ranges_and_keys() {
        use ProxyMediaKind::*;
        for (url, kind) in [
            ("https://pbs.twimg.com/media/AbC_1-2.jpg?name=small", Image),
            ("https://pbs.twimg.com/media/AbC_1-2?format=webp&name=orig", Image),
            ("https://pbs.twimg.com/profile_images/1/x_normal.png", Image),
            ("https://pbs.twimg.com/ext_tw_video_thumb/1/pu/img/a.jpg", Image),
            ("https://pbs.twimg.com/tweet_video_thumb/a.jpg", Image),
            ("https://video.twimg.com/ext_tw_video/1/pu/vid/640x360/a.mp4?tag=12", Mp4),
            ("https://video.twimg.com/amplify_video/1/vid/avc1/a.mp4", Mp4),
            ("https://video.twimg.com/tweet_video/a.mp4", Mp4),
        ] {
            assert_eq!(validate_proxy_media_url(url).map(|(_, k)| k), Some(kind), "{url}");
        }
        for url in [
            "https://pbs.twimg.com/avatar.jpg",
            "https://pbs.twimg.com/media/",
            "https://pbs.twimg.com/media/a",
            "https://pbs.twimg.com/media/a.svg",
            "https://pbs.twimg.com/media/a.html",
            "https://pbs.twimg.com/media/a?format=svg",
            "https://pbs.twimg.com/media/a.jpg?format=html",
            "https://pbs.twimg.com/media/a.jpg?name=small&x=1",
            "https://pbs.twimg.com/media/a.jpg?name=a%2Fb",
            "https://pbs.twimg.com/media/../media/a.jpg",
            "https://pbs.twimg.com/media/a.mp4",
            "https://video.twimg.com/ext_tw_video/1/pu/pl/a.m3u8",
            "https://video.twimg.com/ext_tw_video/1/pu/vid/a.m4s",
            "https://video.twimg.com/ext_tw_video/1/pu/vid/a.ts",
            "https://video.twimg.com/media/a.jpg",
            "https://video.twimg.com/tweet_video/a.mp4?name=x",
            "https://video.twimg.com/synthetic/video/640x360.mp4",
            "http://pbs.twimg.com/media/a.jpg",
            "https://pbs.twimg.com:444/media/a.jpg",
            "https://evil.test/media/a.jpg",
        ] {
            assert!(validate_proxy_media_url(url).is_none(), "{url}");
        }
        assert_eq!(proxy_content_type(Image, Some("image/JPEG; charset=x")), Some("image/jpeg"));
        assert_eq!(proxy_content_type(Mp4, Some("video/mp4")), Some("video/mp4"));
        for (kind, value) in [
            (Image, Some("text/html")),
            (Image, Some("image/svg+xml")),
            (Image, Some("video/mp4")),
            (Mp4, Some("application/vnd.apple.mpegurl")),
            (Mp4, Some("application/x-mpegURL")),
            (Mp4, Some("image/png")),
            (Mp4, None),
        ] {
            assert_eq!(proxy_content_type(kind, value), None, "{value:?}");
        }
        for ok in ["bytes=0-", "bytes=0-1023", "bytes=5-5", "bytes=-500", "bytes=18446744073709551614-"] {
            assert!(valid_media_range(ok), "{ok}");
        }
        for bad in ["bytes=", "bytes=-", "bytes=-0", "bytes=5-1", "bytes=0-1,3-4", "items=0-1", "bytes=abc", "bytes= 0-1", "bytes=99999999999999999999-"] {
            assert!(!valid_media_range(bad), "{bad}");
        }
        assert_eq!(
            media_asset_key("https://pbs.twimg.com/media/a.jpg?name=orig"),
            media_asset_key("https://pbs.twimg.com/media/a.jpg?name=small")
        );
        assert!(media_asset_key("https://evil.test/media/a.jpg").is_none());
        let mut keys = HashSet::new();
        collect_media_keys(&serde_json::to_value(parse(&raw("media")).unwrap()).unwrap(), &mut keys);
        assert!(keys.contains("pbs.twimg.com/media/photo.jpg") && keys.contains("video.twimg.com/a.mp4"));
    }

    #[tokio::test]
    async fn fxtwitter_optional_secret_free_provider() {
        let fixture: Value = serde_json::from_str(include_str!("twitter/fixtures/raw/fxtwitter.json")).unwrap();
        // Never used while the guest provider is configured.
        let (mut guest, transport, _) = client(vec![activate(), response(200, raw("basic"))]);
        Arc::get_mut(&mut guest).unwrap().fx_enabled = true;
        assert!(guest.fetch_tweet("123").await.is_ok());
        assert_eq!(*transport.calls.lock().unwrap(), vec!["activate", "tweet"]);
        // Off by default: no flag, no traffic.
        let (mut fx, transport, _) = client(vec![response(200, fixture.clone())]);
        Arc::get_mut(&mut fx).unwrap().config = None;
        assert!(!fx.enabled());
        assert_eq!(fx.fetch_tweet("123").await.unwrap().availability.reason, Some(UnavailableReason::ProviderDisabled));
        assert!(transport.calls.lock().unwrap().is_empty());
        Arc::get_mut(&mut fx).unwrap().fx_enabled = true;
        let post = fx.fetch_tweet("123").await.unwrap();
        assert_eq!(*transport.calls.lock().unwrap(), vec!["fx"]);
        assert_eq!(post.availability.state, AvailabilityState::Available);
        let author = post.author.as_ref().unwrap();
        assert_eq!((author.name.as_str(), author.handle.as_deref()), ("Example Author", Some("example_author")));
        assert!(author.verification.legacy_verified.is_none() && author.verification.blue_verified.is_none());
        assert_eq!(post.created_at.as_deref(), Some("2026-10-20T12:00:00Z"));
        assert!(post.text.contains("<b>literal</b>") && post.text_complete && post.entities.is_empty());
        assert_eq!(post.metrics.likes.value.as_deref(), Some("0"));
        assert_eq!(post.metrics.reposts.value.as_deref(), Some("18446744073709551615"));
        assert_eq!(post.metrics.quotes.state, MetricState::Unsupported);
        assert_eq!(post.metrics.views.state, MetricState::Unavailable);
        assert_eq!(post.media.len(), 3);
        assert!(!post.media_complete, "the non-CDN photo is dropped and reported");
        assert_eq!(post.media[1].mp4.len(), 2);
        assert!(post.media[1].hls_url.is_some() && post.media[1].duration_ms == Some(12_500));
        assert_eq!((post.media[2].kind, post.media[2].mp4.len()), (MediaKind::AnimatedGif, 1));
        assert_eq!(post.reply.as_ref().unwrap().id.as_deref(), Some("122"));
        assert_eq!(post.quote.state, QuoteState::Available);
        let quote = post.quote.post.as_ref().unwrap();
        assert_eq!((quote.id.as_str(), quote.quote.state), ("124", QuoteState::Omitted));
        // Error evidence only when the body's own code matches the status.
        for (status, body, reason) in [
            (404, serde_json::json!({"code":404,"message":"NOT_FOUND"}), UnavailableReason::NotFound),
            (401, serde_json::json!({"code":401,"message":"PRIVATE_TWEET"}), UnavailableReason::Private),
            (404, serde_json::json!({"code":500,"message":"NOT_FOUND"}), UnavailableReason::Unknown),
            (404, Value::Null, UnavailableReason::Unknown),
        ] {
            let (mut c, _, _) = client(vec![response(status, body)]);
            let c2 = Arc::get_mut(&mut c).unwrap();
            c2.config = None;
            c2.fx_enabled = true;
            assert_eq!(c.fetch_tweet("123").await.unwrap().availability.reason, Some(reason));
        }
        let mut wrong = fixture.clone();
        wrong["tweet"]["id"] = "999".into();
        let mut rate = response(429, Value::Null);
        rate.retry_after = Some("120".into());
        let (mut c, transport, clock) = client(vec![
            response(200, wrong),
            ProviderResponse { status: 200, retry_after: None, json: false, body: b"<html>".to_vec() },
            rate,
            response(500, Value::Null),
        ]);
        let c2 = Arc::get_mut(&mut c).unwrap();
        c2.config = None;
        c2.fx_enabled = true;
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::RateLimited(120));
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::RateLimited(120), "Retry-After respected");
        clock.advance(120);
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(c.fetch_tweet("123").await.unwrap_err(), PreviewError::RateLimited(30), "5xx backoff");
        assert_eq!(transport.calls.lock().unwrap().len(), 4);
        assert!(parse_fx_response(b"{\"code\":200}", "123", now()).is_err());
    }

    fn unique_attribute_flood(count: usize) -> String {
        format!("<p {}>x</p>", (0..count).map(|i| format!("a{i}")).collect::<Vec<_>>().join(" "))
    }

    /// Audit fix (HIGH) + self-review fix: hostile documents stop at the parse deadline. The
    /// limit is cooperative (chunked feeding + a sink deadline), not a pre-scan. Red before:
    /// the whole fragment went to feed() at once and ran to completion, quadratically.
    #[test]
    fn thread_parse_hostile_documents_stop_at_the_deadline() {
        let budget = Duration::from_millis(250);
        for (label, html) in [
            ("40k unique attributes", unique_attribute_flood(40_000)),
            ("the audit's ~180k unique attributes", unique_attribute_flood(180_000)),
            ("1e6 attributes", format!("<p {}>x</p>", "a ".repeat(1_000_000))),
            ("deep comment", format!("<!--{}-->safe", "<p a b c --!> <!-- ".repeat(90_000))),
            ("bogus markup", format!("{}<p>ok</p>", "<!x a=b <?pi c=d </1 e=f ".repeat(60_000))),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({"code":200,"id":"123","content":[html, "after"]})).unwrap();
            assert!(body.len() <= 2 * 1024 * 1024, "{label}: {} bytes", body.len());
            let started = std::time::Instant::now();
            let (parsed, _) = parse_thread_content_within(&body, "123", now(), budget).unwrap();
            let elapsed = started.elapsed();
            assert!(elapsed < budget + Duration::from_millis(1250), "{label}: {elapsed:?}");
            assert!(parsed.partial || !parsed.entries.is_empty(), "{label}");
        }
        let (parsed, timed_out) = parse_thread_content_within(
            &serde_json::to_vec(&serde_json::json!({"code":200,"id":"123","content":[unique_attribute_flood(40_000)]})).unwrap(),
            "123",
            now(),
            budget,
        )
        .unwrap();
        assert!(timed_out && parsed.partial && parsed.entries.is_empty(), "the quadratic page is cut off, not finished");
        // Benign documents are untouched by the chunked feeding.
        let body = serde_json::json!({"code":200,"id":"123","content":[format!("<p>{}</p>", "word &amp; ".repeat(2000)), "b"]});
        let (parsed, timed_out) = parse_thread_content_within(&serde_json::to_vec(&body).unwrap(), "123", now(), THREAD_PARSE_BUDGET).unwrap();
        assert!(!timed_out && parsed.entries.len() == 2 && parsed.entries[0].text.starts_with("word & word"));
        let (parsed, timed_out) = parse_thread_content_within(&serde_json::to_vec(&body).unwrap(), "123", now(), Duration::ZERO).unwrap();
        assert!(timed_out && parsed.entries.is_empty());
    }

    fn thread_client(body: Value, budget: Duration) -> (Arc<TwitterClient>, Arc<FakeTransport>, Arc<FakeClock>) {
        let (mut client, transport, clock) = client(vec![response(200, body.clone()), response(200, body)]);
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.thread_enabled = true;
        c.thread_parse_budget = budget;
        (client, transport, clock)
    }

    fn thread_doc(id: &str, html: String) -> Value {
        serde_json::json!({"code":200,"id":id,"content":[html]})
    }

    /// Self-review fix: a parse that hits its deadline returns promptly and has really freed
    /// its blocking slot (the slot lives inside the blocking task); that ONE id is then
    /// negatively cached, while a good id still works (red before: one crafted thread put
    /// the whole provider on cooldown for everyone).
    #[tokio::test]
    async fn thread_parse_timeout_frees_its_slot_and_blocks_only_that_id() {
        let (mut client, transport, clock) = client(vec![
            response(200, thread_doc("111", unique_attribute_flood(180_000))),
            response(200, thread_doc("222", "Good".into())),
            response(200, thread_doc("111", unique_attribute_flood(180_000))),
        ]);
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.thread_enabled = true;
        c.thread_parse_budget = Duration::from_millis(250);
        let started = std::time::Instant::now();
        assert_eq!(client.fetch_thread("111").await.unwrap_err(), PreviewError::Timeout);
        assert!(started.elapsed() < Duration::from_millis(1500), "{:?}", started.elapsed());
        assert_eq!(client.thread_parses.available_permits(), THREAD_PARSE_SLOTS, "blocking slot released");
        assert_eq!(client.fetch_thread("222").await.unwrap().entries[0].text, "Good", "a good id is unaffected");
        assert!(matches!(client.fetch_thread("111").await, Err(PreviewError::RateLimited(d)) if d > 14 * 60));
        assert_eq!(transport.calls.lock().unwrap().len(), 2, "the bad id is not fetched again");
        clock.advance(15 * 60 + 1);
        assert_eq!(client.fetch_thread("111").await.unwrap_err(), PreviewError::Timeout, "negative entry expires");
    }

    /// Self-review fix: timeouts on several DISTINCT ids within the window do trip the
    /// provider-wide cooldown (red with per-id caching only); repeats of one id don't.
    #[tokio::test]
    async fn thread_timeouts_on_distinct_ids_trip_the_provider_cooldown() {
        let flood = || unique_attribute_flood(180_000);
        let (mut client, transport, _) = client(vec![
            response(200, thread_doc("111", flood())),
            response(200, thread_doc("112", flood())),
            response(200, thread_doc("113", flood())),
            response(200, thread_doc("222", "Good".into())),
        ]);
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.thread_enabled = true;
        c.thread_parse_budget = Duration::from_millis(250);
        for id in ["111", "112"] {
            assert_eq!(client.fetch_thread(id).await.unwrap_err(), PreviewError::Timeout);
        }
        assert!(client.fetch_thread("111").await.is_err(), "a repeat of one id doesn't count again");
        assert!(client.thread_until.lock().unwrap().is_zero(), "two distinct ids: no provider cooldown yet");
        assert_eq!(client.fetch_thread("113").await.unwrap_err(), PreviewError::Timeout);
        assert!(matches!(client.fetch_thread("222").await, Err(PreviewError::RateLimited(d)) if d >= 59));
        assert_eq!(transport.calls.lock().unwrap().len(), 3, "provider cooldown: nothing else is fetched");
    }

    /// Re-check fix (LOW): ThreadReader 5xx responses back the provider off (30, 60 s…),
    /// like the post providers; a success ends the streak. Red before: every request went out.
    #[tokio::test]
    async fn thread_provider_5xx_backoff() {
        let ok = serde_json::json!({"code":200,"id":"123","content":["First"]});
        let (mut client, transport, clock) = client(vec![
            response(503, Value::Null),
            response(500, Value::Null),
            response(200, ok.clone()),
            response(502, Value::Null),
        ]);
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.thread_enabled = true;
        assert_eq!(client.fetch_thread("123").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(client.fetch_thread("124").await.unwrap_err(), PreviewError::RateLimited(30), "another id waits too");
        clock.advance(30);
        assert_eq!(client.fetch_thread("124").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(client.fetch_thread("125").await.unwrap_err(), PreviewError::RateLimited(60), "backoff doubles");
        clock.advance(60);
        assert_eq!(client.fetch_thread("123").await.unwrap().entries.len(), 1);
        assert_eq!(client.fetch_thread("123").await.unwrap_err(), PreviewError::UpstreamFailure);
        assert_eq!(client.fetch_thread("126").await.unwrap_err(), PreviewError::RateLimited(30), "success reset the streak");
        assert_eq!(transport.calls.lock().unwrap().len(), 4);
    }

    /// Self-review fix: the N+1th concurrent parse is refused (busy), within bounds.
    #[tokio::test]
    async fn thread_parses_are_bounded() {
        let body = serde_json::json!({"code":200,"id":"123","content":["First"]});
        let (client, _, _) = thread_client(body, THREAD_PARSE_BUDGET);
        let held = client.thread_parses.clone().try_acquire_many_owned(THREAD_PARSE_SLOTS as u32).unwrap();
        assert_eq!(client.fetch_thread("123").await.unwrap_err(), PreviewError::Busy);
        drop(held);
        assert_eq!(client.fetch_thread("123").await.unwrap().entries.len(), 1);
    }

    /// Audit fix (LOW): repeated content without proven identity stays as separate entries.
    #[test]
    fn thread_repeated_content_is_not_merged() {
        let img = "<img src='https://pbs.twimg.com/media/same.jpg'>";
        let body = serde_json::json!({"code":200,"id":"123","content":["Yes.","Yes.",img,img]});
        let parsed = parse_thread_content(&serde_json::to_vec(&body).unwrap(), "123", now()).unwrap();
        assert_eq!(parsed.entries.len(), 4);
        assert_eq!(parsed.entries[0].text, parsed.entries[1].text);
        assert_eq!(parsed.entries[2].key, "tra:123:2");
        assert_eq!(parsed.entries[3].key, "tra:123:3");
    }

    /// Audit fix (MEDIUM): a success never erases a cooldown another concurrent request set,
    /// and a shorter cooldown never cuts a longer one short.
    #[tokio::test]
    async fn provider_cooldown_survives_concurrent_success_and_shorter_errors() {
        struct Gated {
            gate: Arc<tokio::sync::Notify>,
            calls: Arc<std::sync::Mutex<Vec<String>>>,
        }
        impl TwitterTransport for Gated {
            fn execute(&self, request: ProviderRequest) -> TransportFuture<'_> {
                let ProviderOperation::FixTweet { id } = request.operation else {
                    panic!("FixTweet only");
                };
                self.calls.lock().unwrap().push(id.clone());
                let gate = self.gate.clone();
                Box::pin(async move {
                    let mut body: Value =
                        serde_json::from_str(include_str!("twitter/fixtures/raw/fxtwitter.json")).unwrap();
                    body["tweet"]["id"] = id.clone().into();
                    body["tweet"]["quote"] = Value::Null;
                    match id.as_str() {
                        "1" => {
                            gate.notified().await;
                            Ok(response(200, body))
                        }
                        "2" => {
                            let mut limited = response(429, Value::Null);
                            limited.retry_after = Some("900".into());
                            Ok(limited)
                        }
                        _ => Ok(response(200, body)),
                    }
                })
            }
        }
        let (gate, calls) = (Arc::new(tokio::sync::Notify::new()), Arc::new(std::sync::Mutex::new(Vec::new())));
        let mut client = client(vec![]).0;
        let c = Arc::get_mut(&mut client).unwrap();
        c.config = None;
        c.fx_enabled = true;
        c.transport = Arc::new(Gated { gate: gate.clone(), calls: calls.clone() });
        let slow = {
            let client = client.clone();
            tokio::spawn(async move { client.fetch_tweet("1").await })
        };
        while !calls.lock().unwrap().iter().any(|id| id == "1") {
            tokio::task::yield_now().await;
        }
        assert_eq!(client.fetch_tweet("2").await.unwrap_err(), PreviewError::RateLimited(900));
        gate.notify_one();
        assert!(slow.await.unwrap().is_ok(), "the in-flight request itself succeeds");
        assert!(matches!(client.fetch_tweet("3").await, Err(PreviewError::RateLimited(d)) if d > 800));
        assert!(!calls.lock().unwrap().iter().any(|id| id == "3"), "cooldown kept the provider uncontacted");
        let _ = client.check_status(&response(503, Value::Null));
        assert!(matches!(client.cooldown(), Err(PreviewError::RateLimited(d)) if d > 800), "a 30 s backoff can't shorten 900 s");
    }

    /// Audit fix (MEDIUM): an invalid guest configuration turns post previews OFF instead of
    /// silently switching to another provider whose flag happens to be set.
    #[test]
    fn invalid_guest_config_never_falls_back_to_fixtweet() {
        let env = |guest: Option<&'static str>, bearer: Option<&'static str>, fx: bool| {
            move |key: &str| match key {
                "CRYPTIRC_X_GUEST_ENABLED" => guest.map(String::from),
                "CRYPTIRC_X_GUEST_BEARER" => bearer.map(String::from),
                "CRYPTIRC_X_FXTWITTER_ENABLED" if fx => Some("1".into()),
                "CRYPTIRC_X_THREADREADER_ENABLED" => Some("1".into()),
                _ => None,
            }
        };
        let broken = TwitterClient::from_lookup(env(Some("1"), None, true));
        assert!(!broken.enabled(), "missing bearer + FixTweet flag: post previews off");
        assert!(broken.thread_enabled(), "the independent thread provider is unaffected");
        let broken = TwitterClient::from_lookup(env(Some("1"), Some("bad header"), true));
        assert!(!broken.enabled());
        assert!(TwitterClient::from_lookup(env(None, None, true)).enabled(), "FixTweet alone, as intended");
        assert!(TwitterClient::from_lookup(env(Some("1"), Some("synthetic"), true)).config.is_some());
        assert!(!TwitterClient::from_lookup(env(None, None, false)).enabled(), "nothing set: off");
    }

    #[test]
    fn fixture_contract_roundtrip() {
        for fixture in [
            include_str!("twitter/fixtures/normalized/text-only.json"),
            include_str!("twitter/fixtures/normalized/multiple-photo.json"),
            include_str!("twitter/fixtures/normalized/video.json"),
            include_str!("twitter/fixtures/normalized/animated-gif.json"),
            include_str!("twitter/fixtures/normalized/quoted-post.json"),
            include_str!("twitter/fixtures/normalized/long-post.json"),
            include_str!("twitter/fixtures/normalized/missing-engagement.json"),
            include_str!("twitter/fixtures/normalized/restricted.json"),
        ] {
            let original: Value = serde_json::from_str(fixture).unwrap();
            let parsed: TweetPreview = serde_json::from_str(fixture).unwrap();
            assert_eq!(parsed.schema_version, SCHEMA_VERSION);
            assert_eq!(serde_json::to_value(parsed).unwrap(), original);
        }
        for (state, value) in [
            (MetricState::Available, Some("18446744073709551615")),
            (MetricState::Available, Some("0")),
            (MetricState::Unavailable, None),
            (MetricState::Unsupported, None),
        ] {
            let metric = Metric {
                state,
                value: value.map(String::from),
            };
            let json = serde_json::to_string(&metric).unwrap();
            let result: Metric = serde_json::from_str(&json).unwrap();
            assert_eq!(result.state, state);
            assert_eq!(result.value.as_deref(), value);
        }
    }
}
