/// lastfm.rs — fetch a user's now-playing / last-played track from the Last.fm API.
///
/// Read-only: user.getRecentTracks needs only an application API key + a username,
/// no per-user OAuth. The API key identifies the app, not the person, so one key
/// can serve every user's lookups. Called server-side so keys never reach the browser.
use anyhow::{anyhow, bail, Result};

pub struct Track {
    pub artist: String,
    pub track: String,
    pub album: String,
    /// true = currently scrobbling; false = the most recently played track.
    pub now_playing: bool,
}

/// Maximum number of response bytes we will buffer from Last.fm. A getRecentTracks
/// response for one track is a few KB; 256 KiB is a generous cap that prevents a
/// hostile/misbehaving endpoint from forcing unbounded allocation (audit #64).
const MAX_BODY: usize = 256 * 1024;

/// A hardened, lastfm-owned HTTP client (audit #64).
///
/// We do NOT reuse the shared `gif_client` passed in by main.rs (it carries the default
/// redirect policy, no proxy restriction and no body cap). Instead we build our own:
///   - `redirect::Policy::none()` — never follow 3xx, so the request (which carries the
///     api_key in its query string) can't be bounced to an internal/attacker address
///     (SSRF) and the api_key can't leak via a redirect `Location`.
///   - `.no_proxy()` — ignore env proxies so traffic can't be silently rerouted.
///   - short connect/overall timeouts.
/// The `client` parameter is retained for call-site compatibility with main.rs but is
/// intentionally ignored.
fn http() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .build()
            // A builder failure here is a static misconfiguration; fall back to a default
            // client so we never panic at runtime.
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Fetch the most recent track for `lfm_user` using `api_key`.
///
/// `_client` is ignored on purpose — see `http()` for why we use our own hardened client.
pub async fn now_playing(_client: &reqwest::Client, api_key: &str, lfm_user: &str) -> Result<Track> {
    if api_key.trim().is_empty() { bail!("No Last.fm API key configured"); }
    if lfm_user.trim().is_empty() { bail!("No Last.fm username set"); }

    let resp = http()
        .get("https://ws.audioscrobbler.com/2.0/")
        .query(&[
            ("method", "user.getrecenttracks"),
            ("user", lfm_user),
            ("api_key", api_key),
            ("format", "json"),
            ("limit", "1"),
        ])
        .send()
        .await
        // Never include the reqwest Display (it carries the request URL, hence the
        // api_key) — return a sanitized class only.
        .map_err(|e| anyhow!("Last.fm request failed (timeout={}, connect={})", e.is_timeout(), e.is_connect()))?;

    let status = resp.status();
    // Cap the buffered body (audit #64/#44): reject up front if Content-Length already
    // exceeds the cap, then read the body INCREMENTALLY (chunk-wise) via the shared
    // read_capped_body helper so a hostile/MITM'd endpoint streaming gigabytes (or a
    // gzip bomb) can never force more than MAX_BODY+1 bytes into RAM before we bail.
    if let Some(len) = resp.content_length() {
        if len > MAX_BODY as u64 {
            bail!("Last.fm: response too large");
        }
    }
    // Read one byte past the cap so an oversized body whose Content-Length was absent or
    // understated is still detected and rejected, without ever buffering the whole thing.
    let raw = crate::preview::read_capped_body(resp, MAX_BODY + 1)
        .await
        .map_err(|_| anyhow!("Last.fm: unreadable response"))?;
    if raw.len() > MAX_BODY {
        bail!("Last.fm: response too large");
    }
    let text = String::from_utf8_lossy(&raw);
    let body: serde_json::Value = serde_json::from_str(&text)
        .map_err(|_| anyhow!("Last.fm: malformed response"))?;

    // Last.fm error payloads are {"error":N,"message":"..."} — surface the message
    // (e.g. "User not found", "Invalid API key"); it never contains the key itself.
    if let Some(msg) = body.get("message").and_then(|m| m.as_str()) {
        bail!("Last.fm: {}", msg);
    }
    if !status.is_success() {
        bail!("Last.fm returned status {}", status.as_u16());
    }
    parse_track(&body)
}

/// Strip control chars (incl. CR/LF) and trim — track metadata is arbitrary user-set
/// text, and the caller sends it as a single-line IRC PRIVMSG.
fn clean(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect::<String>().trim().to_string()
}

/// Extract the first track from a user.getRecentTracks response body.
fn parse_track(body: &serde_json::Value) -> Result<Track> {
    let tracks = body.get("recenttracks").and_then(|r| r.get("track"));
    // "track" is an array, or a single object when the user has exactly one scrobble.
    let t = match tracks {
        Some(serde_json::Value::Array(a)) => a.first().cloned(),
        Some(obj @ serde_json::Value::Object(_)) => Some(obj.clone()),
        _ => None,
    };
    let Some(t) = t else { bail!("No recent tracks for that user"); };

    let artist = clean(t.get("artist").and_then(|a| a.get("#text")).and_then(|x| x.as_str()).unwrap_or(""));
    let track  = clean(t.get("name").and_then(|x| x.as_str()).unwrap_or(""));
    let album  = clean(t.get("album").and_then(|a| a.get("#text")).and_then(|x| x.as_str()).unwrap_or(""));
    let now_playing = t.get("@attr")
        .and_then(|a| a.get("nowplaying"))
        .and_then(|x| x.as_str())
        .map(|s| s == "true")
        .unwrap_or(false);

    if artist.is_empty() && track.is_empty() {
        bail!("No track info available");
    }
    Ok(Track { artist, track, album, now_playing })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_now_playing_array() {
        let j = serde_json::json!({"recenttracks":{"track":[
            {"artist":{"#text":"Boards of Canada"},"name":"Roygbiv",
             "album":{"#text":"Music Has the Right to Children"},"@attr":{"nowplaying":"true"}}]}});
        let t = parse_track(&j).unwrap();
        assert_eq!(t.artist, "Boards of Canada");
        assert_eq!(t.track, "Roygbiv");
        assert_eq!(t.album, "Music Has the Right to Children");
        assert!(t.now_playing);
    }

    #[test]
    fn parses_last_played_single_object_and_strips_controls() {
        // Not nowplaying, "track" is a single object, and metadata carries a CR/LF that
        // must be stripped so it can't inject a second IRC command.
        let j = serde_json::json!({"recenttracks":{"track":
            {"artist":{"#text":"Aphex\r\nTwin"},"name":"Xtal\n","album":{"#text":""}}}});
        let t = parse_track(&j).unwrap();
        assert_eq!(t.artist, "AphexTwin");
        assert_eq!(t.track, "Xtal");
        assert_eq!(t.album, "");
        assert!(!t.now_playing);
    }

    #[test]
    fn errors_when_no_tracks() {
        let j = serde_json::json!({"recenttracks":{"track":[]}});
        assert!(parse_track(&j).is_err());
    }
}
