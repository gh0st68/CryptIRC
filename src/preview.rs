/// preview.rs — Link preview metadata fetcher
///
/// Fetches og:title, og:description, og:image from URLs.
/// Blocks private/internal IPs to prevent SSRF.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{watch, OwnedSemaphorePermit, Semaphore};

use crate::twitter::{PreviewError, TweetPreview, TwitterClient, UnavailableReason, X_HOSTS};

const MAX_BODY: usize = 51_200; // 50KB max fetch
const TIMEOUT: Duration = Duration::from_secs(5);
// #18: cap on how many redirect hops we follow manually (each re-validated).
const MAX_REDIRECTS: usize = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkPreview {
    pub url: String,
    pub domain: String,
    pub title: Option<String>,
    pub description: Option<String>,
    pub image: Option<String>,
    pub site_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreviewSettings {
    pub mode: String,           // "off", "whitelist", "all"
    pub whitelist: Vec<String>, // list of allowed domains
}

impl Default for PreviewSettings {
    fn default() -> Self {
        Self {
            mode: "whitelist".into(),
            whitelist: vec![
                "github.com".into(),
                "reddit.com".into(),
                "old.reddit.com".into(),
                "imgur.com".into(),
                "i.imgur.com".into(),
                "twitter.com".into(),
                "x.com".into(),
                "stackoverflow.com".into(),
                "en.wikipedia.org".into(),
                "news.ycombinator.com".into(),
                "medium.com".into(),
                "dev.to".into(),
                "npmjs.com".into(),
                "crates.io".into(),
                "docs.rs".into(),
                "youtube.com".into(),
                "www.youtube.com".into(),
                "youtu.be".into(),
                "store.steampowered.com".into(),
                "twitch.tv".into(),
                "soundcloud.com".into(),
                "open.spotify.com".into(),
                "linkedin.com".into(),
            ],
        }
    }
}

pub struct PreviewService {
    data_dir: String,
    /// X providers (all off unless their startup flags are set) — see twitter.rs.
    twitter: Arc<TwitterClient>,
    /// The process-wide outbound preview permits (#33), shared with generic /preview.
    preview_sem: Arc<Semaphore>,
    tweets: Arc<Mutex<TweetCache>>,
}

impl PreviewService {
    pub fn new(data_dir: &str, preview_sem: Arc<Semaphore>) -> Self {
        // #17/#18: we no longer keep a shared, redirect-following client. Each hop
        // is fetched with a freshly-built client that (a) disables automatic
        // redirects (Policy::none) and (b) pins DNS to the already-validated public
        // IPs via resolve_to_addrs, so reqwest cannot re-resolve to a private IP
        // (DNS-rebinding / TOCTOU). See build_pinned_client / fetch_preview.
        Self {
            data_dir: data_dir.to_string(),
            twitter: Arc::new(TwitterClient::from_environment()),
            preview_sem,
            tweets: Default::default(),
        }
    }

    pub async fn load_settings(&self) -> PreviewSettings {
        let path = PathBuf::from(&self.data_dir).join("admin_settings.json");
        if let Ok(json) = tokio::fs::read_to_string(&path).await {
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&json) {
                let mode = v.get("link_preview_mode")
                    .and_then(|v| v.as_str())
                    .unwrap_or("whitelist").to_string();
                let whitelist = v.get("link_preview_whitelist")
                    .and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_else(|| PreviewSettings::default().whitelist);
                return PreviewSettings { mode, whitelist };
            }
        }
        PreviewSettings::default()
    }

    pub async fn fetch_preview(&self, url: &str) -> Result<LinkPreview> {
        // Load the whitelist/mode once; reused for every hop (#18: redirects are
        // re-validated against the SAME whitelist, not just the original URL).
        let settings = self.load_settings().await;
        if settings.mode == "off" {
            anyhow::bail!("Link previews disabled");
        }

        // #10: the host that owns the resulting preview is the FINAL hop's host (the
        // host actually fetched after following redirects), NOT the original request
        // host — otherwise a trusted/whitelisted URL could redirect to attacker content
        // while still reporting the original domain (content spoofing). We track the
        // validated final host as we walk the redirect chain.
        let mut final_domain = String::new();

        // Manual redirect loop. Each hop is fully re-validated (scheme + private-IP
        // with pinned resolution + whitelist) before we connect, and the connection
        // is pinned to the validated IPs (#17 DNS-rebinding/TOCTOU, #18 redirect bypass).
        let mut current = url.to_string();
        let mut resp = None;
        for hop in 0..=MAX_REDIRECTS {
            // (1) Parse + scheme check on THIS hop's URL.
            let mut parsed = reqwest::Url::parse(&current)
                .map_err(|_| anyhow::anyhow!("Invalid URL"))?;
            // Argon P1 preview.rs:133: canonicalise a fully-qualified host ("github.com.")
            // to its dot-less form for EVERYTHING below — whitelist match, internal-name
            // checks, the pinned resolve, TLS name, Host header and the reported domain —
            // so the two spellings of one name can't be treated differently.
            canonicalize_url_host(&mut parsed)?;
            current = parsed.to_string();
            if parsed.scheme() != "https" {
                anyhow::bail!("Only HTTPS URLs supported");
            }
            // #43: reject embedded userinfo/credentials on EVERY hop, mirroring
            // notifications.rs's push-endpoint guard. A URL like
            // https://trusted.com@evil-public.com/ has host_str()=evil-public.com
            // but reqwest still forwards the credentials to the final host (and
            // re-sends them across redirects); refuse outright so the host we
            // validate and pin is unambiguous.
            if !parsed.username().is_empty() || parsed.password().is_some() {
                anyhow::bail!("URLs must not contain credentials");
            }
            let domain = parsed.host_str().unwrap_or("").to_lowercase();
            if domain.is_empty() {
                anyhow::bail!("No host in URL");
            }

            // (2) Resolve the host ONCE and validate EVERY resolved IP is public.
            // The returned addrs are what we pin the connection to, so reqwest
            // cannot re-resolve to a private IP afterwards.
            let addrs = resolve_and_validate_host(&domain, parsed.port_or_known_default()).await?;

            // Record the host we are actually about to fetch; the last value to survive
            // validation is the FINAL hop's host used for the reported domain (#10) and
            // the og:image same-host check (#98).
            final_domain = domain.clone();

            // (3) Whitelist check on THIS hop's host.
            if settings.mode == "whitelist" {
                let allowed = settings.whitelist.iter().any(|w| {
                    domain == w.as_str() || domain.ends_with(&format!(".{}", w))
                });
                if !allowed {
                    anyhow::bail!("Domain not in whitelist");
                }
            } else if settings.mode == "all" {
                // #20: "all" mode lets an admin preview ANY host, turning the fetcher
                // into a general SSRF surface. The 443-only port pin (#9) and the
                // private-IP block (resolve_and_validate_host) still apply here, so it
                // cannot reach internal/private hosts or scan non-443 ports — but admins
                // should understand it can still fetch arbitrary public https endpoints.
            } else {
                anyhow::bail!("Unknown preview mode");
            }

            // (4) Build a per-hop client: no auto-redirects, DNS pinned to validated IPs.
            let client = build_pinned_client(&domain, &addrs)?;
            let r = client.get(&current)
                .header("Accept", "text/html")
                .send()
                .await?;

            // (5) Handle redirects manually so we re-validate the next hop.
            let status = r.status();
            if status.is_redirection() {
                if hop == MAX_REDIRECTS {
                    anyhow::bail!("Too many redirects");
                }
                let location = r.headers().get("location")
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| anyhow::anyhow!("Redirect without Location"))?;
                // Resolve the Location relative to the current URL, then loop to
                // re-validate scheme/host/IP/whitelist on the next iteration.
                let next = parsed.join(location)
                    .map_err(|_| anyhow::anyhow!("Invalid redirect target"))?;
                current = next.to_string();
                continue;
            }

            resp = Some(r);
            break;
        }
        let resp = resp.ok_or_else(|| anyhow::anyhow!("Too many redirects"))?;

        let ct = resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("text/html") && !ct.contains("application/xhtml") {
            anyhow::bail!("Not HTML");
        }

        // #32: reject up front if Content-Length already exceeds the cap, then read
        // the body incrementally and abort once MAX_BODY bytes have been buffered,
        // so a multi-GB response or a gzip bomb cannot exhaust memory.
        if let Some(len) = resp.content_length() {
            if len > MAX_BODY as u64 {
                anyhow::bail!("Response too large");
            }
        }
        let bytes = read_capped_body(resp, MAX_BODY).await?;
        let body = String::from_utf8_lossy(&bytes);

        // Extract metadata
        let title = extract_meta(&body, "og:title")
            .or_else(|| extract_tag(&body, "title"));
        let description = extract_meta(&body, "og:description")
            .or_else(|| extract_meta(&body, "description"));
        // #81: og:image is rendered directly as <img src> in viewer browsers (a
        // privacy beacon / read-only GET to an attacker-chosen host). The server
        // does not proxy it, so at minimum only return absolute https:// images and
        // drop http/data/javascript/relative values that could beacon or break out.
        // #98: additionally require the image host to match the validated final
        // preview host (same-host). An off-host https image is still an unvalidated
        // beacon to a private/internal host we never vetted, so drop it. We do a
        // string host comparison against the already-validated final host rather than
        // performing a fresh DNS lookup.
        let image = extract_meta(&body, "og:image").filter(|img| {
            let lower = img.to_ascii_lowercase();
            if !lower.starts_with("https://") {
                return false;
            }
            match reqwest::Url::parse(img) {
                Ok(u) => u
                    .host_str()
                    .map(|h| h.trim_end_matches('.').to_lowercase() == final_domain)
                    .unwrap_or(false),
                Err(_) => false,
            }
        });
        let site_name = extract_meta(&body, "og:site_name");

        Ok(LinkPreview {
            url: url.to_string(),
            domain: final_domain,
            title,
            description: description.map(|d| if d.chars().count() > 200 { format!("{}…", d.chars().take(197).collect::<String>()) } else { d }),
            image,
            site_name,
        })
    }
}

// ─── X previews: per-viewer cache, single-flight and policy generation ────────
// Ported from the rich-X-previews reference. Keys are (viewer, policy epoch,
// "preview:<id>" | "thread:<id>"), so one account never reads another's result and a
// policy change (admin Off/Whitelist/All) invalidates everything at once. Nothing here is
// persisted: restart clears tokens and results.

type TweetResult = Result<Arc<serde_json::Value>, PreviewError>;
type TweetKey = (String, u64, String);

const TWEET_MAX_ENTRIES: usize = 1000;
const TWEET_MAX_ENTRIES_PER_USER: usize = 100;
const TWEET_MAX_BYTES: usize = 32 * 1024 * 1024;
const TWEET_MAX_ENTRY_BYTES: usize = 256 * 1024;
const TWEET_MAX_WAITERS: usize = 128;
const TWEET_MAX_WAITERS_PER_KEY: usize = 16;
const TWEET_REFRESH_COOLDOWN_SECS: u64 = 30;
const TWEET_LOGICAL_DEADLINE: Duration = Duration::from_secs(12);

struct TweetEntry {
    result: TweetResult,
    expires: Duration,
    bytes: usize,
    recent: u64,
    /// CDN assets referenced by this result (twitter::media_asset_key), so the signed
    /// media fallback only covers what this viewer actually retrieved.
    media: HashSet<String>,
}
struct TweetFlight {
    sender: watch::Sender<Option<TweetResult>>,
    waiters: usize,
}
#[derive(Default)]
struct TweetCache {
    allowed: Option<bool>,
    epoch: u64,
    entries: HashMap<TweetKey, TweetEntry>,
    flights: HashMap<TweetKey, TweetFlight>,
    refresh: HashMap<(String, String), Duration>,
    waiters: usize,
    bytes: usize,
    recent: u64,
}

impl TweetCache {
    fn remove(&mut self, key: &TweetKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
    }

    fn expire(&mut self, now: Duration) {
        let expired: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, e)| e.expires <= now)
            .map(|(k, _)| k.clone())
            .collect();
        for key in expired {
            self.remove(&key);
        }
        self.refresh.retain(|_, until| *until > now);
    }

    fn insert(&mut self, key: TweetKey, result: TweetResult, now: Duration) {
        self.expire(now);
        self.remove(&key);
        let mut media = HashSet::new();
        let (bytes, ttl) = match &result {
            Ok(value) => {
                crate::twitter::collect_media_keys(value, &mut media);
                let bytes = serde_json::to_vec(value.as_ref())
                    .map(|v| v.len())
                    .unwrap_or(usize::MAX)
                    .saturating_add(media.iter().map(|k| k.len() + 32).sum::<usize>());
                let ttl = match value
                    .pointer("/availability/reason")
                    .and_then(|v| v.as_str())
                {
                    Some("provider_disabled") => 30,
                    Some(_) => 60,
                    None if key.2.starts_with("thread:") => 300,
                    None => 600,
                };
                (bytes, ttl)
            }
            Err(PreviewError::RateLimited(delay)) => (128, *delay),
            Err(_) => (128, 15),
        };
        if bytes > TWEET_MAX_ENTRY_BYTES {
            return;
        }
        loop {
            let per_user = self.entries.keys().filter(|k| k.0 == key.0).count() >= TWEET_MAX_ENTRIES_PER_USER;
            if !(per_user
                || self.entries.len() >= TWEET_MAX_ENTRIES
                || self.bytes + bytes > TWEET_MAX_BYTES)
            {
                break;
            }
            let oldest = self
                .entries
                .iter()
                .filter(|(k, _)| !per_user || k.0 == key.0)
                .min_by_key(|(_, e)| e.recent)
                .map(|(k, _)| k.clone());
            match oldest {
                Some(oldest) => self.remove(&oldest),
                None => return,
            }
        }
        self.recent = self.recent.wrapping_add(1);
        self.bytes += bytes;
        self.entries.insert(
            key,
            TweetEntry {
                result,
                expires: now + Duration::from_secs(ttl),
                bytes,
                recent: self.recent,
                media,
            },
        );
    }
}

struct TweetSubscriber {
    cache: Arc<Mutex<TweetCache>>,
    key: TweetKey,
}
impl Drop for TweetSubscriber {
    fn drop(&mut self) {
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        cache.waiters = cache.waiters.saturating_sub(1);
        if let Some(flight) = cache.flights.get_mut(&self.key) {
            flight.waiters = flight.waiters.saturating_sub(1);
        }
    }
}

// Owns registry cleanup and the shared permit across success, panic, cancellation and
// every error. A disconnected leader can run only until the logical deadline.
struct TweetLeader {
    cache: Arc<Mutex<TweetCache>>,
    key: TweetKey,
    _permit: OwnedSemaphorePermit,
}
impl Drop for TweetLeader {
    fn drop(&mut self) {
        let flight = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .flights
            .remove(&self.key);
        if let Some(flight) = flight {
            if flight.sender.borrow().is_none() {
                flight
                    .sender
                    .send_replace(Some(Err(PreviewError::UpstreamFailure)));
            }
        }
    }
}

impl PreviewService {
    /// Re-read the admin link-preview policy. Off disables X; Whitelist requires an exact
    /// supported X/Twitter alias; All allows it (provider flags still apply). A change of
    /// the effective answer starts a new cache generation and drops every cached result.
    pub async fn update_tweet_policy(&self) -> (bool, u64) {
        let settings = self.load_settings().await;
        let allowed = settings.mode == "all"
            || settings.mode == "whitelist"
                && settings
                    .whitelist
                    .iter()
                    .any(|host| X_HOSTS.iter().any(|alias| host.eq_ignore_ascii_case(alias)));
        let mut cache = self.tweets.lock().unwrap_or_else(|e| e.into_inner());
        if cache.allowed != Some(allowed) {
            cache.allowed = Some(allowed);
            cache.epoch = cache.epoch.wrapping_add(1);
            cache.entries.clear();
            cache.bytes = 0;
        }
        (allowed, cache.epoch)
    }

    /// (post previews available, published threads available) for this server right now:
    /// provider flag set at startup AND the admin policy permits X. Lets the browser skip
    /// X placeholders and requests entirely on a server where nothing is configured.
    pub async fn tweet_capabilities(&self) -> (bool, bool) {
        if !self.twitter.enabled() && !self.twitter.thread_enabled() {
            return (false, false); // no flag set: no policy read, nothing to offer
        }
        let (allowed, _) = self.update_tweet_policy().await;
        (allowed && self.twitter.enabled(), allowed && self.twitter.thread_enabled())
    }

    /// May the signed media fallback serve assets right now? (A provider is configured and
    /// the admin policy permits X — checked before signing AND again before redeeming.)
    pub async fn tweet_media_allowed(&self) -> bool {
        let (preview, thread) = self.tweet_capabilities().await;
        preview || thread
    }

    /// Did `username` retrieve (in a live, current-generation cached result) every asset in
    /// `keys`? The fallback is a fallback for previews this viewer loaded, not an open proxy.
    pub fn tweet_media_retrieved(&self, username: &str, keys: &[String]) -> bool {
        let mut cache = self.tweets.lock().unwrap_or_else(|e| e.into_inner());
        cache.expire(self.twitter.clock.ticks());
        let epoch = cache.epoch;
        keys.iter().all(|key| {
            cache.entries.iter().any(|(k, entry)| {
                k.0 == username && k.1 == epoch && entry.result.is_ok() && entry.media.contains(key)
            })
        })
    }

    fn disabled_tweet(&self, id: &str, thread: bool) -> TweetResult {
        let now = self.twitter.clock.now();
        let value = if thread {
            serde_json::to_value(crate::twitter::ThreadPreview::unavailable(
                id,
                UnavailableReason::ProviderDisabled,
                now,
            ))
        } else {
            serde_json::to_value(TweetPreview::unavailable(
                id,
                UnavailableReason::ProviderDisabled,
                now,
            ))
        };
        value
            .map(Arc::new)
            .map_err(|_| PreviewError::UpstreamFailure)
    }

    pub async fn fetch_tweet_preview(
        self: &Arc<Self>,
        username: &str,
        id: &str,
        refresh: bool,
    ) -> TweetResult {
        self.fetch_x_operation(username, id, refresh, false).await
    }

    pub async fn fetch_tweet_thread(
        self: &Arc<Self>,
        username: &str,
        id: &str,
        refresh: bool,
    ) -> TweetResult {
        self.fetch_x_operation(username, id, refresh, true).await
    }

    async fn fetch_x_operation(
        self: &Arc<Self>,
        username: &str,
        id: &str,
        refresh: bool,
        thread: bool,
    ) -> TweetResult {
        if !crate::twitter::valid_id(id) {
            return Err(PreviewError::InvalidUrl);
        }
        let configured = if thread {
            self.twitter.thread_enabled()
        } else {
            self.twitter.enabled()
        };
        if !configured {
            // Unconfigured provider: answered locally, no policy file read, no network.
            return self.disabled_tweet(id, thread);
        }
        // Policy before cache, and again before publishing (below).
        let (allowed, epoch) = self.update_tweet_policy().await;
        if !allowed {
            return self.disabled_tweet(id, thread);
        }
        let key = (
            username.to_string(),
            epoch,
            format!("{}:{id}", if thread { "thread" } else { "preview" }),
        );
        let mut receiver;
        let mut leader = None;
        {
            let mut cache = self.tweets.lock().unwrap_or_else(|e| e.into_inner());
            let now = self.twitter.clock.ticks();
            cache.expire(now);
            if !refresh {
                cache.recent = cache.recent.wrapping_add(1);
                let recent = cache.recent;
                if let Some(entry) = cache.entries.get_mut(&key) {
                    entry.recent = recent;
                    return entry.result.clone();
                }
            }
            if cache.waiters >= TWEET_MAX_WAITERS {
                return Err(PreviewError::Busy);
            }
            if let Some(flight) = cache.flights.get_mut(&key) {
                if flight.waiters >= TWEET_MAX_WAITERS_PER_KEY {
                    return Err(PreviewError::Busy);
                }
                flight.waiters += 1;
                receiver = flight.sender.subscribe();
            } else {
                let refresh_key = (username.to_string(), id.to_string());
                if refresh {
                    if let Some(until) = cache.refresh.get(&refresh_key) {
                        return Err(PreviewError::RateLimited(
                            until.saturating_sub(now).as_secs().max(1),
                        ));
                    }
                    if cache.refresh.len() >= TWEET_MAX_ENTRIES {
                        return Err(PreviewError::Busy);
                    }
                }
                // Only a miss leader takes one of the shared outbound permits; never wait.
                let permit = self
                    .preview_sem
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| PreviewError::Busy)?;
                let (sender, rx) = watch::channel(None);
                receiver = rx;
                cache
                    .flights
                    .insert(key.clone(), TweetFlight { sender, waiters: 1 });
                if refresh {
                    cache.refresh.insert(
                        refresh_key,
                        now + Duration::from_secs(TWEET_REFRESH_COOLDOWN_SECS),
                    );
                }
                leader = Some(TweetLeader {
                    cache: self.tweets.clone(),
                    key: key.clone(),
                    _permit: permit,
                });
            }
            cache.waiters += 1;
        }
        let _subscriber = TweetSubscriber {
            cache: self.tweets.clone(),
            key: key.clone(),
        };
        if let Some(guard) = leader {
            let service = self.clone();
            let id = id.to_string();
            let key = key.clone();
            tokio::spawn(async move {
                let _guard = guard;
                let work = async {
                    let value = if thread {
                        service.twitter.fetch_thread(&id).await.and_then(|post| {
                            serde_json::to_value(post).map_err(|_| PreviewError::UpstreamFailure)
                        })
                    } else {
                        service.twitter.fetch_tweet(&id).await.and_then(|post| {
                            serde_json::to_value(post).map_err(|_| PreviewError::UpstreamFailure)
                        })
                    };
                    let mut result = value.map(Arc::new);
                    let (allowed, current) = service.update_tweet_policy().await;
                    if !allowed || current != epoch {
                        result = service.disabled_tweet(&id, thread);
                    } else {
                        service
                            .tweets
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .insert(key.clone(), result.clone(), service.twitter.clock.ticks());
                    }
                    result
                };
                let result = tokio::time::timeout(TWEET_LOGICAL_DEADLINE, work)
                    .await
                    .unwrap_or(Err(PreviewError::Timeout));
                let mut cache = service.tweets.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(result, Err(PreviewError::Timeout))
                    && cache.epoch == epoch
                    && cache.allowed == Some(true)
                {
                    let now = service.twitter.clock.ticks();
                    cache.insert(key.clone(), result.clone(), now);
                }
                if let Some(flight) = cache.flights.get(&key) {
                    flight.sender.send_replace(Some(result));
                }
            });
        }
        let result = loop {
            if let Some(result) = receiver.borrow_and_update().clone() {
                break result;
            }
            receiver
                .changed()
                .await
                .map_err(|_| PreviewError::UpstreamFailure)?;
        };
        let (allowed, current) = self.update_tweet_policy().await;
        if !allowed || current != epoch {
            return self.disabled_tweet(id, thread);
        }
        result
    }
}

/// Build a reqwest client pinned to the already-validated public IPs for `host`.
///
/// #17: resolve_to_addrs() forces reqwest to connect to exactly these addresses
/// for `host`, so DNS is not re-resolved at connect time (defeats DNS-rebinding /
/// TOCTOU). #18: Policy::none() disables automatic redirect following; the caller
/// follows + re-validates each hop itself.
/// Rewrite a URL whose host ends in '.' (root-label form) to the dot-less host. IP literals
/// come back from the parser already normalised; an all-dots host is refused.
pub(crate) fn canonicalize_url_host(u: &mut reqwest::Url) -> Result<()> {
    let Some(h) = u.host_str().map(str::to_string) else { return Ok(()) };
    let trimmed = h.trim_end_matches('.');
    if trimmed.len() == h.len() { return Ok(()); }
    if trimmed.is_empty() { anyhow::bail!("No host in URL"); }
    u.set_host(Some(trimmed)).map_err(|_| anyhow::anyhow!("Invalid URL"))
}

pub(crate) fn build_pinned_client(host: &str, addrs: &[SocketAddr]) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CryptIRC/1.0 (Link Preview)")
        // #17b: disable reqwest's default system-proxy auto-detection. If an ambient
        // HTTP(S)_PROXY/ALL_PROXY env var were set, the request would tunnel through the
        // proxy — which re-resolves the hostname itself — completely bypassing the
        // resolve_to_addrs IP pin and is_private_ip validation (SSRF). A pinned anti-SSRF
        // client must always connect directly to the validated addresses.
        .no_proxy()
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| anyhow::anyhow!("client build failed: {}", e))
}

/// Same SSRF-safe pinning as `build_pinned_client` (validated public IPs only, no system
/// proxy, no redirects) for the signed X media fallback. No whole-request timeout: a media
/// stream may outlive the 5-second preview budget, so the caller bounds the response
/// headers, the idle gap between chunks, the total stream duration and the byte count.
pub(crate) fn build_pinned_media_client(host: &str, addrs: &[SocketAddr]) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("CryptIRC/1.0 (Media Fallback)")
        .no_proxy()
        .resolve_to_addrs(host, addrs)
        .build()
        .map_err(|e| anyhow::anyhow!("client build failed: {}", e))
}

/// Read a response body incrementally, capping the buffered size at `max` bytes.
/// Aborts (returns what was read so far) once the cap is reached so an oversized
/// or decompression-bomb body cannot exhaust memory. (#32)
pub(crate) async fn read_capped_body(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut truncated = false;
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max.saturating_sub(buf.len());
        if remaining == 0 {
            // More body remained but we already hit the cap.
            truncated = true;
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= max {
            // If this chunk had more bytes than we took, the body is being truncated.
            if take < chunk.len() {
                truncated = true;
            }
            break;
        }
    }
    // #97: the cap is intentional, but record when a body is truncated so operators
    // can tell that a preview was generated from a partial document.
    if truncated {
        tracing::warn!("read_capped_body: response exceeded {} byte cap; body truncated", max);
    }
    Ok(buf)
}

/// Resolve `host` once and validate that EVERY resolved address is a public IP.
/// Returns the validated SocketAddrs (to be pinned by the caller). Rejects when
/// resolution yields zero addresses or when ANY address is private/internal.
/// (#17: validate all A/AAAA records and pin the exact set we validated.)
pub(crate) async fn resolve_and_validate_host(host: &str, port: Option<u16>) -> Result<Vec<SocketAddr>> {
    // #119: strip the trailing '.'(s) (fully-qualified form, e.g. "localhost." — Argon P1:
    // all of them, "localhost.." too) and also reject ".localhost" so the name-prefilter
    // matches the IP-check backstop below.
    let host = host.trim_end_matches('.');
    if host.is_empty() { anyhow::bail!("No host in URL"); }
    // Reject obvious internal names before resolving.
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".internal")
    {
        anyhow::bail!("Private/internal URLs not allowed");
    }
    // #9/#20: pin the port to 443 (https only) for the initial URL AND every redirect
    // hop. Any explicit non-443 port is rejected so the preview fetcher cannot be used
    // as a port scanner / general SSRF engine — this applies regardless of preview mode.
    let port = port.unwrap_or(443);
    if port != 443 {
        anyhow::bail!("Only HTTPS port 443 is allowed");
    }
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|_| anyhow::anyhow!("DNS resolution failed"))?
        .collect();
    if addrs.is_empty() {
        anyhow::bail!("DNS resolution returned no addresses");
    }
    for addr in &addrs {
        if is_private_ip(addr.ip()) {
            anyhow::bail!("Private/internal URLs not allowed");
        }
    }
    Ok(addrs)
}

/// Extract content from <meta property="X" content="..."> or <meta name="X" content="...">
fn extract_meta(html: &str, name: &str) -> Option<String> {
    // Try property= first (og tags), then name= (regular meta)
    for attr in &["property", "name"] {
        let patterns = [
            format!(r#"{}="{}""#, attr, name),
            format!(r#"{}='{}'"#, attr, name),
        ];
        for pat in &patterns {
            // agy P1 (LOW): search an ASCII-lowercased copy. to_lowercase() is Unicode-aware
            // and changes byte length for some characters (ẞ→ß, K→k, İ→i̇), so an offset
            // found in that copy pointed at the wrong place (or a non-boundary) in `html`
            // whenever such a character came first. ASCII lowercasing is byte-for-byte, so
            // offsets line up, and the patterns ("property=", "og:title", …) are ASCII.
            if let Some(idx) = html.to_ascii_lowercase().find(&pat.to_ascii_lowercase()) {
                // #86: still slice with get() (defensive; offsets are boundaries now).
                let Some(after) = html.get(idx..) else { continue };
                // Find content="..."
                if let Some(ci) = after.to_ascii_lowercase().find("content=") {
                    let Some(rest) = after.get(ci + 8..) else { continue };
                    let quote = if rest.starts_with('"') { '"' } else if rest.starts_with('\'') { '\'' } else { continue };
                    let inner = &rest[1..];
                    if let Some(end) = inner.find(quote) {
                        let val = html_decode(&inner[..end]);
                        if !val.is_empty() { return Some(val); }
                    }
                }
            }
        }
    }
    None
}

/// Extract content from <title>...</title>
fn extract_tag(html: &str, tag: &str) -> Option<String> {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    // ASCII-only lowercasing keeps byte offsets identical to `html` (see extract_meta).
    let lower = html.to_ascii_lowercase();
    let start = lower.find(&open)?;
    // #86: slice with get() and bail to None instead of panicking (defensive).
    let after_open = html.get(start..)?;
    let gt = after_open.find('>')?;
    let content_start = start + gt + 1;
    let end = lower.get(content_start..)?.find(&close)?;
    let val = html_decode(html.get(content_start..content_start + end)?.trim());
    if val.is_empty() { None } else { Some(val) }
}

fn html_decode(s: &str) -> String {
    // L9 (#120): decode in a SINGLE left-to-right pass so an already-encoded
    // ampersand isn't decoded twice. The old two-stage version replaced "&amp;"→"&"
    // FIRST and then ran the numeric pass, so "&amp;#39;" became "&#39;" and then
    // wrongly decoded to "'". A single pass consumes each entity once: "&amp;#39;"
    // yields "&#39;" (the literal text the source author wrote), not "'".
    if !s.contains('&') {
        return s.to_string();
    }
    // Named entities recognised at the start of an "&...;" run. Order doesn't
    // matter — each is matched as a complete token before advancing past it.
    const NAMED: &[(&str, char)] = &[
        ("&amp;", '&'),
        ("&lt;", '<'),
        ("&gt;", '>'),
        ("&quot;", '"'),
        ("&#39;", '\''),
        ("&#x27;", '\''),
        ("&#X27;", '\''),
        ("&apos;", '\''),
    ];
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    'scan: while i < bytes.len() {
        if bytes[i] == b'&' {
            // Try a fixed named entity first.
            for (ent, ch) in NAMED {
                if s[i..].starts_with(ent) {
                    out.push(*ch);
                    i += ent.len();
                    continue 'scan;
                }
            }
            // Then a generic numeric "&#NN;" (decimal) or "&#xNN;"/"&#XNN;" (hex).
            if i + 2 < bytes.len() && bytes[i + 1] == b'#' {
                let (radix, mut j) = if bytes[i + 2] == b'x' || bytes[i + 2] == b'X' {
                    (16, i + 3)
                } else {
                    (10, i + 2)
                };
                let digits_start = j;
                while j < bytes.len() && bytes[j] != b';' {
                    j += 1;
                }
                if j < bytes.len() && j > digits_start {
                    if let Ok(code) = u32::from_str_radix(&s[digits_start..j], radix) {
                        if let Some(ch) = char::from_u32(code) {
                            out.push(ch);
                            i = j + 1; // skip past the ';'
                            continue 'scan;
                        }
                    }
                }
            }
        }
        // Not the start of a recognised entity; copy this char verbatim.
        let ch_len = utf8_char_len(bytes[i]);
        out.push_str(&s[i..(i + ch_len).min(s.len())]);
        i += ch_len;
    }
    out
}

/// Byte length of a UTF-8 sequence given its leading byte (defaults to 1 for
/// continuation/invalid bytes, which keeps the byte-wise walk in bounds).
fn utf8_char_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

/// Reject any address that is not a globally-routable public IP. This is the single
/// source of truth used by resolve_and_validate_host (#17) for every hop (#18) and
/// reused by notifications.rs's push-endpoint SSRF guard (#83) so both paths share
/// the same audited logic.
/// #82: in addition to loopback/RFC1918/link-local/CGNAT, this also rejects
/// 192.0.0.0/24, 198.18.0.0/15 (benchmarking), multicast (224.0.0.0/4 / ff00::/8),
/// documentation ranges, and decodes 6to4 (2002::/16) / Teredo (2001::/32) wrappers
/// so a private IPv4 cannot hide inside an IPv6 tunnel address.
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || o[0] == 0
                || (o[0] == 100 && (64..=127).contains(&o[1])) // CGNAT 100.64/10
                || v4.is_broadcast()
                || v4.is_multicast() // 224.0.0.0/4
                || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0.0/24 (IETF protocol assignments)
                || (o[0] == 192 && o[1] == 0 && o[2] == 2) // 192.0.2.0/24 (TEST-NET-1, documentation)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100) // 198.51.100.0/24 (TEST-NET-2)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113) // 203.0.113.0/24 (TEST-NET-3)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19)) // 198.18.0.0/15 (benchmarking)
                || o[0] >= 240 // 240.0.0.0/4 (Class E, reserved-future-use; also covers 255.255.255.255)
        }
        IpAddr::V6(v6) => {
            let seg = v6.segments();
            v6.is_loopback()
                // IPv4-mapped IPv6 (::ffff:x.x.x.x)
                || { seg[0..5] == [0,0,0,0,0] && seg[5] == 0xffff && {
                    let v4 = std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8, seg[6] as u8,
                        (seg[7] >> 8) as u8, seg[7] as u8,
                    );
                    is_private_ip(IpAddr::V4(v4))
                }}
                // 6to4 (2002::/16): next 32 bits embed the IPv4 address — decode & check it.
                || (seg[0] == 0x2002 && {
                    let v4 = std::net::Ipv4Addr::new(
                        (seg[1] >> 8) as u8, seg[1] as u8,
                        (seg[2] >> 8) as u8, seg[2] as u8,
                    );
                    is_private_ip(IpAddr::V4(v4))
                })
                // Teredo (2001:0000::/32): server IPv4 in seg[2..4], client IPv4 (obfuscated,
                // bit-inverted) in seg[6..8] — decode both and check them.
                || (seg[0] == 0x2001 && seg[1] == 0x0000 && {
                    let server = std::net::Ipv4Addr::new(
                        (seg[2] >> 8) as u8, seg[2] as u8,
                        (seg[3] >> 8) as u8, seg[3] as u8,
                    );
                    // Client IPv4 is stored bit-inverted; invert each segment first.
                    let (c6, c7) = (!seg[6], !seg[7]);
                    let client = std::net::Ipv4Addr::new(
                        (c6 >> 8) as u8, c6 as u8,
                        (c7 >> 8) as u8, c7 as u8,
                    );
                    is_private_ip(IpAddr::V4(server)) || is_private_ip(IpAddr::V4(client))
                })
                // NAT64 (64:ff9b::/96, RFC 6052): the target IPv4 is embedded in seg[6..8].
                // On a NAT64-enabled host the kernel forwards to that IPv4, so an AAAA of
                // 64:ff9b::169.254.169.254 would otherwise reach the metadata service.
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0,0,0,0] && {
                    let v4 = std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8, seg[6] as u8,
                        (seg[7] >> 8) as u8, seg[7] as u8,
                    );
                    is_private_ip(IpAddr::V4(v4))
                })
                // Local-use NAT64 prefix (64:ff9b:1::/48, RFC 8215). Operators carve their
                // own translator prefixes out of it with varying embedding layouts, so the
                // IPv4 can't be decoded reliably — and nothing public lives there. Block it.
                || (seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001)
                // IPv4-translated (::ffff:0:a.b.c.d, RFC 2765 SIIT): decode & check.
                || (seg[0..4] == [0,0,0,0] && seg[4] == 0xffff && seg[5] == 0 && {
                    let v4 = std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8, seg[6] as u8,
                        (seg[7] >> 8) as u8, seg[7] as u8,
                    );
                    is_private_ip(IpAddr::V4(v4))
                })
                // Deprecated IPv4-compatible IPv6 (::a.b.c.d): seg[0..6]==0, embedded v4 in
                // seg[6..8]. Decode & check (loopback ::1 is already handled above).
                || (seg[0..6] == [0,0,0,0,0,0] && (seg[6] != 0 || seg[7] != 0) && {
                    let v4 = std::net::Ipv4Addr::new(
                        (seg[6] >> 8) as u8, seg[6] as u8,
                        (seg[7] >> 8) as u8, seg[7] as u8,
                    );
                    is_private_ip(IpAddr::V4(v4))
                })
                // Link-local (fe80::/10)
                || (seg[0] & 0xffc0) == 0xfe80
                // Unique local (fc00::/7)
                || (seg[0] & 0xfe00) == 0xfc00
                // Deprecated site-local (fec0::/10)
                || (seg[0] & 0xffc0) == 0xfec0
                // Multicast (ff00::/8)
                || (seg[0] & 0xff00) == 0xff00
                // Documentation (2001:db8::/32)
                || (seg[0] == 0x2001 && seg[1] == 0x0db8)
                // Unspecified
                || seg == [0; 8]
        }
    }
}

#[cfg(test)]
mod ssrf_tests {
    use super::is_private_ip;
    use std::net::IpAddr;

    fn blocked(s: &str) -> bool { is_private_ip(s.parse::<IpAddr>().unwrap()) }

    #[test]
    fn nat64_prefixes() {
        // RFC 6052 well-known prefix: decoded, private targets blocked …
        assert!(blocked("64:ff9b::7f00:1"));
        assert!(blocked("64:ff9b::a9fe:a9fe"));
        assert!(blocked("64:ff9b::a00:1"));
        // … public targets still allowed (NAT64 hosts reach the internet this way).
        assert!(!blocked("64:ff9b::808:808"));
        // RFC 8215 local-use prefix: blocked wholesale (was reachable before).
        assert!(blocked("64:ff9b:1::7f00:1"));
        assert!(blocked("64:ff9b:1:abcd::1"));
        assert!(blocked("64:ff9b:1:ffff:ffff:ffff:ffff:ffff"));
        // RFC 2765 IPv4-translated form.
        assert!(blocked("::ffff:0:7f00:1"));
        assert!(!blocked("::ffff:0:808:808"));
    }

    #[test]
    fn unicode_before_tags_does_not_shift_offsets() {
        // Each of these lowercases to a different byte length under to_lowercase().
        for pre in ["GROẞE", "\u{212A}elvin", "İstanbul İ İ İ", "ẞẞẞẞẞẞẞẞẞẞ", "İİİİİİİİİİİİİİİİİİİİİİİİİİİİİİ"] {
            let html = format!("<html><head><meta name=\"author\" content=\"{}\">\
                <meta property=\"og:title\" content=\"Real Title\"><title>Tab Title</title>\
                <meta name=\"description\" content=\"Desc ✓\"></head></html>", pre);
            assert_eq!(super::extract_meta(&html, "og:title").as_deref(), Some("Real Title"), "{}", pre);
            assert_eq!(super::extract_tag(&html, "title").as_deref(), Some("Tab Title"), "{}", pre);
            assert_eq!(super::extract_meta(&html, "description").as_deref(), Some("Desc ✓"), "{}", pre);
        }
        // Mixed-case markup still matches.
        let html = "<TITLE>Hi</TITLE><META PROPERTY='OG:TITLE' CONTENT='Up'>";
        assert_eq!(super::extract_tag(html, "title").as_deref(), Some("Hi"));
        assert_eq!(super::extract_meta(html, "og:title").as_deref(), Some("Up"));
    }

    #[test]
    fn existing_ranges_unchanged() {
        for a in ["127.0.0.1", "10.1.2.3", "169.254.169.254", "100.96.133.84", "::1",
                  "::ffff:127.0.0.1", "2002:7f00:1::", "fd7a:115c:a1e0::1", "fe80::1", "::"] {
            assert!(blocked(a), "{} should be blocked", a);
        }
        for a in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(!blocked(a), "{} should be allowed", a);
        }
    }
}

#[cfg(test)]
mod r3_trailing_dot_tests {
    use super::*;

    /// Argon P1 preview.rs:133/313: "host." is canonicalised to "host" (so the whitelist,
    /// pin, TLS name and reported domain all see one spelling); IP literals are untouched.
    #[test]
    fn fully_qualified_hosts_are_canonicalised() {
        let canon = |u: &str| { let mut x = reqwest::Url::parse(u).unwrap(); canonicalize_url_host(&mut x).map(|_| x.to_string()) };
        assert_eq!(canon("https://github.com./a/b?c=1").unwrap(), "https://github.com/a/b?c=1");
        assert_eq!(canon("https://GitHub.COM../x").unwrap(), "https://github.com/x");
        assert_eq!(canon("https://github.com/x").unwrap(), "https://github.com/x");
        assert_eq!(canon("https://1.2.3.4./x").unwrap(), "https://1.2.3.4/x");
    }

    /// The internal-name prefilter strips every trailing dot, before any DNS lookup.
    #[tokio::test]
    async fn internal_names_with_trailing_dots_are_refused() {
        for h in ["localhost.", "localhost..", "svc.internal.", "svc.internal..", "printer.local.."] {
            let e = resolve_and_validate_host(h, Some(443)).await.unwrap_err().to_string();
            assert!(e.contains("Private/internal"), "{h}: {e}");
        }
    }
}

#[cfg(test)]
pub(crate) mod tweet_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    pub(crate) struct Fixture {
        pub(crate) service: Arc<PreviewService>,
        pub(crate) path: PathBuf,
        pub(crate) calls: Arc<AtomicUsize>,
        clock: Arc<crate::twitter::tests::FakeClock>,
    }
    impl Fixture {
        pub(crate) fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("cryptirc-preview-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let clock = Arc::new(crate::twitter::tests::FakeClock::default());
            let service = Arc::new(PreviewService {
                data_dir: path.to_str().unwrap().into(),
                twitter: Arc::new(crate::twitter::tests::fixture_client(
                    calls.clone(),
                    clock.clone(),
                )),
                preview_sem: Arc::new(Semaphore::new(8)),
                tweets: Default::default(),
            });
            Self {
                service,
                path,
                calls,
                clock,
            }
        }
        pub(crate) fn semaphore(&self) -> Arc<Semaphore> {
            self.service.preview_sem.clone()
        }
        pub(crate) fn with_thread() -> Self {
            let mut fixture = Self::new();
            Arc::get_mut(&mut fixture.service).unwrap().twitter =
                Arc::new(crate::twitter::tests::fixture_thread_client(
                    fixture.calls.clone(),
                    fixture.clock.clone(),
                ));
            fixture
        }
        async fn policy(&self, mode: &str) {
            std::fs::write(
                self.path.join("admin_settings.json"),
                serde_json::json!({"link_preview_mode":mode}).to_string(),
            )
            .unwrap();
            self.service.update_tweet_policy().await;
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[tokio::test]
    async fn preview_singleflight_account_cache_expiry_refresh() {
        let fixture = Fixture::new();
        let requests = (0..10).map(|_| fixture.service.fetch_tweet_preview("alice", "123", false));
        let results = futures_util::future::join_all(requests).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.preview_sem.available_permits(), 8);
        assert!(fixture.service.tweets.lock().unwrap().flights.is_empty());
        assert_eq!(fixture.service.tweets.lock().unwrap().waiters, 0);
        fixture
            .service
            .fetch_tweet_preview("alice", "123", false)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        fixture
            .service
            .fetch_tweet_preview("bob", "123", false)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 2);
        fixture
            .service
            .fetch_tweet_preview("alice", "123", true)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 3);
        assert!(matches!(
            fixture
                .service
                .fetch_tweet_preview("alice", "123", true)
                .await,
            Err(PreviewError::RateLimited(_))
        ));
        fixture.clock.advance(601);
        fixture
            .service
            .fetch_tweet_preview("alice", "123", false)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn preview_policy_invalidation_saturation_and_disconnect_cleanup() {
        let fixture = Fixture::new();
        let permits = fixture
            .service
            .preview_sem
            .clone()
            .try_acquire_many_owned(8)
            .unwrap();
        assert!(matches!(
            fixture
                .service
                .fetch_tweet_preview("alice", "123", false)
                .await,
            Err(PreviewError::Busy)
        ));
        assert!(fixture.service.tweets.lock().unwrap().flights.is_empty());
        drop(permits);
        fixture
            .service
            .fetch_tweet_preview("alice", "123", false)
            .await
            .unwrap();
        fixture.policy("off").await;
        let disabled = fixture
            .service
            .fetch_tweet_preview("alice", "123", false)
            .await
            .unwrap();
        assert_eq!(disabled["availability"]["reason"], "provider_disabled");
        assert!(fixture.service.tweets.lock().unwrap().entries.is_empty());
        fixture.policy("all").await;
        let service = fixture.service.clone();
        let pending =
            tokio::spawn(async move { service.fetch_tweet_preview("alice", "124", false).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        fixture.policy("off").await;
        let disabled = pending.await.unwrap().unwrap();
        assert_eq!(disabled["availability"]["reason"], "provider_disabled");
        assert!(fixture.service.tweets.lock().unwrap().entries.is_empty());
        fixture.policy("all").await;
        let service = fixture.service.clone();
        let pending =
            tokio::spawn(async move { service.fetch_tweet_preview("alice", "125", false).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        pending.abort();
        let _ = pending.await;
        assert_eq!(fixture.service.tweets.lock().unwrap().waiters, 0);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(fixture.service.tweets.lock().unwrap().flights.is_empty());
        assert_eq!(fixture.service.preview_sem.available_permits(), 8);
    }

    #[test]
    fn preview_cache_count_bytes_lru_and_failure_ttls() {
        let mut cache = TweetCache::default();
        let now = Duration::ZERO;
        for index in 0..1001 {
            cache.insert(
                (format!("user{}", index / 100), 1, index.to_string()),
                Ok(Arc::new(serde_json::json!({}))),
                now,
            );
        }
        assert_eq!(cache.entries.len(), 1000);
        assert!(!cache.entries.contains_key(&("user0".into(), 1, "0".into())));
        for index in 0..101 {
            cache.insert(
                ("alice".into(), 1, index.to_string()),
                Ok(Arc::new(serde_json::json!({}))),
                now,
            );
        }
        assert_eq!(cache.entries.keys().filter(|k| k.0 == "alice").count(), 100);
        assert!(!cache.entries.contains_key(&("alice".into(), 1, "0".into())));
        let large = Arc::new(serde_json::json!({"text":"x".repeat(240 * 1024)}));
        for index in 0..150 {
            cache.insert(
                (format!("large{}", index / 100), 1, index.to_string()),
                Ok(large.clone()),
                now,
            );
        }
        assert!(cache.bytes <= 32 * 1024 * 1024 && cache.entries.len() <= 1000);
        cache.insert(
            ("err".into(), 1, "1".into()),
            Err(PreviewError::UpstreamFailure),
            now,
        );
        cache.expire(Duration::from_secs(16));
        assert!(!cache.entries.contains_key(&("err".into(), 1, "1".into())));
    }

    #[tokio::test]
    async fn preview_waiter_bound() {
        let fixture = Fixture::new();
        let requests = (0..24).map(|_| fixture.service.fetch_tweet_preview("alice", "123", false));
        let results = futures_util::future::join_all(requests).await;
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(PreviewError::Busy)))
                .count(),
            8
        );
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.service.tweets.lock().unwrap().waiters, 0);
    }

    #[tokio::test]
    async fn preview_thread_coalescing_shared_refresh_and_ttl() {
        let fixture = Fixture::with_thread();
        let results = futures_util::future::join_all(
            (0..10).map(|_| fixture.service.fetch_tweet_thread("alice", "123", false)),
        )
        .await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            results[0].as_ref().unwrap()["entries"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        fixture
            .service
            .fetch_tweet_preview("alice", "123", true)
            .await
            .unwrap();
        assert!(matches!(
            fixture
                .service
                .fetch_tweet_thread("alice", "123", true)
                .await,
            Err(PreviewError::RateLimited(_))
        ));
        fixture.clock.advance(301);
        fixture
            .service
            .fetch_tweet_thread("alice", "123", false)
            .await
            .unwrap();
        assert_eq!(fixture.calls.load(Ordering::SeqCst), 3);
        assert_eq!(fixture.service.preview_sem.available_permits(), 8);
    }

    #[tokio::test]
    async fn media_fallback_bound_to_retrieved_assets_and_policy() {
        let fixture = Fixture::new();
        let key = crate::twitter::media_asset_key("https://pbs.twimg.com/profile_images/1/synthetic_normal.jpg?name=x").unwrap();
        assert!(!fixture.service.tweet_media_retrieved("alice", &[key.clone()]));
        fixture.service.fetch_tweet_preview("alice", "123", false).await.unwrap();
        assert!(fixture.service.tweet_media_retrieved("alice", &[key.clone()]));
        assert!(!fixture.service.tweet_media_retrieved("bob", &[key.clone()]));
        let other = crate::twitter::media_asset_key("https://pbs.twimg.com/media/never.jpg").unwrap();
        assert!(!fixture.service.tweet_media_retrieved("alice", &[key.clone(), other]));
        assert!(fixture.service.tweet_media_allowed().await);
        assert_eq!(fixture.service.tweet_capabilities().await, (true, false));
        fixture.policy("off").await;
        assert!(!fixture.service.tweet_media_allowed().await);
        assert!(!fixture.service.tweet_media_retrieved("alice", &[key]));
        fixture.clock.advance(1);
    }

    #[tokio::test]
    async fn unconfigured_providers_answer_locally_without_policy_or_permits() {
        let path = std::env::temp_dir().join(format!("cryptirc-preview-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        // Even an "all" policy cannot enable a provider whose startup flag is unset.
        std::fs::write(path.join("admin_settings.json"), r#"{"link_preview_mode":"all"}"#).unwrap();
        let sem = Arc::new(Semaphore::new(8));
        let service = Arc::new(PreviewService::new(path.to_str().unwrap(), sem.clone()));
        if service.twitter.enabled() || service.twitter.thread_enabled() {
            // The test environment set a provider flag; the default-off contract is
            // covered by twitter::tests::transport_disabled_invalid_and_coalesced_activation.
            let _ = std::fs::remove_dir_all(&path);
            return;
        }
        let permits = sem.clone().try_acquire_many_owned(8).unwrap();
        for thread in [false, true] {
            let value = if thread {
                service.fetch_tweet_thread("alice", "123", false).await
            } else {
                service.fetch_tweet_preview("alice", "123", true).await
            }
            .unwrap();
            assert_eq!(value["availability"]["reason"], "provider_disabled");
        }
        drop(permits);
        assert_eq!(service.tweet_capabilities().await, (false, false));
        assert!(!service.tweet_media_allowed().await);
        assert!(service.tweets.lock().unwrap().entries.is_empty());
        assert!(service.tweets.lock().unwrap().allowed.is_none(), "policy never consulted");
        let _ = std::fs::remove_dir_all(&path);
    }
}
