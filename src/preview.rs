/// preview.rs — Link preview metadata fetcher
///
/// Fetches og:title, og:description, og:image from URLs.
/// Blocks private/internal IPs to prevent SSRF.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

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
}

impl PreviewService {
    pub fn new(data_dir: &str) -> Self {
        // #17/#18: we no longer keep a shared, redirect-following client. Each hop
        // is fetched with a freshly-built client that (a) disables automatic
        // redirects (Policy::none) and (b) pins DNS to the already-validated public
        // IPs via resolve_to_addrs, so reqwest cannot re-resolve to a private IP
        // (DNS-rebinding / TOCTOU). See build_pinned_client / fetch_preview.
        Self { data_dir: data_dir.to_string() }
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

        // The host that owns the resulting preview is the ORIGINAL request host,
        // even though we may follow redirects.
        let original_domain = reqwest::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
            .unwrap_or_default();

        // Manual redirect loop. Each hop is fully re-validated (scheme + private-IP
        // with pinned resolution + whitelist) before we connect, and the connection
        // is pinned to the validated IPs (#17 DNS-rebinding/TOCTOU, #18 redirect bypass).
        let mut current = url.to_string();
        let mut resp = None;
        for hop in 0..=MAX_REDIRECTS {
            // (1) Parse + scheme check on THIS hop's URL.
            let parsed = reqwest::Url::parse(&current)
                .map_err(|_| anyhow::anyhow!("Invalid URL"))?;
            if parsed.scheme() != "https" {
                anyhow::bail!("Only HTTPS URLs supported");
            }
            let domain = parsed.host_str().unwrap_or("").to_lowercase();
            if domain.is_empty() {
                anyhow::bail!("No host in URL");
            }

            // (2) Resolve the host ONCE and validate EVERY resolved IP is public.
            // The returned addrs are what we pin the connection to, so reqwest
            // cannot re-resolve to a private IP afterwards.
            let addrs = resolve_and_validate_host(&domain, parsed.port_or_known_default()).await?;

            // (3) Whitelist check on THIS hop's host.
            if settings.mode == "whitelist" {
                let allowed = settings.whitelist.iter().any(|w| {
                    domain == w.as_str() || domain.ends_with(&format!(".{}", w))
                });
                if !allowed {
                    anyhow::bail!("Domain not in whitelist");
                }
            } else if settings.mode != "all" {
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
        let image = extract_meta(&body, "og:image")
            .filter(|img| img.to_ascii_lowercase().starts_with("https://"));
        let site_name = extract_meta(&body, "og:site_name");

        Ok(LinkPreview {
            url: url.to_string(),
            domain: original_domain,
            title,
            description: description.map(|d| if d.chars().count() > 200 { format!("{}…", d.chars().take(197).collect::<String>()) } else { d }),
            image,
            site_name,
        })
    }
}

/// Build a reqwest client pinned to the already-validated public IPs for `host`.
///
/// #17: resolve_to_addrs() forces reqwest to connect to exactly these addresses
/// for `host`, so DNS is not re-resolved at connect time (defeats DNS-rebinding /
/// TOCTOU). #18: Policy::none() disables automatic redirect following; the caller
/// follows + re-validates each hop itself.
fn build_pinned_client(host: &str, addrs: &[SocketAddr]) -> Result<reqwest::Client> {
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

/// Read a response body incrementally, capping the buffered size at `max` bytes.
/// Aborts (returns what was read so far) once the cap is reached so an oversized
/// or decompression-bomb body cannot exhaust memory. (#32)
async fn read_capped_body(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = resp.chunk().await? {
        let remaining = max.saturating_sub(buf.len());
        if remaining == 0 {
            break;
        }
        let take = remaining.min(chunk.len());
        buf.extend_from_slice(&chunk[..take]);
        if buf.len() >= max {
            break;
        }
    }
    Ok(buf)
}

/// Resolve `host` once and validate that EVERY resolved address is a public IP.
/// Returns the validated SocketAddrs (to be pinned by the caller). Rejects when
/// resolution yields zero addresses or when ANY address is private/internal.
/// (#17: validate all A/AAAA records and pin the exact set we validated.)
async fn resolve_and_validate_host(host: &str, port: Option<u16>) -> Result<Vec<SocketAddr>> {
    // Reject obvious internal names before resolving.
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        anyhow::bail!("Private/internal URLs not allowed");
    }
    let port = port.unwrap_or(443);
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
            if let Some(idx) = html.to_lowercase().find(&pat.to_lowercase()) {
                // #86: idx came from a lowercased copy; to_lowercase() can change byte
                // length for some Unicode, so idx may not be a char boundary in the
                // original. Use get() and bail to None instead of panicking on slice.
                let Some(after) = html.get(idx..) else { continue };
                // Find content="..."
                if let Some(ci) = after.to_lowercase().find("content=") {
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
    let lower = html.to_lowercase();
    let start = lower.find(&open)?;
    // #86: indices come from the lowercased copy and may not be char boundaries in
    // the original (to_lowercase() can change byte length). Slice with get() and
    // bail to None instead of panicking.
    let after_open = html.get(start..)?;
    let gt = after_open.find('>')?;
    let content_start = start + gt + 1;
    let end = lower.get(content_start..)?.find(&close)?;
    let val = html_decode(html.get(content_start..content_start + end)?.trim());
    if val.is_empty() { None } else { Some(val) }
}

fn html_decode(s: &str) -> String {
    s.replace("&amp;", "&")
     .replace("&lt;", "<")
     .replace("&gt;", ">")
     .replace("&quot;", "\"")
     .replace("&#39;", "'")
     .replace("&#x27;", "'")
     .replace("&apos;", "'")
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
