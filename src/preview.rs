/// preview.rs — Link preview metadata fetcher
///
/// Fetches og:title, og:description, og:image from URLs.
/// Blocks private/internal IPs to prevent SSRF.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

const MAX_BODY: usize = 51_200; // 50KB max fetch
const TIMEOUT: Duration = Duration::from_secs(5);

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
    client: reqwest::Client,
}

impl PreviewService {
    pub fn new(data_dir: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .redirect(reqwest::redirect::Policy::limited(3))
            .user_agent("CryptIRC/1.0 (Link Preview)")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self { data_dir: data_dir.to_string(), client }
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
        // Validate URL
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| anyhow::anyhow!("Invalid URL"))?;

        // Only HTTPS
        if parsed.scheme() != "https" {
            anyhow::bail!("Only HTTPS URLs supported");
        }

        let domain = parsed.host_str().unwrap_or("").to_lowercase();
        if domain.is_empty() {
            anyhow::bail!("No host in URL");
        }

        // Block private/internal IPs (SSRF protection)
        if is_private_host(&domain).await {
            anyhow::bail!("Private/internal URLs not allowed");
        }

        // Check whitelist
        let settings = self.load_settings().await;
        match settings.mode.as_str() {
            "off" => anyhow::bail!("Link previews disabled"),
            "whitelist" => {
                let allowed = settings.whitelist.iter().any(|w| {
                    domain == w.as_str() || domain.ends_with(&format!(".{}", w))
                });
                if !allowed {
                    anyhow::bail!("Domain not in whitelist");
                }
            }
            "all" => {} // Allow everything
            _ => anyhow::bail!("Unknown preview mode"),
        }

        // Fetch the page (limited to MAX_BODY bytes)
        let resp = self.client.get(url)
            .header("Accept", "text/html")
            .send()
            .await?;

        let ct = resp.headers().get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !ct.contains("text/html") && !ct.contains("application/xhtml") {
            anyhow::bail!("Not HTML");
        }

        let bytes = resp.bytes().await?;
        let body = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_BODY)]);

        // Extract metadata
        let title = extract_meta(&body, "og:title")
            .or_else(|| extract_tag(&body, "title"));
        let description = extract_meta(&body, "og:description")
            .or_else(|| extract_meta(&body, "description"));
        let image = extract_meta(&body, "og:image");
        let site_name = extract_meta(&body, "og:site_name");

        Ok(LinkPreview {
            url: url.to_string(),
            domain,
            title,
            description: description.map(|d| if d.len() > 200 { format!("{}…", &d[..197]) } else { d }),
            image,
            site_name,
        })
    }
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
                let after = &html[idx..];
                // Find content="..."
                if let Some(ci) = after.to_lowercase().find("content=") {
                    let rest = &after[ci + 8..];
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
    let after_open = &html[start..];
    let gt = after_open.find('>')?;
    let content_start = start + gt + 1;
    let end = lower[content_start..].find(&close)?;
    let val = html_decode(html[content_start..content_start + end].trim());
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

async fn is_private_host(host: &str) -> bool {
    // Check obvious patterns
    if host == "localhost" || host.ends_with(".local") || host.ends_with(".internal") {
        return true;
    }
    // Resolve and check IP
    if let Ok(addrs) = tokio::net::lookup_host(format!("{}:80", host)).await {
        for addr in addrs {
            if is_private_ip(addr.ip()) { return true; }
        }
    }
    false
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local()
                || v4.octets()[0] == 0
                || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127 // CGNAT
                || v4.is_broadcast()
        }
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}
