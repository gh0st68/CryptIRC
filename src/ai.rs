//! ai.rs — multi-provider AI chat for the AI bot. Given a provider, model, API key,
//! system context, user message and max_tokens, calls the right API and returns the
//! assistant's reply text. Providers: OpenAI (ChatGPT), Anthropic (Claude), xAI
//! (Grok), Google (Gemini), OpenRouter, Groq, Mistral, and a custom OpenAI-compatible
//! endpoint. reqwest is built without the "json" feature, so request bodies are
//! serialized with serde_json and responses are parsed from text().
//!
//! SECURITY: error messages returned to callers NEVER include the reqwest Display
//! (it can carry the request URL, and Google puts the API key in the URL query).

use std::sync::OnceLock;
use serde_json::Value;
use base64::Engine as _;

/// The set of providers the UI offers (also used to validate input).
pub const PROVIDERS: &[&str] = &[
    "openai", "anthropic", "xai", "google", "perplexity", "openrouter", "groq", "mistral",
    "openai-codex", "custom",
];

// ── ChatGPT (Codex) OAuth constants — mirror the OpenAI Codex CLI, per
// NousResearch/hermes-agent (hermes_cli/auth.py). The user imports the token bundle
// produced by `codex login` (~/.codex/auth.json); we call the Codex Responses backend
// with it. This uses a ChatGPT subscription outside the Codex CLI — it's ToS-gray and
// Cloudflare-gated (whitelisted originator `codex_cli_rs`), so it can break at OpenAI's
// discretion. Off unless the user explicitly imports a token.
const CODEX_BASE: &str = "https://chatgpt.com/backend-api/codex";
const CODEX_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const CODEX_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";

/// A longer-timeout client — AI completions routinely take longer than the 10s the
/// other bots use.
fn client() -> &'static reqwest::Client {
    static C: OnceLock<reqwest::Client> = OnceLock::new();
    C.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new())
    })
}

/// Percent-encode a URL component (used for the Google URL's model + key).
fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(*b as char),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// Base URL for the OpenAI-compatible providers. `custom` is the user-supplied base
/// URL, only used when provider == "custom".
fn openai_base(provider: &str, custom: &str) -> Option<String> {
    Some(match provider {
        "openai"     => "https://api.openai.com/v1".to_string(),
        "xai"        => "https://api.x.ai/v1".to_string(),
        "openrouter" => "https://openrouter.ai/api/v1".to_string(),
        "groq"       => "https://api.groq.com/openai/v1".to_string(),
        "mistral"    => "https://api.mistral.ai/v1".to_string(),
        "perplexity" => "https://api.perplexity.ai".to_string(),
        "custom"     => {
            // Self-hosted / LAN LLMs (Ollama, LM Studio, LocalAI, vLLM, …) that speak
            // the OpenAI protocol — allow http:// too (a LAN box like
            // http://192.168.1.5:11434/v1 usually isn't TLS). The owner is pointing at
            // their OWN endpoint, so this is their call.
            let c = custom.trim().trim_end_matches('/');
            if !(c.starts_with("https://") || c.starts_with("http://")) { return None; }
            c.to_string()
        }
        _ => return None,
    })
}

/// Run a chat completion. `custom_base` is only consulted for provider == "custom".
pub async fn chat(
    provider: &str,
    custom_base: &str,
    model: &str,
    api_key: &str,
    system: &str,
    // The conversation as (role, content) turns — role is "user" or "assistant";
    // the current message is the last turn. History enables multi-turn memory.
    turns: &[(String, String)],
    max_tokens: u32,
) -> Result<String, String> {
    // Self-hosted/custom endpoints often need no key; every hosted provider does.
    if api_key.trim().is_empty() && provider != "custom" {
        return Err("AI: no API key set (Settings ▸ Bots)".to_string());
    }
    if model.trim().is_empty() {
        return Err("AI: no model set".to_string());
    }
    if turns.is_empty() {
        return Err("AI: empty message".to_string());
    }
    let max_tokens = max_tokens.clamp(1, 32_000);
    match provider {
        "anthropic"    => anthropic(model, api_key, system, turns, max_tokens).await,
        "google"       => google(model, api_key, system, turns, max_tokens).await,
        "openai-codex" => codex(model, api_key, system, turns, max_tokens).await,
        _ => {
            let base = openai_base(provider, custom_base)
                .ok_or_else(|| "AI: unknown provider or bad custom URL (must be http(s)://)".to_string())?;
            openai_compat(&base, model, api_key, system, turns, max_tokens).await
        }
    }
}

/// Extract a provider error message from a parsed JSON body, falling back to a
/// generic string. Never surfaces the raw request (no key/URL leak).
fn err_msg(j: &Value, status: u16) -> String {
    let m = j.get("error").and_then(|e| e.get("message")).and_then(|m| m.as_str())
        .or_else(|| j.get("error").and_then(|e| e.as_str()))
        .or_else(|| j.get("message").and_then(|m| m.as_str()))
        .unwrap_or("request rejected");
    format!("AI: {} ({})", m, status)
}

async fn openai_compat(base: &str, model: &str, key: &str, system: &str, turns: &[(String, String)], max_tokens: u32) -> Result<String, String> {
    let mut messages: Vec<Value> = Vec::new();
    if !system.trim().is_empty() {
        messages.push(serde_json::json!({"role": "system", "content": system}));
    }
    for (role, content) in turns {
        messages.push(serde_json::json!({"role": role, "content": content}));
    }
    let body = serde_json::json!({"model": model, "messages": messages, "max_tokens": max_tokens}).to_string();

    let mut req = client().post(format!("{}/chat/completions", base))
        .header("Content-Type", "application/json")
        .body(body);
    // A self-hosted endpoint may take no key; only send auth when we have one.
    if !key.trim().is_empty() {
        req = req.header("Authorization", format!("Bearer {}", key));
    }
    let resp = req.send().await
        .map_err(|_| "AI: request failed (network/timeout)".to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(err_msg(&j, status));
    }
    j.get("choices").and_then(|c| c.get(0)).and_then(|c| c.get("message"))
        .and_then(|m| m.get("content")).and_then(|c| c.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AI: empty response".to_string())
}

async fn anthropic(model: &str, key: &str, system: &str, turns: &[(String, String)], max_tokens: u32) -> Result<String, String> {
    let msgs: Vec<Value> = turns.iter()
        .map(|(role, content)| serde_json::json!({"role": role, "content": content}))
        .collect();
    let mut body = serde_json::json!({
        "model": model,
        "max_tokens": max_tokens,
        "messages": msgs,
    });
    if !system.trim().is_empty() {
        body["system"] = Value::String(system.to_string());
    }
    let resp = client().post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send().await
        .map_err(|_| "AI: request failed (network/timeout)".to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(err_msg(&j, status));
    }
    j.get("content").and_then(|c| c.get(0)).and_then(|c| c.get("text")).and_then(|t| t.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AI: empty response".to_string())
}

async fn google(model: &str, key: &str, system: &str, turns: &[(String, String)], max_tokens: u32) -> Result<String, String> {
    // The key is a URL query param here — so NEVER echo the URL or a reqwest Display.
    let url = format!(
        "https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}",
        enc(model), enc(key)
    );
    // Gemini uses role "model" for the assistant; map "assistant" → "model".
    let contents: Vec<Value> = turns.iter().map(|(role, content)| {
        let r = if role == "assistant" { "model" } else { "user" };
        serde_json::json!({"role": r, "parts": [{"text": content}]})
    }).collect();
    let mut body = serde_json::json!({
        "contents": contents,
        "generationConfig": {"maxOutputTokens": max_tokens},
    });
    if !system.trim().is_empty() {
        body["systemInstruction"] = serde_json::json!({"parts": [{"text": system}]});
    }
    let resp = client().post(url)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send().await
        .map_err(|_| "AI: request failed (network/timeout)".to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) {
        return Err(err_msg(&j, status));
    }
    j.get("candidates").and_then(|c| c.get(0)).and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts")).and_then(|p| p.get(0)).and_then(|p| p.get("text"))
        .and_then(|t| t.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "AI: empty response".to_string())
}

// ── ChatGPT (Codex) OAuth provider ───────────────────────────────────────────
// `api_key` here is the imported token BUNDLE (the JSON from `codex login`'s
// ~/.codex/auth.json), NOT a plain key. We pull the access_token + account id out of
// it, call the Codex Responses backend (SSE), and on a 401 self-refresh once with the
// bundle's refresh_token and retry. We never persist the refreshed token (keeps this
// self-contained), so after expiry each turn does one extra refresh — acceptable.

/// Pull (access_token, account_id, refresh_token) out of a Codex auth bundle. Accepts
/// both the `{tokens:{...}}` nesting (~/.codex/auth.json) and a flat object.
fn codex_parse_bundle(raw: &str) -> Result<(String, String, String), String> {
    let v: Value = serde_json::from_str(raw.trim())
        .map_err(|_| "ChatGPT: token isn't valid JSON — paste the contents of ~/.codex/auth.json".to_string())?;
    let tokens = v.get("tokens").unwrap_or(&v);
    let pick = |k: &str| tokens.get(k).and_then(|s| s.as_str())
        .or_else(|| v.get(k).and_then(|s| s.as_str()))
        .map(|s| s.to_string());
    let access = pick("access_token").filter(|s| !s.is_empty())
        .ok_or("ChatGPT: no access_token in the imported bundle")?;
    let refresh = pick("refresh_token").unwrap_or_default();
    let account = pick("account_id")
        .or_else(|| pick("id_token").and_then(|jwt| codex_account_from_jwt(&jwt)))
        .unwrap_or_default();
    Ok((access, account, refresh))
}

/// Extract the ChatGPT account id from an id_token JWT's `https://api.openai.com/auth`
/// claim. No signature check — it's the user's own token, used only for a header.
fn codex_account_from_jwt(jwt: &str) -> Option<String> {
    let payload_b64 = jwt.split('.').nth(1)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64).ok()?;
    let claims: Value = serde_json::from_slice(&bytes).ok()?;
    claims.get("https://api.openai.com/auth")
        .and_then(|a| a.get("chatgpt_account_id"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string())
}

/// Exchange a refresh_token for a fresh access_token at the OpenAI OAuth endpoint.
async fn codex_refresh(refresh_token: &str) -> Result<String, String> {
    if refresh_token.trim().is_empty() { return Err("ChatGPT: token expired (no refresh token to renew it — re-import)".into()); }
    let body = serde_json::json!({
        "client_id": CODEX_CLIENT_ID,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "scope": "openid profile email",
    }).to_string();
    let resp = client().post(CODEX_TOKEN_URL)
        .header("Content-Type", "application/json")
        .body(body).send().await
        .map_err(|_| "ChatGPT: token refresh failed (network/timeout)".to_string())?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if !(200..300).contains(&status) { return Err(err_msg(&j, status)); }
    j.get("access_token").and_then(|s| s.as_str()).map(|s| s.to_string())
        .ok_or_else(|| "ChatGPT: refresh returned no access_token".to_string())
}

/// One Codex Responses call with a given access token. Returns Ok(text) or Err. The
/// bool in Err signals "unauthorized" so the caller can refresh + retry.
async fn codex_call(model: &str, access: &str, account: &str, system: &str, turns: &[(String, String)], max_tokens: u32) -> Result<String, (String, bool)> {
    let input: Vec<Value> = turns.iter().map(|(role, content)| {
        // Responses API: assistant text is "output_text", user/other is "input_text".
        let ttype = if role == "assistant" { "output_text" } else { "input_text" };
        serde_json::json!({"role": role, "content": [{"type": ttype, "text": content}]})
    }).collect();
    let mut body = serde_json::json!({
        "model": model,
        "input": input,
        "stream": true,
        "store": false,
        "max_output_tokens": max_tokens,
    });
    if !system.trim().is_empty() { body["instructions"] = Value::String(system.to_string()); }

    let mut req = client().post(format!("{}/responses", CODEX_BASE))
        .header("Content-Type", "application/json")
        .header("Authorization", format!("Bearer {}", access))
        // Cloudflare in front of the Codex backend only serves the whitelisted CLI
        // originator; a non-matching value is 403'd.
        .header("originator", "codex_cli_rs")
        .header("User-Agent", "codex_cli_rs/0.1")
        .header("Accept", "text/event-stream");
    if !account.is_empty() { req = req.header("ChatGPT-Account-ID", account); }

    let resp = req.body(body.to_string()).send().await
        .map_err(|_| ("ChatGPT: request failed (network/timeout)".to_string(), false))?;
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    if !(200..300).contains(&status) {
        if status == 401 { return Err(("ChatGPT: unauthorized".to_string(), true)); }
        if status == 403 { return Err(("ChatGPT: blocked by OpenAI (403) — the Codex backend refused this request".to_string(), false)); }
        let j: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        return Err((err_msg(&j, status), false));
    }
    codex_parse_sse(&text).map_err(|e| (e, false))
}

/// Codex provider entry: parse the bundle, call, and refresh-and-retry once on 401.
async fn codex(model: &str, bundle: &str, system: &str, turns: &[(String, String)], max_tokens: u32) -> Result<String, String> {
    let (access, account, refresh) = codex_parse_bundle(bundle)?;
    match codex_call(model, &access, &account, system, turns, max_tokens).await {
        Ok(t) => Ok(t),
        Err((_, true)) => {
            // Access token expired — refresh once and retry.
            let fresh = codex_refresh(&refresh).await?;
            codex_call(model, &fresh, &account, system, turns, max_tokens).await.map_err(|(e, _)| e)
        }
        Err((e, false)) => Err(e),
    }
}

/// Parse a buffered Responses SSE transcript into the assistant's text. Accumulates
/// `response.output_text.delta` frames; falls back to the final completed event.
fn codex_parse_sse(text: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut completed: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        let Some(data) = line.strip_prefix("data:") else { continue };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" { continue; }
        let Ok(ev) = serde_json::from_str::<Value>(data) else { continue };
        match ev.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "response.output_text.delta" => {
                if let Some(d) = ev.get("delta").and_then(|d| d.as_str()) { out.push_str(d); }
            }
            "response.completed" | "response.done" => {
                if let Some(t) = codex_extract_completed(&ev) { completed = Some(t); }
            }
            "error" | "response.failed" | "response.error" => {
                let m = ev.get("message")
                    .or_else(|| ev.get("error").and_then(|e| e.get("message")))
                    .or_else(|| ev.get("response").and_then(|r| r.get("error")).and_then(|e| e.get("message")))
                    .and_then(|m| m.as_str()).unwrap_or("stream error");
                return Err(format!("ChatGPT: {}", m));
            }
            _ => {}
        }
    }
    let result = if !out.trim().is_empty() { out.trim().to_string() }
                 else { completed.unwrap_or_default().trim().to_string() };
    if result.is_empty() { Err("ChatGPT: empty response".into()) } else { Ok(result) }
}

/// Pull the concatenated output text out of a `response.completed` event's
/// `response.output[].content[].text`.
fn codex_extract_completed(ev: &Value) -> Option<String> {
    let output = ev.get("response").and_then(|r| r.get("output")).and_then(|o| o.as_array())?;
    let mut s = String::new();
    for item in output {
        if let Some(content) = item.get("content").and_then(|c| c.as_array()) {
            for part in content {
                if let Some(t) = part.get("text").and_then(|t| t.as_str()) { s.push_str(t); }
            }
        }
    }
    if s.is_empty() { None } else { Some(s) }
}

#[cfg(test)]
mod codex_tests {
    use super::*;

    fn mk_jwt(claims: &str) -> String {
        let p = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims);
        format!("header.{}.sig", p)
    }

    #[test]
    fn parse_bundle_flat_and_nested() {
        let flat = r#"{"access_token":"AT","refresh_token":"RT","account_id":"acct-1"}"#;
        let (a, acc, r) = codex_parse_bundle(flat).unwrap();
        assert_eq!((a.as_str(), acc.as_str(), r.as_str()), ("AT", "acct-1", "RT"));

        // nested {tokens:{...}} with account id derived from the id_token JWT
        let jwt = mk_jwt(r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-jwt"}}"#);
        let nested = format!(r#"{{"tokens":{{"access_token":"AT2","refresh_token":"RT2","id_token":"{}"}}}}"#, jwt);
        let (a2, acc2, r2) = codex_parse_bundle(&nested).unwrap();
        assert_eq!((a2.as_str(), acc2.as_str(), r2.as_str()), ("AT2", "acct-jwt", "RT2"));
    }

    #[test]
    fn parse_bundle_rejects_garbage_and_missing_access() {
        assert!(codex_parse_bundle("not json").is_err());
        assert!(codex_parse_bundle(r#"{"refresh_token":"x"}"#).is_err()); // no access_token
    }

    #[test]
    fn account_from_jwt() {
        let jwt = mk_jwt(r#"{"https://api.openai.com/auth":{"chatgpt_account_id":"acct-xyz"}}"#);
        assert_eq!(codex_account_from_jwt(&jwt).as_deref(), Some("acct-xyz"));
        assert_eq!(codex_account_from_jwt("garbage"), None);          // not a JWT
        assert_eq!(codex_account_from_jwt(&mk_jwt(r#"{"sub":"u"}"#)), None); // claim absent
    }

    #[test]
    fn sse_accumulates_deltas() {
        let sse = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}\n\
                   \ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}\n\
                   \ndata: {\"type\":\"response.completed\"}\n\
                   \ndata: [DONE]\n";
        assert_eq!(codex_parse_sse(sse).unwrap(), "Hello");
    }

    #[test]
    fn sse_falls_back_to_completed_output() {
        let comp = r#"data: {"type":"response.completed","response":{"output":[{"content":[{"text":"Answer"}]}]}}"#;
        assert_eq!(codex_parse_sse(comp).unwrap(), "Answer");
    }

    #[test]
    fn sse_surfaces_error_frames() {
        let err = "data: {\"type\":\"error\",\"message\":\"boom\"}\n";
        let e = codex_parse_sse(err).unwrap_err();
        assert!(e.contains("boom"), "got: {}", e);
    }

    #[test]
    fn sse_empty_is_error() {
        assert!(codex_parse_sse("data: [DONE]\n").is_err());
    }
}
