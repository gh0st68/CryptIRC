# Add HTML / JS App & Markdown Support to CryptIRC Paste

## Why

CryptIRC pastes render every payload as escaped plain text, so a single-file HTML/JS app or a Markdown document shared through a paste is an unreadable wall of source. The smart-paste flow already detects multi-line text pasted into the chat input, but it always creates a `text` paste — it cannot show the user what they pasted. Users expect pastes to act like a mini hosting surface: HTML runs as a page, Markdown reads as a formatted document.

## What Changes

- Pastes gain an explicit render type stored as a new `content_type` field: `text` (default), `markdown`, or `html`. Existing pastes have no such field and MUST keep rendering as today (backward compatible, no migration).
- The paste view page renders by type:
  - `markdown` → server-rendered GitHub-flavored Markdown (headings, lists, tables, task lists, code fences, blockquotes) styled with the CryptIRC theme. Embedded raw HTML in the Markdown is never executed (escaped/sanitized).
  - `html` → the single-file app runs in a sandboxed iframe with an opaque origin and its own page-sized viewport, plus a toolbar with an App/Source toggle and a raw link. External resources (CDN scripts, API calls, remote images) are permitted inside the sandbox; scripts run. The sandbox MUST NOT grant same-origin access to CryptIRC.
  - `text` → unchanged escaped `<pre>` view with the existing language label.
- The raw endpoint keeps returning source bytes as `text/plain; charset=utf-8` for every type, so an HTML paste is never executed at the raw URL with CryptIRC origin privileges. Rendering happens only through a dedicated sandboxed app route used by the paste page (and its "open app" affordance).
- The smart-paste dialog becomes type-aware: content pasted into the chat input box is classified as HTML, Markdown, or plain multi-line text, and the dialog offers the matching action (e.g. "Create HTML app paste" / "Create Markdown paste" / "Paste as text"), defaulting to paste creation for HTML and Markdown.
- The manual 📋 Paste modal, which already lists HTML and Markdown languages, now creates the corresponding `content_type` with a short hint that HTML pastes render as a page.
- Password-protected pastes render exactly like public ones after unlock; the unlock flow and status behavior are unchanged.
- Security posture is preserved: rendered apps cannot read CryptIRC cookies, tokens, localStorage, or the parent document; the paste view page keeps its framing protections; the global `X-Frame-Options`/CSP policy is only carved out narrowly for the sandbox frame endpoint and the same-origin `frame-src` allowance it needs.

## Capabilities

### New Capabilities

- `paste`: Creation, storage, and type-aware rendering of CryptIRC pastes (`text` / `markdown` / `html`), source-faithful raw serving, the sandboxed HTML app view, and chat-input smart-paste detection that routes HTML/Markdown to pastes.

### Modified Capabilities

None — `openspec/specs/` is empty; no existing capability requirements change.

## Impact

- `src/paste.rs`: `Paste` and `CreatePasteRequest` gain `content_type` (serde-defaulted to `text`), with validation of allowed values.
- `src/main.rs`: `render_paste` branches by content type; a new sandboxed app route serves HTML pastes to the paste-page iframe and to "open app" links; `route_paste_raw` stays source-faithful (`text/plain`); `security_headers_mw` needs a narrow path-scoped exception so the app route can be framed by the same-origin paste page; global CSP must allow same-origin framing (`frame-src 'self'`).
- Markdown rendering requires a new Rust dependency (e.g. `pulldown-cmark` plus a sanitizer such as `ammonia`) or an equivalent reviewed approach; no client-side bundle dependency is planned.
- `static/app.js` and `static/index.html`: type-aware smart-paste dialog and helper functions, paste modal hint/behavior, paste view styles.
- No breaking API changes: `language` is retained, new field is additive and optional, and legacy pastes default to `text`.
