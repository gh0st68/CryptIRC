# Design: HTML / JS App & Markdown Paste Support

## Context

See `proposal.md` for motivation and `specs/paste/spec.md` for the behavior contract.

Current state that shapes the approach:

- Single Rust/axum binary with a vanilla-JS frontend. `static/index.html`, `static/app.js`, and `static/sw.js` are embedded at compile time (`include_str!` in `src/main.rs:919-924`) and served with `no-store`; the service worker fetches the HTML page and app scripts network-first.
- Paste storage is one JSON file per paste (`src/paste.rs`): full-UUID id, `content`, `language`, `created_at`, `expires_at` (also encoded in the filename), Argon2id `password_hash`, `author`. 500 KB cap, per-user create limiter, per-IP `paste_view` limiter. Routes: `POST /paste`, `GET|POST /paste/:id`, `GET /paste/:id/raw` (`src/main.rs:1121-1123`).
- `render_paste` (`src/main.rs:2373`) always escapes content into a `<pre>`; unlock is a same-URL POST form; `raw` serves `text/plain`.
- `security_headers_mw` (`src/main.rs:765`) applies, to every response: `X-Frame-Options: DENY`, `frame-ancestors 'none'`, and a CSP whose `frame-src` allows only YouTube. The middleware overwrites (not appends to) these headers.
- Smart-paste (`static/app.js:3678`) offers the dialog in `static/index.html:3699` for ≥5-line text pastes into the message input and creates `language:"text"` pastes (`smartPasteYes`, `static/app.js:10361`). The manual Paste modal (`static/app.js:4884`) already lists HTML and Markdown, but they render as escaped text.
- Base path is configurable (`CRYPTIRC_BASE_PATH`, default `/cryptirc`); the existing paste-view links hardcode `/cryptirc`, which new code should not copy.

## Goals / Non-Goals

**Goals:**

- Type-aware paste rendering: `text` unchanged, `markdown` formatted and sanitized, `html` executed as a sandboxed page.
- Type-aware creation from the chat input and the manual Paste modal, with safe defaults for legacy pastes and third-party API clients.
- Preserve the existing security posture exactly, except for one narrowly scoped, same-origin-only frame carve-out for the app route.

**Non-Goals:**

- Editing pastes; syntax highlighting for text pastes; inline chat previews of paste content (the chat keeps showing a plain URL); multi-file apps or hosting; an app↔host postMessage API; per-type size limits; changes to password hashing, expiry, or rate-limit budgets; storage migration.

## Decisions

### D1: Explicit `content_type` on the paste record

Add `PasteKind { Text, Markdown, Html }` (serialized lowercase) in `src/paste.rs`. `Paste.content_type` carries `#[serde(default)]` so legacy files parse as `text`. `CreatePasteRequest.content_type` is optional; omitted means `text`, unknown values are rejected with 400.

Why not infer the render type from `language`: third-party API clients already send `language:"html"`/`"markdown"` for code display. Silently turning those into executable rendering would be a security-relevant behavior change; rendering is explicit opt-in. `language` stays display metadata.

### D2: Server-side Markdown rendering with `pulldown-cmark` + `ammonia`

New module `src/paste_render.rs` (web binary) exposing `render_markdown(src) -> String`, with GFM options enabled (tables, task lists, strikethrough, footnotes, ENABLE_GFM) and output sanitized by `ammonia` (default tag/attribute allowlist, `link_rel(Some("noopener noreferrer"))`, http/https/mailto URL schemes only). Ammonia's default allowlist drops `<input>`, which is how pulldown-cmark renders task-list checkboxes; the builder explicitly re-allows `input` with only `type`/`checked`/`disabled` so task lists render as disabled, inert checkboxes (forms are stripped, so an input cannot submit anywhere).

Why server-side: the paste view is already server-rendered; the result is identical for public and password-unlocked pastes; no third-party JS bundle or client renderer is added; `ammonia` is the sanitizer crates.io itself uses for untrusted README rendering. Rendering runs inline in the handler — input is capped at 500 KB, the parser is linear, and the per-IP `paste_view` limiter already bounds abuse, unlike the multi-second Argon2 path that needs `spawn_blocking`.

Alternatives rejected: vendored marked.js + DOMPurify (client bundle, wider CSP surface, breaks without JS); `pulldown-cmark` output inserted unsanitized (raw HTML passthrough would be stored XSS on the CryptIRC origin); pre-escaping the source (breaks code fences and legitimate inline HTML, and is easy to get wrong).

### D3: HTML pastes run on a dedicated `/paste/:id/app` route framed by the paste page

The paste view embeds `<iframe sandbox="allow-scripts allow-forms allow-modals allow-popups allow-downloads allow-pointer-lock">` (never `allow-same-origin`, never top-navigation) pointing at a new `GET|POST /paste/:id/app` route. That route returns `text/html; charset=utf-8` with its own policy: CSP `sandbox allow-scripts allow-forms allow-modals allow-popups allow-downloads allow-pointer-lock`, permissive resource directives (`script-src`/`style-src`/`img-src`/`media-src`/`font-src`/`connect-src`/`worker-src` with `*`, `data:`, `blob:`, `'unsafe-inline'`, `'unsafe-eval'`), `base-uri 'none'`, `frame-ancestors 'self'`, and `X-Frame-Options: SAMEORIGIN` for legacy agents.

The opaque origin produced by the sandbox is what isolates the app: it cannot read CryptIRC cookies, session credentials, `localStorage`, or the parent document. CSP `sandbox` and the iframe `sandbox` attribute are layered so a processing gap in one layer does not silently restore origin access.

Alternatives rejected:

- `srcdoc`: a srcdoc frame inherits the paste page's CSP — `connect-src` is an allowlist and `script-src 'self'` cannot load CDN scripts — which directly breaks the "external resources allowed" requirement.
- Serving `raw` as `text/html`: opening the raw URL in a tab would execute untrusted code with CryptIRC origin privileges (stored XSS). `raw` stays source-faithful `text/plain` for every type.

### D4: Header carve-out keyed by a private response marker

`security_headers_mw` currently overwrites framing headers for all responses. The app route sets a private marker header (e.g. `x-cryptirc-app-frame`) on its response; the middleware detects the marker, removes it, and emits the app-route header set instead of the global set. Every other response keeps today's exact headers. The global CSP gains `'self'` in `frame-src` so the paste page may frame the app route; because every non-app route still sends `frame-ancestors 'none'` and `XFO: DENY`, that allowance cannot expose them to framing.

Alternatives rejected: matching the request path inside the middleware (fragile coupling to route shape); moving the route outside the middleware (invasive to the base-path nesting and easy to regress).

### D5: Password-protected HTML pastes use a hidden auto-submit POST form

After a successful unlock, `render_paste` emits (for protected html pastes) a hidden form with `method="post"`, `target` set to the iframe's `name`, and the verified password in a hidden input, submitted on load. The app route verifies the password through the same rate-limited path as the unlock POST before serving content.

Why: no secret ever enters a URL (audit #F24), the existing verification path and its Argon2 rate limiting are reused, and no render-token machinery is introduced. The inline "Open app" affordance is only offered for unprotected pastes, since a bare GET of the app route for a protected paste is refused.

Alternatives rejected: one-time render token in the query (new capability surface, appears in logs/history); srcdoc fallback for protected pastes (inconsistent resource behavior vs. public pastes).

### D6: View composition

- HTML view: toolbar with an App/Source toggle, "Open app" (public pastes only), raw link, and the existing meta line; the App pane is the sandboxed iframe, the Source pane is the server-escaped `<pre>`. A small inline script/CSS block on the paste page implements the toggle.
- Markdown view: sanitized HTML inside a themed article container (styles added to the paste page's embedded CSS).
- Text view: byte-for-byte the current output.
- New URLs (`/paste/:id/app`, toolbar links) are built from `state.base_path`; the legacy hardcoded `/cryptirc` links in the existing view may be fixed opportunistically but are not required by this change.

### D7: Smart-paste classification and dialog

Classification runs on paste into the message input before the existing length gate:

1. Complete HTML document → offer an HTML app paste. Detection: leading `<!doctype html>` or `<html` (case-insensitive, ignoring leading whitespace/BOM), or a `<script` plus a closing `</html>`/`</body>`/`</div>`/`</section>`/`</main>` tag.
2. Otherwise, ≥5 lines with at least one strong Markdown marker (ATX heading, fenced code, blockquote, table delimiter row, ordered/unordered list, link) → offer a Markdown paste.
3. Otherwise the existing behaviour (≥5 lines → text paste dialog; shorter input is untouched).

The dialog's primary button creates the classified type; "Paste as text" is always available and inserts the exact source. A failed creation keeps the content in the input (existing fallback). The manual modal maps its existing HTML/Markdown options to `content_type` and shows a one-line hint; all other options create text pastes.

Why strong markers: detection intercepts ordinary typing on paste, so false positives (log excerpts with `#` or `-` lines) are kept low and always escapable via "Paste as text".

### D8: Dependencies

Add `pulldown-cmark` (with the `html` feature) and `ammonia` to `Cargo.toml`; both are pure Rust and compatible with the current toolchain (rustc 1.98), and `Cargo.lock` is updated. No frontend dependency is added.

## Risks / Trade-offs

- Sanitizer bypass → stored XSS on the CryptIRC origin: mitigate with ammonia's default allowlist plus unit tests carrying hostile payloads (script/event-handler attributes, `javascript:` URLs, SVG/MathML vectors, data: URLs), and keep the dependency current.
- App-route header carve-out regressing the global policy: the carve-out only affects responses carrying the private marker; tests assert the marker is stripped and that representative non-app routes still send `DENY`/`frame-ancestors 'none'`.
- `frame-src 'self'` broadens same-origin framing globally: only the app route permits same-origin ancestors; all other routes keep `frame-ancestors 'none'`.
- Opaque-origin apps cannot use `localStorage`/cookies inside the frame (access throws/returns empty): inherent to isolation; apps relying on persistence degrade. Documented as the cost of never exposing the CryptIRC origin; surface the limitation in the view hint.
- Allowing external resources means viewing an app contacts third parties and an app can render deceptive UI on the CryptIRC domain: accepted feature trade-off; the global `no-referrer` policy limits referrer leakage, and the app stays inside its sandbox with no host access.
- Markdown rendering cost per view: bounded by the 500 KB cap and the per-IP limiter; linear-time parser, no blocking.
- Detection false positives interrupting chat: dismissible dialog, exact-content "Paste as text", strong-marker requirement.
- Rollback: a previous server binary ignores unknown `content_type` fields (no `deny_unknown_fields` anywhere) and renders every paste as text — safe, no data loss.
- HTML view doubles transfer (escaped source plus the iframe fetch): bounded by 500 KB.

## Migration Plan

- Storage: additive field with a serde default; no migration, no filename changes; legacy pastes and legacy API clients render as text.
- Deploy: rebuild the binary (static assets are embedded at compile time) — no new env vars; the CSP change is backward compatible. The service worker already fetches HTML and app scripts network-first, so clients pick up the new UI on reload; bumping `CACHE` in `static/sw.js` is optional.
- Rollback: restore the previous binary; `content_type` is ignored and all pastes render as escaped text.
