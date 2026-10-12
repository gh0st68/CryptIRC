# Tasks: HTML / JS App & Markdown Paste Support

## 1. Paste type model and creation API

- [x] 1.1 Add `PasteKind { Text, Markdown, Html }` (lowercase serialization) and `content_type` with `#[serde(default)]` to `Paste` in `src/paste.rs`; default omitted/unknown handling to `text` and reject unknown request values with a client error. Verify with `cargo test` unit tests: legacy JSON without the field parses as text, and each allowed value round-trips.
- [x] 1.2 Thread `content_type` through `create()` and `route_paste_create` (`src/main.rs`) so the created paste and the JSON response reflect the requested type. Verify with `cargo test` for the request validation plus a live `curl -X POST /cryptirc/paste` creating a `markdown` paste and an invalid-type request returning 400.
- [x] 1.3 Confirm limits are type-independent: oversized `html`/`markdown` content is rejected with the existing 500 KB error and rate limits are unchanged. Verify with `cargo test` (boundary at 500 KB) and a curl oversized request.

## 2. Markdown rendering

- [x] 2.1 Add `pulldown-cmark` (html feature) and `ammonia` to `Cargo.toml`; run `cargo build` and confirm `Cargo.lock` updates and the build succeeds without new system dependencies.
- [x] 2.2 Implement `src/paste_render.rs` with `render_markdown(src) -> String` using the GFM options from design D2 and ammonia sanitization with `link_rel("noopener noreferrer")`. Verify with unit tests: headings/lists/tables/task lists/fenced code render as HTML; `<script>`, `onerror=`, `javascript:` URLs, and `data:text/html` payloads are neutralized.
- [x] 2.3 Render `markdown` pastes in `render_paste` inside a themed article container and add the view CSS. Verify by viewing a markdown paste in a browser: formatted output, no literal markers, code fences preserved, and hostile markup inert.
- [x] 2.4 Verify password-protected markdown parity: unlock a protected markdown paste and confirm the rendered result matches a public one. Observable check in the browser; no content or type is revealed before unlock.

## 3. Sandboxed HTML app view

- [x] 3.1 Add the `GET|POST /paste/:id/app` route (`src/main.rs`): serve only `html` pastes (404 otherwise) as `text/html; charset=utf-8` with GET password refusal and POST password verification reusing the existing rate-limited unlock path; include the app response headers and private marker from design D3/D4. Verify with `curl`: content type and policy headers on a public html paste, 403/refusal for a protected paste without POST, 404 for text/markdown ids.
- [x] 3.2 Add the marker-header carve-out to `security_headers_mw` and `'self'` to the global `frame-src` CSP. Verify with `curl -I`: the app route returns `frame-ancestors 'self'`/`SAMEORIGIN` and no leaked marker header, while a representative non-app route (e.g. `/paste/<id>` and `/cryptirc/`) still returns `X-Frame-Options: DENY` and `frame-ancestors 'none'`.
- [x] 3.3 Build the HTML paste view in `render_paste`: sandboxed iframe (no `allow-same-origin`), App/Source toggle, "Open app" for unprotected pastes, raw link, and base-path-correct URLs; for protected pastes emit the hidden auto-submit POST form. Verify in a browser: the app runs, the toggle shows escaped source, and a protected paste runs after unlock.
- [x] 3.4 Verify isolation end to end: a rendered app attempting `document.cookie`, `localStorage`, and parent-document access fails or is empty; top-level navigation is blocked; an external CDN script and an external fetch succeed. Observable browser check with a purpose-built test paste.
- [x] 3.5 Verify `text` pastes containing a complete HTML document still render escaped with no execution (spec: Text paste rendering stays source-only) and that `raw` returns exact source as `text/plain` for every type. Observable check plus a curl diff of raw bytes.

## 4. Frontend paste-creation flows

- [x] 4.1 Implement client-side classification per design D7 and update the smart-paste dialog (`static/index.html`, `static/app.js`) with a type-aware primary action and the always-available "Paste as text". Verify in a browser: complete-HTML paste offers HTML, strong-marker multiline Markdown offers Markdown, plain multiline keeps the text paste action, and one/two-line chat is untouched.
- [x] 4.2 Update `smartPasteYes` to create the classified `content_type`, insert the resulting URL into the input, and preserve the original content on failure. Verify in a browser: choosing the primary action creates the right type (check the view) and a forced failure leaves the text intact.
- [x] 4.3 Map the manual Paste modal's HTML/Markdown options to `content_type` and add the one-line hint; confirm other languages still create `text` pastes. Verify in a browser: modal-created HTML and Markdown pastes render accordingly and JavaScript/Plain Text pastes do not.

## 5. Verification and wrap-up

- [x] 5.1 Run `cargo test` and `cargo build --release`; confirm all new unit tests pass and existing tests remain green.
- [x] 5.2 Walk the spec scenarios from `specs/paste/spec.md` end to end against a locally running server (legacy paste, type defaults, markdown sanitization, app isolation, protected parity, raw content type, smart-paste flows); note any deviation back into the change before implementation is called done.
- [x] 5.3 Add a short in-app changelog entry describing paste rendering (following the existing changelog pattern in `static/app.js`) and verify it renders in the changelog UI.
