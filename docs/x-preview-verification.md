# X preview verification

Port of the community "rich X previews" reference (patch against b8e1ede) onto v0.5.8 (76dd905), branch `x/previews`. All providers stay off unless their startup flag is set (INSTALL.md, "X post previews"). Every run below was offline: tests ran in a user + network + mount namespace with only loopback, the systemd-resolved socket and `resolv.conf` masked, so neither a connection nor a DNS lookup could leave the box.

## Results (Arch Linux, Rust 1.99.1, 2026-11-14)

| Suite | Port (x/previews) | Base 76dd905 |
|---|---|---|
| `cargo build --locked` (web binary) | 0 warnings | — |
| `cargo test --locked` — library | 68 passed | 68 passed |
| `cargo test --locked` — web binary | 334 passed, 1 failed (pre-existing timing test, below) | 293 passed, 1 failed (same test) |
| `node scripts/test-x-previews.js` | passed (all sections) | — |
| `node scripts/test-x-previews-browser.mjs` (Chromium 157) | 98/98 checks; 0 requests to X/ThreadReader hosts; 0 generic `/preview` requests for X links; video Referer 0; five 20-card batches 3.5–4.4 ms | — |
| `node scripts/test-x-previews-firefox.mjs` (Firefox 160) | 7/7, decoded the fixture MP4 natively | — |
| `node scripts/test-layout.mjs` | 53/53 | 53/53 |
| `node scripts/test-interactions.mjs` | 53/53 | 53/53 |
| `scripts/test-x-previews-parity.mjs` (vs. the 76dd905 frontend) | 15/15 (all ten rows, X rows included) | — |
| `scripts/test-x-previews-server.mjs` under `strace -f -e trace=connect` | 39/39 at `/cryptirc`, `/chat/nested`, `/`; the server's only `connect()` calls were to its own irc-core unix socket (no IPv4/IPv6, no resolver) | — |

`auth::r3_srv_a_auth_tests::a_stuck_script_makes_writes_busy_not_hung` is timing-sensitive: it fails in a full parallel run on BOTH trees and passes in isolation (3/3 on each). It is pre-existing and unrelated to this port (it holds an admin-script lock for 8 s and races Argon2 work against it).

The 1,000-message / 100-ID run observed at most 3 active operations and stayed within the 50-queue / 200-entry / 8 MiB caps; every automatic disclosure had a permitted card within the 300 px viewport margin, and fewer than 100 IDs were fetched.

## What each suite covers

- **Rust** (`cargo test --locked`): URL table shared with the browser; raw provider shapes (result, visibility wrappers, note, media, quote, restricted) and the eight normalized v1 fixtures; counts, entities, media limits; guest token coalescing, expiry retry, Retry-After / drift / 5xx backoff, paused-clock absolute deadlines; ThreadReaderApp tokenizer limits and hostile HTML; FixTweet mapping and error evidence; per-viewer cache single-flight, bounds, TTLs, refresh cooldown, policy generations, waiter caps, disconnect cleanup, unconfigured providers answered locally; routes at `""`, `/cryptirc` and a nested prefix (auth before cache, shared budget, private/no-store + Vary, malformed queries, saturation); signed media fallback (signature binding to URL + account, recognized paths, MIME allowlist, range syntax, admin policy before sign and redeem, "retrieved by this viewer", a non-reading client released at the deadline and after the idle bound, per-account stream cap with another account unaffected). Test route state uses a media upstream that panics if reached, and stream tests use a local endless source.
- **Node** (`scripts/test-x-previews.js`): validators against the shared URL table, count precision, video variant choice, signed-media client cache, scheduler (coalescing, permission before cache, cancellation, 3 active / 50 queued / 200 entries / 8 MiB, account isolation), disclosure policy (including the upgrade rules: a stored Manual stays Manual, only a missing policy gets auto_public, damaged storage fails closed to Manual), capability gating, row-context evidence (E2E conversations, history rows, unknown contexts), the v0.5.8 `buildMediaEl(url, encrypted)` contract, appearance storage within the 4 KiB sync budget, and the service worker passing every `/tweet` route straight to the network at three base paths.
- **Chromium** (`scripts/test-x-previews-browser.mjs`): the real v0.5.8 frontend with mocked same-origin APIs and intercepted CDN bytes; zero metadata/assets for default encrypted, DM and unknown contexts (also with a warm cache), mixed media order, batches of three, keyboard and ARIA, galleries (1-4 photos, index, arrows, Escape, focus restore, source release), legacy single-image viewer, 320/390/768/1440 px in a dark and a real light theme, native MP4 only after Play with no Referer, collapse pauses, late errors can't restart a collapsed video, teardown releases sources, signed fallback for card video and lightbox image, every normalized fixture rendered inert, supplied quotes without another request, consented thread with local 5/10/20 batches, history anchor within 2 px (metadata, mode, Space, media), global Link previews off, auto-public vs encrypted, conversation opt-in, revocation purge, account isolation, auto-load expanded, 20-card batch timing, 1,000 rows / 100 IDs disclosing only near the viewport within queue/cache limits, ten aliases → one request, gallery geometry, long RTL names at 200% text, missing IntersectionObserver → manual, small failure states, 100 conversation switches, late completion after a channel change, no IRC payloads, no request to any X/ThreadReader host.
- **Firefox** (`scripts/test-x-previews-firefox.mjs`): native fixture MP4 decode, controls/inline playback, pause on collapse, source release, zero requests before permission.
- **Parity** (`scripts/test-x-previews-parity.mjs`): the same messages rendered by the 76dd905 frontend and this one on an unconfigured server; EVERY row — X links included — is byte-identical (random preview ids and the invisible X slot markers normalized), so X links keep v0.5.8's generic preview and encrypted click-to-load; the generic `/preview` and third-party request sets are identical, no X card appears, and only `GET /tweet/config` touches `/tweet`. (On a configured server the Chromium suite asserts X links never reach `/preview`.)
- **Server smoke** (`scripts/test-x-previews-server.mjs`): the real web binary with no X flags and admin policy "all", at `/cryptirc`, `/chat/nested` and `/`: base-path rewriting in `app.js` and `sw.js`, auth + private/no-store on every route, `provider_disabled` answers, refused signing and forged media URLs — run under `strace -f -e trace=connect`.
- **Layout / interactions** (`scripts/test-layout.mjs`, `scripts/test-interactions.mjs`): the existing v0.5.8 regression suites, run on this branch and on 76dd905.

## Audit round 1 (Codex astra-high on 97c4210): fixes and red/green proof

Each fix has a test that fails with the fix's core logic reverted in a scratch copy on the build box (`make_red2.py` variants) and passes on the branch:

| Finding | Fix | Test (red → green) |
|---|---|---|
| HIGH thread tokenizer quadratic in attributes, blocking runtime workers | cooperative hard limit: each fragment is fed to html5ever in 1 KiB chunks with the 2 s document deadline checked between chunks and on every token in the sink, so at most one chunk's work runs past it; the parse runs on the blocking pool, at most 2 at once (slot held by the blocking task until it returns; otherwise busy); a deadline hit returns Timeout and negatively caches that post ID for 15 min (≤256 IDs); only timeouts on 3 distinct IDs within 5 min put ThreadReader on a 60 s provider cooldown (429/Retry-After and repeated 5xx keep their provider-wide cooldowns) | `thread_parse_hostile_documents_stop_at_the_deadline` (40k and the audit's ~180k unique attributes, 1e6 attributes, deep comments, bogus markup — each within budget + slack), `thread_parse_timeout_frees_its_slot_and_blocks_only_that_id`, `thread_timeouts_on_distinct_ids_trip_the_provider_cooldown`, `thread_parses_are_bounded` |
| (self-review, security review) a provider-wide cooldown on ONE parse timeout let a single crafted thread switch the viewer off for everyone | per-ID negative cache; provider-wide only after distinct IDs | red: provider cooldown on the first timeout (good ID blocked) / per-ID only (never trips) |
| (self-review, security review ×2) a byte pre-scan can be desynchronised from the tokenizer (bare `=`, comments, `<!`/`<?`, `</`+non-alpha, quotes), and an outer timeout around `spawn_blocking` does not stop the blocking work | pre-scan removed; the cooperative limit above is the only mechanism | same tests; red against the previous design (single feed, outer timeout, no slot, no cooldown) |
| MED signed media cacheable | `Cache-Control: private, no-store` | `media_stream_non_reading_client_releases_permit_at_deadline` |
| MED media DNS outside every timeout | one deadline around DNS + connect + headers (504), slots released | `media_fetch_stall_is_bounded_and_releases_slots` |
| MED success erases concurrent cooldowns | success only clears the 5xx streak; cooldowns only extend | `provider_cooldown_survives_concurrent_success_and_shorter_errors` |
| MED invalid guest config falls back to FixTweet | invalid guest config ⇒ post previews off | `invalid_guest_config_never_falls_back_to_fixtweet` |
| LOW thread dedup without identity | no content-based dedup (server and browser) | `thread_repeated_content_is_not_merged`, node `normalizedThreadEntries` |
| MED fallback continues after External media revoked | permission re-checked after every async fallback step | Chromium "revoking External media stops a pending fallback" |
| MED unconfigured server drops X links' generic previews | no provider offered ⇒ exact v0.5.8 generic path (slot markers keep order) | parity (all rows), node `testCapabilitiesAndContext` |
| LOW late signing repopulates cleared cache | generation/account guard; teardown cancels queued signing | node `testMediaProxy` |
| LOW split-pane auto cards stuck loading | click-to-load fallback outside the main pane | Chromium "split-pane auto previews fall back to click-to-load" |
| LOW concurrent fallbacks waste the budget | per-asset coalescing + 25 ms batches (≤16) | node `testMediaProxy` (40 callers → 1 request; distinct assets → 1 batch) |

## Audit re-check (Codex on c4f7cbf): fixes and red/green proof

Server lane GO with three LOW findings, browser lane NO-GO; all seven fixed:

| Finding | Fix | Test (red → green) |
|---|---|---|
| LOW html5ever trace logs carry thread content | service log filter always adds `html5ever=off,markup5ever=off` to `RUST_LOG` | `log_filter_silences_tokenizer_content` |
| LOW ThreadReader 5xx bypassed the provider backoff | same 30/60/120… s (≤5 min) provider-wide 5xx backoff as the post providers; a success ends the streak | `thread_provider_5xx_backoff` |
| LOW GraphQL config location unreadable by the service | INSTALL.md: own `/etc/cryptirc-x` directory, `0750 root:cryptirc`, file `0640`, with a readability check | doc fix (needs another Unix user to execute; not run) |
| MED a failed `/tweet/config` probe bypassed the X disclosure choices | a failed probe is "unknown, retry with backoff", not "no provider": X links take the generic path but never less private than the X choice (Hide: nothing; click-to-load contexts: click-to-load generic preview; encrypted: v0.5.8 gate) | node `testProbeFailureLockAndSigningBounds` (1) |
| MED a delayed probe could rebuild previews after a vault lock | probe answers are dropped after any teardown (generation check); nothing X-related is built or fetched while the vault or device is locked; unlock rebuilds | node (2) and (3) |
| LOW signing: no concurrency bound, timeout or cancellation | ≤2 batches in flight, 10 s abort, teardown aborts in-flight batches | node (4) |
| LOW closing split view left X playback / pending work running | closing the split pane disposes its X cards | Chromium "closing split view tears down its X cards" |

## Audit re-check 2 (Codex on 05f71c0): fixes and red/green proof

Server lane GO with one LOW, browser lane NO-GO; all four fixed:

| Finding | Fix | Test (red → green) |
|---|---|---|
| MED failed-probe fallback let a crafted encrypted X link (`…/status/123?attachment=.jpg`) auto-load as an image | a recognized X status URL never takes the direct-media branches in any mode — only the generic link-preview path (encrypted / click-to-load gates and the X choice first) | Chromium "crafted media-looking X URL in an encrypted DM never loads directly"; node `testCapabilitiesAndContext`, `testProbeFailureLockAndSigningBounds` (1) |
| MED a clicked fallback card escaped revocation and teardown | generic X nodes (and a click's replacement) are registered in their slot and in `clearTweetData` / `disposeTweetPreviews`; their async render and image load re-check permission, lock and generation | Chromium "clicked fallback card is removed by revocation before it renders" |
| LOW signing work had no owner | each signing item carries its requesting cards' liveness checks; ownerless items are dropped before a batch, a batch whose items all lost their owners is aborted (run on card disposal, lightbox close and before each batch) | node (5) |
| LOW `html5ever=off` lost to a more specific user directive (`html5ever::tokenizer=trace`) | every RUST_LOG directive targeting html5ever / markup5ever is dropped before the filter is built, then the off directives are added; default still ERROR | `log_filter_silences_tokenizer_content` (now also `html5ever::tokenizer=trace`, `markup5ever=trace`, span-scoped forms) |

Re-check 3 (on c0c9b97, GO on both lanes) left one LOW: generic X previews that failed or had no title were removed without leaving the node registry (no removal observer on a default install). Every removal path now unregisters, and pane disposal prunes detached registered nodes — Chromium "100 failed generic X previews leave nothing registered" (red: 100 left registered).

## Not verified here

- No live X (guest GraphQL), FixTweet or ThreadReaderApp request was made; their live response shapes and availability are unverified. The bundled GraphQL operation snapshot may already be stale.
- Safari/iOS and the Electron wrapper were not run (Linux only). Firefox covers native playback only, not the full layout/touch matrix.
- Real Caddy/nginx access-log redaction was not exercised; INSTALL.md documents the configuration.

The procedures below cover the platform checks without claiming they were run.

**M1 — Gallery and keyboard compatibility.** Use synthetic normalized fixtures and local network-response overrides for their CDN bytes, with all other remote traffic blocked. At 320 px, landscape, and 200% text size in light/dark/custom themes: load manually, expand, Tab through controls, activate with Enter/Space, verify focus and `aria-expanded`, open the third photo, use Previous/Next/arrows/Escape/mobile Back, and verify opener focus and source release. At zoom one, swipe horizontally; after pinch/double-click zoom, pan without changing images. Repeat the original one-argument viewer call with an ordinary uploaded image. Check names, metrics and unknown authors with the platform screen reader and reduced motion enabled.

**M2 — Native media compatibility.** Use `scripts/fixtures/x-preview.mp4` as the network override for synthetic MP4 URLs. On Safari/iOS/Electron, verify no video/source before Play, native seek/mute/fullscreen and inline playback after activation, and muted looping GIF playback with pause. Test missing MP4 plus native HLS using a locally controlled HLS response on the allowlisted CDN override; unsupported native HLS must keep Open on X. Force one playback error, verify at most one alternate, then a small fallback. Collapse or remove before a delayed error and verify playback does not restart.

**M3 — Failure and diagnostic inspection.** Stub expired/broken assets, HTTP 403/404/429/5xx, malformed JSON and unsupported schema versions, using only synthetic IDs. Verify valid siblings and original links survive, Retry/Refresh respect cooldown, and a failed thread preserves the root. Inspect application logs for coarse categories only, inspect same-origin requests for `url`/`refresh` parameters only, verify no application Authorization header on assets, and verify preview actions send no IRC payload. Check proxy query redaction before any permitted live smoke.

**M4 — Optional provider deployment.** With all flags unset, verify X links stay plain links and `GET <base>/tweet/config` reports nothing offered. Only with permitted access, enable one provider, restart the web service, perform one authorized public-post request, inspect schema/status without logging credentials or bodies, then disable and restart to roll back.
