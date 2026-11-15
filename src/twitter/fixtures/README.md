# Offline X fixtures

All posts, identities, text, media paths and guest credentials in these tests are synthetic. Do not download their CDN paths.

`normalized/` contains the eight complete version 1 examples copied from the planning contract. They live here so archiving OpenSpec artifacts cannot break compilation or tests. `raw/` covers the supported GraphQL result, visibility, note, quote, media and unavailable shapes; Rust tests mutate these shapes for optional-field and boundary cases. The wrapped Unicode note fixture supplies repeated mentions, combining text, RTL and literal HTML-looking content. These shapes establish tested adapter behavior, not live upstream availability.

Rust and browser validators share `scripts/fixtures/x-urls.json`. The browser also tests conservative punctuation removal during message extraction without changing the original anchors. Native browser tests use the tiny generated `scripts/fixtures/x-preview.mp4` and local image bytes; normal tests never contact X or ThreadReaderApp.

`raw/fxtwitter.json` is a synthetic FixTweet `/status/<id>` response shaped after that provider's public documentation (port addition); it includes a non-CDN photo, a hostile video variant and a two-level quote to exercise validation and the one-level quote limit. `raw/basic.json` uses a realistic `/profile_images/` avatar path so the signed media fallback tests can bind to a retrieved asset.
