//! Avatar tests: image processing (formats, metadata stripping, orientation, limits,
//! malformed input), storage, route authorization at three base paths, and discovery.

use super::*;
use image::{Rgb, RgbImage, Rgba, RgbaImage};
use std::path::Path;

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in bytes {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
        }
    }
    !c
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut body = kind.to_vec();
    body.extend_from_slice(data);
    let mut out = (data.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&body);
    out.extend_from_slice(&crc32(&body).to_be_bytes());
    out
}

/// Chunk types of a PNG, in order.
fn png_chunks(png: &[u8]) -> Vec<String> {
    assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));
    let mut out = Vec::new();
    let mut i = 8;
    while i + 8 <= png.len() {
        let len = u32::from_be_bytes(png[i..i + 4].try_into().unwrap()) as usize;
        out.push(String::from_utf8_lossy(&png[i + 4..i + 8]).to_string());
        i += 12 + len;
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn encode(img: &DynamicImage, fmt: ImageFormat) -> Vec<u8> {
    let mut c = Cursor::new(Vec::new());
    img.write_to(&mut c, fmt).unwrap();
    c.into_inner()
}

fn jpeg_segment(marker: u8, payload: &[u8]) -> Vec<u8> {
    let len = (payload.len() + 2) as u16;
    let mut out = vec![0xFF, marker];
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A little-endian TIFF block (an EXIF payload) with one Orientation entry.
fn tiff_orientation(o: u16) -> Vec<u8> {
    let mut t = b"II*\0".to_vec();
    t.extend_from_slice(&8u32.to_le_bytes());
    t.extend_from_slice(&1u16.to_le_bytes());
    t.extend_from_slice(&0x0112u16.to_le_bytes());
    t.extend_from_slice(&3u16.to_le_bytes());
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(&o.to_le_bytes());
    t.extend_from_slice(&0u16.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t
}

/// `jpg` with an APP1 Exif segment (and optional extra segments) right after SOI.
fn jpeg_with(jpg: &[u8], segments: &[Vec<u8>]) -> Vec<u8> {
    let mut out = jpg[..2].to_vec();
    for s in segments {
        out.extend_from_slice(s);
    }
    out.extend_from_slice(&jpg[2..]);
    out
}

fn patch_png_ihdr(png: &[u8], w: u32, h: u32, depth: Option<u8>, color: Option<u8>) -> Vec<u8> {
    let mut p = png.to_vec();
    p[16..20].copy_from_slice(&w.to_be_bytes());
    p[20..24].copy_from_slice(&h.to_be_bytes());
    if let Some(d) = depth {
        p[24] = d;
    }
    if let Some(c) = color {
        p[25] = c;
    }
    let crc = crc32(&p[12..29]);
    p[29..33].copy_from_slice(&crc.to_be_bytes());
    p
}

fn decode_png(bytes: &[u8]) -> DynamicImage {
    assert_eq!(sniff_format(bytes), Some(ImageFormat::Png));
    image::load_from_memory_with_format(bytes, ImageFormat::Png).unwrap()
}

fn two_tone(w: u32, h: u32) -> DynamicImage {
    DynamicImage::ImageRgb8(RgbImage::from_fn(w, h, |x, _| if x < w / 2 { Rgb([230, 20, 20]) } else { Rgb([20, 20, 230]) }))
}

fn is_red(p: &Rgb<u8>) -> bool {
    p.0[0] > 150 && p.0[2] < 100
}
fn is_blue(p: &Rgb<u8>) -> bool {
    p.0[2] > 150 && p.0[0] < 100
}

// ─── Processing ───────────────────────────────────────────────────────────────

#[test]
fn png_jpeg_and_webp_become_square_pngs() {
    let img = two_tone(300, 200);
    for fmt in [ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::WebP] {
        let p = process_image(&encode(&img, fmt)).unwrap_or_else(|e| panic!("{fmt:?}: {e:?}"));
        let large = decode_png(&p.large);
        let small = decode_png(&p.small);
        assert_eq!((large.width(), large.height()), (SIZE_LARGE, SIZE_LARGE), "{fmt:?}");
        assert_eq!((small.width(), small.height()), (SIZE_SMALL, SIZE_SMALL), "{fmt:?}");
        assert!(valid_version(&p.version));
        assert_eq!(p.version, content_version(&p.large));
        // Centre crop of 300×200: columns 50..250, so red on the left, blue on the right.
        let l = large.to_rgb8();
        assert!(is_red(l.get_pixel(8, 64)) && is_blue(l.get_pixel(120, 64)), "{fmt:?}");
    }
    // Tiny pictures are scaled up, tall ones cropped to their middle.
    let tall = DynamicImage::ImageRgb8(RgbImage::from_fn(10, 30, |_, y| if y < 10 { Rgb([0, 0, 0]) } else if y < 20 { Rgb([0, 220, 0]) } else { Rgb([0, 0, 0]) }));
    let p = process_image(&encode(&tall, ImageFormat::Png)).unwrap();
    let l = decode_png(&p.large).to_rgb8();
    assert!(l.get_pixel(64, 64).0[1] > 150 && l.get_pixel(5, 5).0[1] > 150, "the middle third fills the square");
}

#[test]
fn transparency_is_kept_and_opaque_pictures_drop_alpha() {
    let rgba = DynamicImage::ImageRgba8(RgbaImage::from_fn(64, 64, |x, _| if x < 32 { Rgba([255, 0, 0, 0]) } else { Rgba([0, 0, 255, 255]) }));
    let p = process_image(&encode(&rgba, ImageFormat::Png)).unwrap();
    assert_eq!(decode_png(&p.large).color(), image::ColorType::Rgba8);
    let opaque = two_tone(64, 64);
    let p = process_image(&encode(&opaque, ImageFormat::Png)).unwrap();
    assert_eq!(decode_png(&p.large).color(), image::ColorType::Rgb8);
}

#[test]
fn metadata_never_survives_processing() {
    let img = DynamicImage::ImageRgb8(RgbImage::from_pixel(64, 64, Rgb([10, 200, 10])));
    let png = encode(&img, ImageFormat::Png);
    let ihdr_end = 8 + 8 + 13 + 4;
    let mut tagged_png = png[..ihdr_end].to_vec();
    tagged_png.extend(png_chunk(b"tEXt", b"Comment\0SECRET-PNG-TEXT"));
    tagged_png.extend(png_chunk(b"eXIf", &[tiff_orientation(1), b"SECRET-PNG-EXIF".to_vec()].concat()));
    tagged_png.extend_from_slice(&png[ihdr_end..]);
    let jpg = encode(&img, ImageFormat::Jpeg);
    let tagged_jpg = jpeg_with(&jpg, &[
        jpeg_segment(0xE1, &[b"Exif\0\0".to_vec(), tiff_orientation(1), b"SECRET-JPEG-EXIF-GPS".to_vec()].concat()),
        jpeg_segment(0xFE, b"SECRET-JPEG-COMMENT"),
        jpeg_segment(0xE2, &[b"ICC_PROFILE\0\x01\x01".to_vec(), b"SECRET-ICC".to_vec()].concat()),
    ]);
    for input in [tagged_png, tagged_jpg] {
        assert!(contains(&input, b"SECRET"));
        let p = process_image(&input).unwrap();
        for out in [&p.large, &p.small] {
            assert!(!contains(out, b"SECRET"), "metadata leaked");
            let chunks = png_chunks(out);
            assert!(chunks.iter().all(|c| ["IHDR", "IDAT", "IEND"].contains(&c.as_str())), "{chunks:?}");
            assert!(!contains(out, &input[8..40]), "no original bytes are reused");
        }
    }
}

#[test]
fn exif_orientation_is_applied_before_cropping() {
    let jpg = encode(&two_tone(128, 64), ImageFormat::Jpeg);
    let with = |o: u16| jpeg_with(&jpg, &[jpeg_segment(0xE1, &[b"Exif\0\0".to_vec(), tiff_orientation(o)].concat())]);
    // 1 = as stored: red left, blue right.
    let l = decode_png(&process_image(&with(1)).unwrap().large).to_rgb8();
    assert!(is_red(l.get_pixel(8, 64)) && is_blue(l.get_pixel(120, 64)));
    // 6 = rotate 90° clockwise to display: the left (red) side ends up on top.
    let l = decode_png(&process_image(&with(6)).unwrap().large).to_rgb8();
    assert!(is_red(l.get_pixel(64, 8)) && is_blue(l.get_pixel(64, 120)));
}

#[test]
fn oversized_and_bomb_dimensions_are_refused_before_decoding() {
    let small = encode(&DynamicImage::ImageRgb8(RgbImage::new(8, 8)), ImageFormat::Png);
    for (w, h) in [(4097, 1), (1, 4097), (5000, 5000), (65_535, 65_535), (100_000, 100_000), (0x7fff_ffff, 1)] {
        let started = Instant::now();
        assert_eq!(process_image(&patch_png_ihdr(&small, w, h, None, None)).err(), Some(AvatarError::Dimensions), "{w}x{h}");
        assert!(started.elapsed() < Duration::from_secs(2), "{w}x{h} took {:?}", started.elapsed());
    }
    // 16-bit RGBA at 4096²: a 128 MiB output buffer, refused without allocating it.
    let rgba16 = patch_png_ihdr(&small, 4096, 4096, Some(16), Some(6));
    assert_eq!(process_image(&rgba16).err(), Some(AvatarError::Dimensions));
    // A JPEG whose frame header claims 65500 × 65500.
    let mut jpg = encode(&DynamicImage::ImageRgb8(RgbImage::new(8, 8)), ImageFormat::Jpeg);
    let sof = jpg.windows(2).position(|w| w == [0xFF, 0xC0]).expect("baseline SOF0");
    jpg[sof + 5..sof + 7].copy_from_slice(&65_500u16.to_be_bytes());
    jpg[sof + 7..sof + 9].copy_from_slice(&65_500u16.to_be_bytes());
    let started = Instant::now();
    let err = process_image(&jpg).err();
    assert!(matches!(err, Some(AvatarError::Dimensions | AvatarError::Malformed)), "{err:?}");
    assert!(started.elapsed() < Duration::from_secs(2));
    // A legitimately large (but allowed) 4096 × 64 strip still works.
    assert!(process_image(&encode(&two_tone(4096, 64), ImageFormat::Png)).is_ok());
}

#[test]
fn malformed_and_unsupported_input_is_refused() {
    assert_eq!(process_image(b"").err(), Some(AvatarError::Empty));
    let mut huge = b"\x89PNG\r\n\x1a\n".to_vec();
    huge.resize(MAX_UPLOAD_BYTES + 1, 0);
    assert_eq!(process_image(&huge).err(), Some(AvatarError::TooLarge));
    for bad in [
        b"GIF89a\x01\x00\x01\x00\x00\x00\x00;".to_vec(),
        b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>".to_vec(),
        b"<!doctype html><img src=x onerror=alert(1)>".to_vec(),
        b"BM\x3e\x00\x00\x00".to_vec(),
        b"\x00\x00\x00\x0cjP  \r\n\x87\n".to_vec(),
    ] {
        assert_eq!(process_image(&bad).err(), Some(AvatarError::Unsupported));
    }
    let mut junk_png = b"\x89PNG\r\n\x1a\n".to_vec();
    junk_png.extend(std::iter::repeat(0xAB).take(1000));
    let mut junk_jpg = vec![0xFF, 0xD8, 0xFF, 0xE0];
    junk_jpg.extend(std::iter::repeat(0x5A).take(1000));
    let junk_webp = b"RIFF\x20\x00\x00\x00WEBPVP8 \x14\x00\x00\x00garbage-garbage-garb".to_vec();
    for bad in [junk_png, junk_jpg, junk_webp] {
        assert_eq!(process_image(&bad).err(), Some(AvatarError::Malformed));
    }
    let noisy = DynamicImage::ImageRgb8(RgbImage::from_fn(200, 200, |x, y| Rgb([(x * 7) as u8, (y * 13) as u8, (x ^ y) as u8])));
    for fmt in [ImageFormat::Png, ImageFormat::WebP] {
        let full = encode(&noisy, fmt);
        assert_eq!(process_image(&full[..full.len() / 2]).err(), Some(AvatarError::Malformed), "{fmt:?} truncated");
    }
}

#[tokio::test(start_paused = true)]
async fn processing_waits_for_the_single_slot_then_reports_busy() {
    let slots = Arc::new(Semaphore::new(PROCESS_SLOTS));
    let _held = slots.clone().acquire_owned().await.unwrap();
    let png = encode(&two_tone(16, 16), ImageFormat::Png);
    assert_eq!(process_in_background(&slots, png).await.err(), Some(AvatarError::Busy));
}

#[tokio::test]
async fn processing_runs_on_the_blocking_pool_and_frees_its_slot() {
    let slots = Arc::new(Semaphore::new(PROCESS_SLOTS));
    let png = encode(&two_tone(16, 16), ImageFormat::Png);
    assert!(process_in_background(&slots, png.clone()).await.is_ok());
    assert_eq!(process_in_background(&slots, b"GIF89a".to_vec()).await.err(), Some(AvatarError::Unsupported));
    assert_eq!(slots.available_permits(), PROCESS_SLOTS);
}

#[test]
fn small_helpers() {
    assert_eq!(canonical_host(" IRC.Example.NET. "), "irc.example.net");
    assert_eq!(canonical_host("[::1]"), "::1");
    assert_eq!(canonical_host("127.0.0.1"), "127.0.0.1");
    assert_eq!(image_file_version("avatar-0123456789abcdef-128.png"), Some("0123456789abcdef"));
    assert_eq!(image_file_version("avatar-0123456789abcdef-48.png"), Some("0123456789abcdef"));
    assert_eq!(image_file_version("avatar-0123456789abcdef-64.png"), None);
    assert_eq!(image_file_version("avatar-0123456789ABCDEF-128.png"), None);
    assert_eq!(image_file_version("appearance.json"), None);
    assert!(valid_token(&new_token()) && new_token() != new_token());
    let mut seen = SeenNicks::default();
    for i in 0..100 {
        seen.note(&format!("n{i}"));
    }
    assert_eq!(seen.fresh().count(), WHOIS_SEEN_MAX);
    seen.note("n0");
    assert!(seen.fresh().any(|n| n == "n0"));
    seen.note(&"x".repeat(NICK_MAX_BYTES + 1));
    assert!(!seen.fresh().any(|n| n.len() > NICK_MAX_BYTES));
    seen.clear();
    assert_eq!(seen.fresh().count(), 0);
}

// ─── Fixture ──────────────────────────────────────────────────────────────────

struct Fixture {
    dir: PathBuf,
    auth: Arc<AuthManager>,
    store: Arc<AvatarStore>,
    connections: Arc<DashMap<String, Arc<Mutex<IrcConnection>>>>,
    conn_owners: Arc<DashMap<String, String>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture() -> Fixture {
    let dir = std::env::temp_dir().join(format!("cryptirc-avatar-test-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(dir.join("users")).unwrap();
    // Minimal records are enough for sessions; the admin needs a full one (is_admin parses it).
    for u in ["alice", "bob", "carol", "mallory"] {
        std::fs::write(dir.join(format!("users/{u}.json")), format!(r#"{{"username":"{u}"}}"#)).unwrap();
    }
    std::fs::write(
        dir.join("users/root.json"),
        r#"{"username":"root","email":"","password_hash":"x","verified":true,"created_at":0,"admin":true}"#,
    )
    .unwrap();
    let auth = Arc::new(AuthManager::new(dir.to_str().unwrap()).unwrap());
    let store = Arc::new(AvatarStore::new(dir.to_str().unwrap(), true));
    Fixture { dir, auth, store, connections: Arc::new(DashMap::new()), conn_owners: Arc::new(DashMap::new()) }
}

impl Fixture {
    fn route_state(&self) -> AvatarRouteState {
        AvatarRouteState {
            auth: self.auth.clone(),
            store: self.store.clone(),
            connections: self.connections.clone(),
            conn_owners: self.conn_owners.clone(),
            link: || 1,
        }
    }
    async fn give_avatar(&self, user: &str, color: [u8; 3]) -> AvatarMeta {
        let png = encode(&DynamicImage::ImageRgb8(RgbImage::from_pixel(32, 32, Rgb(color))), ImageFormat::Png);
        self.store.save(&self.auth, user, self.auth.account_epoch(user), process_image(&png).unwrap()).await.unwrap()
    }
    /// A live connection of `owner` dialing `server:port` as `nick`, in `channels`.
    fn add_conn(&self, owner: &str, nick: &str, server: &str, port: u16, channels: &[(&str, &[&str])]) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut c = IrcConnection::for_test(&id, nick, server, port);
        for (name, names) in channels {
            let key = c.casemapping.fold(name);
            c.channels.insert(key, crate::irc::ChannelState {
                name: name.to_string(),
                topic: String::new(),
                names: names.iter().map(|s| s.to_string()).collect(),
                key: None,
            });
        }
        self.conn_owners.insert(id.clone(), owner.to_string());
        self.connections.insert(id.clone(), Arc::new(Mutex::new(c)));
        id
    }
    async fn edit(&self, id: &str, f: impl FnOnce(&mut IrcConnection)) {
        let conn = self.connections.get(id).unwrap().clone();
        let mut c = conn.lock().await;
        f(&mut c);
    }
    async fn lookup(&self, viewer: &str, conn: &str, nicks: &[&str]) -> Result<HashMap<String, AvatarMeta>, LookupError> {
        let nicks: Vec<String> = nicks.iter().map(|s| s.to_string()).collect();
        discover(&self.connections, &self.conn_owners, &self.store, &self.auth, 1, viewer, conn, &nicks).await
    }
}

fn files_of(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

// ─── Storage ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn store_saves_replaces_reloads_and_removes() {
    let f = fixture();
    let first = f.give_avatar("alice", [200, 0, 0]).await;
    assert!(first.visible && valid_token(&first.token));
    assert_eq!(f.store.owner_of(&first.token).as_deref(), Some("alice"));
    let dir = f.dir.join("users/alice");
    assert_eq!(files_of(&dir), vec![format!("avatar-{}-128.png", first.v), format!("avatar-{}-48.png", first.v), "avatar.json".to_string()]);
    // Replace: same token, new version, old pictures gone, the visibility choice kept.
    f.store.set_visible("alice", false).await.unwrap();
    let second = f.give_avatar("alice", [0, 200, 0]).await;
    assert_eq!(second.token, first.token);
    assert_ne!(second.v, first.v);
    assert!(!second.visible);
    assert_eq!(files_of(&dir), vec![format!("avatar-{}-128.png", second.v), format!("avatar-{}-48.png", second.v), "avatar.json".to_string()]);
    assert!(f.store.read_image("alice", &second.v, SIZE_SMALL).await.is_some());
    assert!(f.store.read_image("alice", &first.v, SIZE_LARGE).await.is_none());
    // A restart indexes it again; junk and unsafe directories are ignored.
    std::fs::create_dir_all(f.dir.join("users/bob")).unwrap();
    std::fs::write(f.dir.join("users/bob/avatar.json"), r#"{"token":"../../etc","v":"x"}"#).unwrap();
    std::fs::create_dir_all(f.dir.join("users/Not-Lower")).unwrap();
    std::fs::write(f.dir.join("users/Not-Lower/avatar.json"), serde_json::to_vec(&second).unwrap()).unwrap();
    let reloaded = AvatarStore::load(f.dir.to_str().unwrap(), true).await;
    assert_eq!(reloaded.meta("alice"), Some(second.clone()));
    assert_eq!(reloaded.owner_of(&second.token).as_deref(), Some("alice"));
    assert!(reloaded.meta("bob").is_none() && reloaded.meta("not-lower").is_none() && reloaded.meta("Not-Lower").is_none());
    // Remove: index and files.
    assert!(f.store.remove("alice").await);
    assert!(f.store.meta("alice").is_none() && f.store.owner_of(&second.token).is_none());
    assert!(files_of(&dir).is_empty());
    assert!(!f.store.remove("alice").await);
    // A new upload gets a new token.
    let third = f.give_avatar("alice", [0, 0, 200]).await;
    assert_ne!(third.token, first.token);
}

#[tokio::test]
async fn deleted_or_deleting_accounts_cannot_store_and_purge_forgets() {
    let f = fixture();
    let png = encode(&two_tone(16, 16), ImageFormat::Png);
    std::fs::remove_file(f.dir.join("users/mallory.json")).unwrap();
    assert_eq!(f.store.save(&f.auth, "mallory", 0, process_image(&png).unwrap()).await.err(), Some(AvatarError::Gone));
    assert_eq!(f.store.save(&f.auth, "../x", 0, process_image(&png).unwrap()).await.err(), Some(AvatarError::Gone));
    let meta = f.give_avatar("carol", [1, 2, 3]).await;
    let epoch = f.auth.account_epoch("carol");
    f.auth.begin_account_deletion("carol").await;
    assert_eq!(f.store.save(&f.auth, "carol", epoch, process_image(&png).unwrap()).await.err(), Some(AvatarError::Gone));
    f.store.purge_user("carol").await;
    assert!(f.store.owner_of(&meta.token).is_none());
    assert!(files_of(&f.dir.join("users/carol")).is_empty());
    f.auth.end_account_deletion("carol");
    // Audit H (avatar.rs:787): an upload accepted for the deleted account, completed after
    // the same name was registered again, must not land on the new account.
    assert_eq!(f.store.save(&f.auth, "carol", epoch, process_image(&png).unwrap()).await.err(), Some(AvatarError::Gone));
    assert!(f.store.meta("carol").is_none() && files_of(&f.dir.join("users/carol")).is_empty());
    assert!(f.store.save(&f.auth, "carol", f.auth.account_epoch("carol"), process_image(&png).unwrap()).await.is_ok(), "the new account's own upload works");
    // An account re-created behind the server's back does not inherit the old token.
    let alice = f.give_avatar("alice", [9, 9, 9]).await;
    std::fs::remove_dir_all(f.dir.join("users/alice")).unwrap();
    let again = f.give_avatar("alice", [8, 8, 8]).await;
    assert_ne!(again.token, alice.token);
    assert!(f.store.owner_of(&alice.token).is_none());
}

// ─── Routes ───────────────────────────────────────────────────────────────────

/// reqwest is built without its `json` feature here.
trait JsonValue {
    async fn json_value(self) -> serde_json::Value;
}
impl JsonValue for reqwest::Response {
    async fn json_value(self) -> serde_json::Value {
        serde_json::from_slice(&self.bytes().await.unwrap()).unwrap()
    }
}

struct Server(tokio::task::JoinHandle<()>);
impl Drop for Server {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn router(state: AvatarRouteState, base: &str) -> axum::Router {
    use axum::extract::DefaultBodyLimit;
    use axum::routing::{delete, get, post};
    let inner = axum::Router::new()
        .route(
            "/api/avatar/me",
            get(route_me_get).post(route_me_upload).put(route_me_settings).delete(route_me_delete)
                .layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/api/avatar/lookup", post(route_lookup).layer(DefaultBodyLimit::max(LOOKUP_BODY_MAX)))
        .route("/avatar/:token", get(route_image))
        .route("/admin/user/:username/avatar", delete(route_admin_remove));
    let app = if base.is_empty() { inner } else { axum::Router::new().nest(base, inner) };
    app.layer(axum::middleware::from_fn(crate::security_headers_mw)).with_state(state)
}

#[tokio::test]
async fn routes_authorize_every_request_at_every_base_path() {
    for base in ["", "/cryptirc", "/nested/prefix"] {
        let f = fixture();
        let alice = f.auth.issue_session("alice");
        let bob = f.auth.issue_session("bob");
        let carol = f.auth.issue_session("carol");
        let root = f.auth.issue_session("root");
        let meta = f.give_avatar("alice", [200, 50, 50]).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = router(f.route_state(), base);
        let _server = Server(tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        }));
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let url = |p: &str| format!("http://{address}{base}{p}");
        let img = url(&format!("/avatar/{}?v={}", meta.token, meta.v));

        // ── the picture ──
        let r = client.get(&img).send().await.unwrap();
        assert_eq!(r.status(), 401, "{base}: no session");
        assert_eq!(r.headers()["cache-control"], "private, no-store");
        assert_eq!(client.get(&img).bearer_auth(uuid::Uuid::new_v4().to_string()).send().await.unwrap().status(), 401);
        assert_eq!(client.get(&img).header("cookie", "cryptirc_token=not-a-session").send().await.unwrap().status(), 401);
        // Audit M (browser caching): the picture takes the Authorization header only (the
        // app fetches it into memory) — a cookie alone, as a cached <img> would send, is 401.
        assert_eq!(client.get(&img).header("cookie", format!("cryptirc_token={bob}")).send().await.unwrap().status(), 401);
        let r = client.get(&img).bearer_auth(&bob).send().await.unwrap();
        assert_eq!(r.status(), 200, "{base}: another account of this instance");
        assert_eq!(r.headers()["content-type"], "image/png");
        assert_eq!(r.headers()["cache-control"], "private, no-store", "never reused without coming back here");
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        assert_eq!(r.headers()["cross-origin-resource-policy"], "same-origin");
        assert!(r.headers().get("set-cookie").is_none());
        let etag = r.headers()["etag"].to_str().unwrap().to_string();
        let body = r.bytes().await.unwrap();
        assert_eq!(decode_png(&body).width(), SIZE_LARGE);
        let r = client.get(&img).bearer_auth(&bob).header("if-none-match", &etag).send().await.unwrap();
        assert_eq!(r.status(), 304, "revalidation");
        assert_eq!(client.get(&img).header("if-none-match", &etag).send().await.unwrap().status(), 401, "revalidation still needs a session");
        let r = client.get(format!("{img}&s=48")).bearer_auth(&carol).send().await.unwrap();
        assert_eq!(decode_png(&r.bytes().await.unwrap()).width(), SIZE_SMALL);
        for bad in [
            format!("/avatar/{}?v={}&s=64", meta.token, meta.v),
            format!("/avatar/{}?v=0000000000000000", meta.token),
            format!("/avatar/{}", meta.token),
            format!("/avatar/{}?v={}", "0".repeat(32), meta.v),
            format!("/avatar/alice?v={}", meta.v),
            format!("/avatar/{}?v={}", meta.token.to_uppercase(), meta.v),
        ] {
            let r = client.get(url(&bad)).bearer_auth(&bob).send().await.unwrap();
            assert_eq!(r.status(), 404, "{base}{bad}");
            assert_eq!(r.headers()["cache-control"], "private, no-store");
        }
        // Opted out: the owner and admins still see it, nobody else does.
        f.store.set_visible("alice", false).await.unwrap();
        assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 404);
        assert_eq!(client.get(&img).bearer_auth(&alice).send().await.unwrap().status(), 200);
        assert_eq!(client.get(&img).bearer_auth(&root).send().await.unwrap().status(), 200);
        f.store.set_visible("alice", true).await.unwrap();
        // Admin switch off: nothing is served.
        f.store.set_enabled(false);
        assert_eq!(client.get(&img).bearer_auth(&alice).send().await.unwrap().status(), 404);
        f.store.set_enabled(true);
        // Audit M (avatar.rs:870): the owner's account status is checked on every serve.
        let record = f.dir.join("users/alice.json");
        let saved = std::fs::read(&record).unwrap();
        std::fs::write(&record, r#"{"username":"alice","email":"","password_hash":"x","verified":false,"created_at":0,"disabled":true}"#).unwrap();
        assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 404, "disabled owner");
        assert_eq!(client.get(&img).bearer_auth(&root).send().await.unwrap().status(), 200, "admins can still moderate it");
        std::fs::write(&record, &saved).unwrap();
        std::fs::remove_file(&record).unwrap();
        assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 404, "owner record gone");
        std::fs::write(&record, &saved).unwrap();
        assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 200);

        // ── own avatar ──
        let me = url("/api/avatar/me");
        assert_eq!(client.get(&me).send().await.unwrap().status(), 401);
        assert_eq!(client.get(&me).header("cookie", format!("cryptirc_token={bob}")).send().await.unwrap().status(), 401, "API routes take no cookie");
        let r: serde_json::Value = client.get(&me).bearer_auth(&bob).send().await.unwrap().json_value().await;
        assert_eq!(r["enabled"], true);
        assert!(r["avatar"].is_null());
        let png = encode(&two_tone(64, 48), ImageFormat::Png);
        assert_eq!(client.post(&me).body(png.clone()).send().await.unwrap().status(), 401);
        let r = client.post(&me).bearer_auth(&bob).header("content-type", "image/png").body(png.clone()).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "private, no-store");
        let r: serde_json::Value = r.json_value().await;
        let bob_token = r["avatar"]["t"].as_str().unwrap().to_string();
        let bob_v = r["avatar"]["v"].as_str().unwrap().to_string();
        assert_eq!(r["visible"], true);
        assert!(f.dir.join(format!("users/bob/avatar-{bob_v}-128.png")).exists());
        let r = client.get(url(&format!("/avatar/{bob_token}?v={bob_v}"))).bearer_auth(&alice).send().await.unwrap();
        assert_eq!(r.status(), 200);
        // Audit M (avatar.rs:779): one body in flight per account, a few process-wide.
        f.store.uploading.insert("bob".into(), ());
        assert_eq!(client.post(&me).bearer_auth(&bob).body(png.clone()).send().await.unwrap().status(), 429);
        f.store.uploading.remove("bob");
        let permits = f.store.upload_bodies.clone().try_acquire_many_owned(UPLOAD_BODIES_MAX as u32).unwrap();
        assert_eq!(client.post(&me).bearer_auth(&bob).body(png.clone()).send().await.unwrap().status(), 503);
        drop(permits);
        assert!(f.store.uploading.is_empty(), "a refused request leaves no slot behind");
        let gif = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;".to_vec();
        assert_eq!(client.post(&me).bearer_auth(&bob).body(gif).send().await.unwrap().status(), 415);
        let mut junk = b"\x89PNG\r\n\x1a\n".to_vec();
        junk.extend(std::iter::repeat(1u8).take(100));
        assert_eq!(client.post(&me).bearer_auth(&bob).body(junk).send().await.unwrap().status(), 400);
        // Over 2 MB: 413 before the body is read (the server may close the connection while
        // the client is still sending, which also counts as refused).
        let mut big = png.clone();
        big.resize(MAX_UPLOAD_BYTES + 1, 0);
        if let Ok(r) = client.post(&me).bearer_auth(&bob).body(big).send().await {
            assert_eq!(r.status(), 413);
        }
        assert!(f.store.meta("bob").map_or(true, |m| m.v == bob_v), "nothing was stored");
        let r: serde_json::Value = client.put(&me).bearer_auth(&bob).header("content-type", "application/json").body((serde_json::json!({"visible": false})).to_string()).send().await.unwrap().json_value().await;
        assert_eq!(r["visible"], false);
        assert_eq!(client.get(url(&format!("/avatar/{bob_token}?v={bob_v}"))).bearer_auth(&alice).send().await.unwrap().status(), 404);
        assert_eq!(client.put(&me).bearer_auth(&carol).header("content-type", "application/json").body((serde_json::json!({"visible": false})).to_string()).send().await.unwrap().status(), 404);
        assert_eq!(client.delete(&me).send().await.unwrap().status(), 401);
        let r: serde_json::Value = client.delete(&me).bearer_auth(&bob).send().await.unwrap().json_value().await;
        assert!(r["avatar"].is_null());
        assert!(files_of(&f.dir.join("users/bob")).is_empty());
        assert_eq!(client.get(url(&format!("/avatar/{bob_token}?v={bob_v}"))).bearer_auth(&bob).send().await.unwrap().status(), 404);
        f.store.set_enabled(false);
        let r = client.post(&me).bearer_auth(&bob).body(png.clone()).send().await.unwrap();
        assert_eq!(r.status(), 403, "uploads refused while avatars are off");
        let r: serde_json::Value = client.get(&me).bearer_auth(&bob).send().await.unwrap().json_value().await;
        assert_eq!(r["enabled"], false);
        f.store.set_enabled(true);

        // ── lookups ──
        let lookup = url("/api/avatar/lookup");
        let alice_conn = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", &["alice"])]);
        let body = serde_json::json!({"conn_id": alice_conn, "nicks": ["alice"]});
        assert_eq!(client.post(&lookup).header("content-type", "application/json").body((body).to_string()).send().await.unwrap().status(), 401);
        let r = client.post(&lookup).bearer_auth(&bob).header("content-type", "application/json").body((body).to_string()).send().await.unwrap();
        assert_eq!(r.status(), 404, "someone else's connection");
        let r = client.post(&lookup).bearer_auth(&alice).header("content-type", "application/json").body((body).to_string()).send().await.unwrap();
        assert_eq!(r.status(), 200);
        assert_eq!(r.headers()["cache-control"], "private, no-store");
        let r: serde_json::Value = r.json_value().await;
        assert_eq!(r["avatars"]["alice"]["t"], meta.token.as_str());
        assert_eq!(r["ttl"], LOOKUP_TTL_SECS);
        let many: Vec<String> = (0..=LOOKUP_MAX_NICKS).map(|i| format!("n{i}")).collect();
        let r = client.post(&lookup).bearer_auth(&alice).header("content-type", "application/json").body((serde_json::json!({"conn_id": alice_conn, "nicks": many})).to_string()).send().await.unwrap();
        assert_eq!(r.status(), 400);

        // ── admin remove ──
        let admin = url("/admin/user/alice/avatar");
        assert_eq!(client.delete(&admin).send().await.unwrap().status(), 401);
        assert_eq!(client.delete(&admin).bearer_auth(&bob).send().await.unwrap().status(), 403);
        assert_eq!(client.delete(url("/admin/user/..%2F..%2Fetc/avatar")).bearer_auth(&root).send().await.unwrap().status(), 400);
        assert_eq!(client.delete(&admin).bearer_auth(&root).send().await.unwrap().status(), 200);
        assert_eq!(client.delete(&admin).bearer_auth(&root).send().await.unwrap().status(), 404);
        assert_eq!(client.get(&img).bearer_auth(&alice).send().await.unwrap().status(), 404);
    }
}

#[tokio::test]
async fn lookups_are_rate_limited_per_account() {
    let f = fixture();
    for _ in 0..LOOKUP_RATE_MAX {
        assert!(f.store.lookup_rate_ok("alice"));
    }
    assert!(!f.store.lookup_rate_ok("alice"));
    assert!(f.store.lookup_rate_ok("bob"), "per account");
}

// ─── Discovery ────────────────────────────────────────────────────────────────

const ROOM: &[&str] = &["@alice", "+bob", "mallory", "Carol"];

#[tokio::test]
async fn same_server_host_matches_regardless_of_port_and_spelling() {
    let f = fixture();
    let bob = f.give_avatar("bob", [0, 0, 255]).await;
    let alice_av = f.give_avatar("alice", [255, 0, 0]).await;
    let viewer = f.add_conn("alice", "alice", "irc.example.net", 6697, &[("#room", ROOM)]);
    f.add_conn("bob", "bob", " IRC.Example.NET. ", 6667, &[("#room", ROOM)]);
    let found = f.lookup("alice", &viewer, &["bob", "+bob", "BOB", "mallory", "alice", "nobody"]).await.unwrap();
    assert_eq!(found.get("bob"), Some(&bob));
    assert_eq!(found.get("BOB"), Some(&bob), "answers use the spelling asked");
    assert_eq!(found.get("alice"), Some(&alice_av), "the viewer sees their own avatar");
    assert!(!found.contains_key("mallory") && !found.contains_key("nobody"), "no avatar / not a CryptIRC user");
    assert_eq!(found.len(), 3);
}

#[tokio::test]
async fn a_different_host_or_a_fake_network_name_never_matches() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "127.0.0.1", 6667, &[("#room", ROOM)]);
    crate::e2e::note_isupport(&viewer, &["NETWORK=TwistedNET".to_string()]);
    // The very same ircd under another name is another host for this rule.
    let alias = f.add_conn("bob", "bob", "localhost", 6667, &[("#room", ROOM)]);
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    // A look-alike ircd advertising the same NETWORK name, where "bob" was taken.
    f.connections.remove(&alias);
    let fake = f.add_conn("bob", "bob", "irc.evil.example", 6667, &[("#room", ROOM)]);
    crate::e2e::note_isupport(&fake, &["NETWORK=TwistedNET".to_string()]);
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    // Same host, but the two connections report different NETWORK names (a bouncer host
    // fronting two networks): vetoed.
    f.connections.remove(&fake);
    let bnc = f.add_conn("bob", "bob", "127.0.0.1", 6697, &[("#room", ROOM)]);
    crate::e2e::note_isupport(&bnc, &["NETWORK=OtherNet".to_string()]);
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    // Same host and the same name (or no name yet): a match.
    crate::e2e::note_isupport(&bnc, &["NETWORK=TwistedNET".to_string()]);
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
}

#[tokio::test]
async fn only_nicks_the_viewer_sees_are_answered() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", &["alice", "mallory"])]);
    f.add_conn("bob", "Bob", "irc.test", 6667, &[("#secret", &["Bob"])]);
    assert!(f.lookup("alice", &viewer, &["Bob"]).await.unwrap().is_empty(), "no shared channel");
    f.edit(&viewer, |c| c.whois_seen.note("bob")).await;
    assert_eq!(f.lookup("alice", &viewer, &["Bob"]).await.unwrap().len(), 1, "a WHOIS reply showed the nick");
    f.edit(&viewer, |c| c.whois_seen.clear()).await;
    assert!(f.lookup("alice", &viewer, &["Bob"]).await.unwrap().is_empty());
}

#[tokio::test]
async fn opted_out_disconnected_deleted_or_avatarless_owners_are_never_revealed() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    let bob_conn = f.add_conn("bob", "bob", "irc.test", 6667, &[("#room", ROOM)]);
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
    // Opted out: hidden from others, still shown to the owner.
    f.store.set_visible("bob", false).await.unwrap();
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    assert_eq!(f.lookup("bob", &bob_conn, &["bob"]).await.unwrap().len(), 1);
    f.store.set_visible("bob", true).await.unwrap();
    // Not live.
    f.edit(&bob_conn, |c| c.connected = false).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&bob_conn, |c| c.connected = true).await;
    f.edit(&bob_conn, |c| c.registered = false).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&bob_conn, |c| c.registered = true).await;
    // The viewer's own connection is down: no answers from stale member lists.
    f.edit(&viewer, |c| c.registered = false).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&viewer, |c| c.registered = true).await;
    // Being deleted, or the record is gone.
    f.auth.begin_account_deletion("bob").await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.auth.end_account_deletion("bob");
    let record = f.dir.join("users/bob.json");
    let saved = std::fs::read(&record).unwrap();
    std::fs::remove_file(&record).unwrap();
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    std::fs::write(&record, &saved).unwrap();
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
    // Disabled (banned) by an admin while the IRC session stays up.
    std::fs::write(&record, r#"{"username":"bob","email":"","password_hash":"x","verified":false,"created_at":0,"disabled":true}"#).unwrap();
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    std::fs::write(&record, &saved).unwrap();
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
    // Avatars switched off by the admin.
    f.store.set_enabled(false);
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.store.set_enabled(true);
    // No avatar.
    f.store.remove("bob").await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
}

#[tokio::test]
async fn the_current_nick_counts_and_ambiguity_fails_closed() {
    let f = fixture();
    let bob = f.give_avatar("bob", [0, 0, 255]).await;
    f.give_avatar("carol", [0, 255, 0]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", &["alice", "bob", "bobby"])]);
    let bob_conn = f.add_conn("bob", "bobby", "irc.test", 6667, &[]);
    // The server tracks bob's connection as "bobby"; "bob" in the list is someone else.
    let found = f.lookup("alice", &viewer, &["bob", "bobby"]).await.unwrap();
    assert!(!found.contains_key("bob"));
    assert_eq!(found.get("bobby"), Some(&bob));
    // Two accounts' live connections hold the same nick (two ircds / a bouncer on one
    // host): neither is vouched for.
    f.add_conn("carol", "BOBBY", "irc.test", 7000, &[]);
    assert!(f.lookup("alice", &viewer, &["bobby"]).await.unwrap().is_empty());
    let _ = bob_conn;
}

#[tokio::test]
async fn nicks_compare_under_the_networks_casemapping_never_wider() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", &["alice", "a{b"])]);
    f.add_conn("bob", "a[b", "irc.test", 6667, &[]);
    // Unknown casemapping → ASCII only: a[b and a{b are different nicks.
    assert!(f.lookup("alice", &viewer, &["a{b"]).await.unwrap().is_empty());
    f.edit(&viewer, |c| c.server_casemapping = Some(cryptirc::ircproto::CaseMapping::Ascii)).await;
    assert!(f.lookup("alice", &viewer, &["a{b"]).await.unwrap().is_empty());
    // rfc1459 says they are the same nick.
    f.edit(&viewer, |c| c.server_casemapping = Some(cryptirc::ircproto::CaseMapping::Rfc1459)).await;
    assert_eq!(f.lookup("alice", &viewer, &["a{b"]).await.unwrap().len(), 1);
}

#[tokio::test]
async fn only_the_owner_of_a_connection_may_ask_through_it() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    let bob_conn = f.add_conn("bob", "bob", "irc.test", 6667, &[("#room", ROOM)]);
    assert_eq!(f.lookup("mallory", &viewer, &["bob"]).await.err(), Some(LookupError::NotYourConnection));
    assert_eq!(f.lookup("alice", &bob_conn, &["bob"]).await.err(), Some(LookupError::NotYourConnection));
    assert_eq!(f.lookup("alice", &uuid::Uuid::new_v4().to_string(), &["bob"]).await.err(), Some(LookupError::NotYourConnection));
    assert_eq!(f.lookup("alice", &viewer.to_uppercase(), &["bob"]).await.err(), Some(LookupError::NotYourConnection));
    // Junk nicks are ignored, not errors.
    let found = f.lookup("alice", &viewer, &["", "a b", "x\r\ny", &"n".repeat(100), "bob"]).await.unwrap();
    assert_eq!(found.len(), 1);
}


// ─── Audit round 1 (Codex) ────────────────────────────────────────────────────

fn stream_body<S>(stream: S) -> Body
where
    S: futures_util::Stream<Item = Result<axum::body::Bytes, std::io::Error>> + Send + 'static,
{
    Body::from_stream(stream)
}

#[tokio::test(start_paused = true)]
async fn upload_bodies_are_bounded_in_size_and_time() {
    use futures_util::{stream, StreamExt};
    // Stalls after the first chunk: refused at the idle limit, not held forever.
    let stalled = stream::once(async { Ok(axum::body::Bytes::from_static(b"\x89PNG")) }).chain(stream::pending());
    assert_eq!(read_upload(stream_body(stalled)).await.err(), Some(AvatarError::Slow));
    // A trickle that never ends: refused at the total deadline.
    let trickle = stream::unfold((), |_| async {
        tokio::time::sleep(Duration::from_secs(10)).await;
        Some((Ok(axum::body::Bytes::from_static(b"x")), ()))
    });
    let started = tokio::time::Instant::now();
    assert_eq!(read_upload(stream_body(trickle)).await.err(), Some(AvatarError::Slow));
    assert!(started.elapsed() <= UPLOAD_TOTAL + UPLOAD_IDLE);
    // Over the cap: refused as soon as it is exceeded.
    let big = stream::iter((0..40).map(|_| Ok(axum::body::Bytes::from(vec![0u8; 64 * 1024]))));
    assert_eq!(read_upload(stream_body(big)).await.err(), Some(AvatarError::TooLarge));
    let ok = stream::iter(vec![Ok(axum::body::Bytes::from_static(b"ab")), Ok(axum::body::Bytes::from_static(b"cd"))]);
    assert_eq!(read_upload(stream_body(ok)).await.unwrap(), b"abcd");
}

#[test]
fn bouncer_capabilities_and_isupport_are_recognised() {
    assert!(caps_name_a_bouncer("multi-prefix znc.in/batch server-time"));
    assert!(caps_name_a_bouncer("ZNC.IN/server-time-iso"));
    assert!(caps_name_a_bouncer("soju.im/bouncer-networks-notify sasl=PLAIN"));
    assert!(caps_name_a_bouncer("draft/bouncer-networks=notify"));
    assert!(caps_name_a_bouncer("causal.agency/passive"));
    assert!(!caps_name_a_bouncer("multi-prefix sasl=PLAIN,EXTERNAL draft/chathistory message-tags"));
    // Ergo, a real ircd, advertises these two (seen live on the test ircd).
    assert!(!caps_name_a_bouncer("draft/read-marker echo-message ergo.chat/nope userhost-in-names znc.in/playback znc.in/self-message"));
    assert!(cap_line_names_a_bouncer(Some("irc.znc.in"), "multi-prefix"));
    assert!(!cap_line_names_a_bouncer(Some("ergo.test"), "multi-prefix znc.in/self-message"));
    assert!(isupport_names_a_bouncer(&["me".into(), "BOUNCER_NETID=42".into(), "are supported".into()]));
    assert!(!isupport_names_a_bouncer(&["me".into(), "NETWORK=Libera.Chat".into()]));
}

#[tokio::test]
async fn connections_behind_a_bouncer_or_not_yet_negotiated_are_never_matched() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "bnc.example", 6697, &[("#room", ROOM)]);
    let bob_conn = f.add_conn("bob", "bob", "bnc.example", 6697, &[("#room", ROOM)]);
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1, "both negotiated with a plain ircd");
    // Audit H (avatar.rs:658): a shared bouncer authenticates itself, not each upstream.
    f.edit(&bob_conn, |c| note_cap_line(c, Some("irc.znc.in"), "LS", false, "multi-prefix", false)).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty(), "the holder is behind a bouncer");
    f.edit(&bob_conn, |c| c.behind_bouncer = false).await;
    f.edit(&viewer, |c| note_cap_line(c, Some("bnc.example"), "NEW", false, "soju.im/bouncer-networks", false)).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty(), "the viewer is behind a bouncer");
    f.edit(&viewer, |c| c.behind_bouncer = false).await;
    // Unknown (CAP negotiation not seen in this process): no match either way.
    f.edit(&bob_conn, |c| c.cap_ls_done = false).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&bob_conn, |c| c.cap_ls_done = true).await;
    f.edit(&viewer, |c| c.cap_ls_done = false).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&viewer, |c| c.cap_ls_done = true).await;
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
}

#[tokio::test]
async fn one_accounts_bouncer_connection_never_affects_another_connection() {
    // Self-review (security review of the first fix): classification is per live connection.
    // A shared, persisted per-host registry could be grown or steered by any account; here an
    // account behind a bouncer on another port of the same host only loses its own matches.
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    f.give_avatar("mallory", [9, 9, 9]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", &["alice", "bob", "mal"])]);
    f.add_conn("bob", "bob", "irc.test", 6667, &[]);
    let mal = f.add_conn("mallory", "mal", "irc.test", 7000, &[]);
    f.edit(&mal, |c| note_cap_line(c, None, "LS", false, "znc.in/batch multi-prefix", false)).await;
    let found = f.lookup("alice", &viewer, &["bob", "mal"]).await.unwrap();
    assert!(found.contains_key("bob"), "other connections on the host keep matching");
    assert!(!found.contains_key("mal"), "the bouncer connection itself is never matched");
}

#[test]
fn cap_lines_classify_their_own_connection() {
    let mut c = IrcConnection::for_test("c1", "me", "irc.test", 6667);
    c.cap_ls_done = false;
    note_cap_line(&mut c, Some("irc.test"), "LS", true, "multi-prefix znc.in/self-message znc.in/playback", false);
    assert!(!c.cap_ls_done && !c.behind_bouncer, "more lines follow; Ergo's znc.in caps are not a bouncer");
    note_cap_line(&mut c, Some("irc.test"), "LS", false, "sasl server-time", false);
    assert!(c.cap_ls_done && !c.behind_bouncer);
    note_cap_line(&mut c, Some("irc.test"), "NEW", false, "draft/bouncer-networks", false);
    assert!(c.behind_bouncer, "a bouncer capability announced later counts too");
    let mut z = IrcConnection::for_test("c2", "me", "bnc", 6667);
    z.cap_ls_done = false;
    note_cap_line(&mut z, Some("irc.znc.in"), "LS", false, "multi-prefix", false);
    assert!(z.cap_ls_done && z.behind_bouncer, "ZNC answers CAP itself");
}

#[tokio::test]
async fn the_viewers_user_at_host_must_match_the_holder() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    let bob_conn = f.add_conn("bob", "bob", "irc.test", 6667, &[("#room", ROOM)]);
    // No user@host seen for bob yet: nothing to compare.
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
    // The viewer's server shows bob as ~bob@real.host (a JOIN line).
    f.edit(&viewer, |c| observe_line(c, Some("bob!~bob@Real.Host"), "JOIN", &["#room".into()])).await;
    f.edit(&bob_conn, |c| c.self_userhost = "~bob@real.host".into()).await;
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1, "same user@host (host case-insensitive)");
    // Audit H (avatar.rs:658): the holder's own user@host differs (another upstream).
    f.edit(&bob_conn, |c| c.self_userhost = "~evil@fake.upstream".into()).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
    f.edit(&bob_conn, |c| c.self_userhost = String::new()).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty(), "unknown own user@host");
    f.edit(&bob_conn, |c| c.self_userhost = "~bob@real.host".into()).await;
    // A WHO reply with a newer user@host wins.
    f.edit(&viewer, |c| observe_line(c, Some("irc.test"), "352", &["alice".into(), "#room".into(), "~bob".into(), "moved.host".into(), "irc.test".into(), "bob".into(), "H".into(), "0 Bob".into()])).await;
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
}

#[tokio::test]
async fn accounts_without_an_avatar_count_for_ambiguity() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    f.add_conn("bob", "bob", "irc.test", 6667, &[]);
    assert_eq!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().len(), 1);
    // Audit H (avatar.rs:647): carol has no avatar but also holds "bob" on this host.
    f.add_conn("carol", "BOB", "irc.test", 7000, &[]);
    assert!(f.lookup("alice", &viewer, &["bob"]).await.unwrap().is_empty());
}

#[tokio::test]
async fn nothing_is_vouched_for_without_a_fresh_irc_core_link() {
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    let bob_conn = f.add_conn("bob", "bob", "irc.test", 6667, &[("#room", ROOM)]);
    let ask = |link: u64| {
        let nicks = vec!["bob".to_string()];
        let (c, o, s, a, v) = (f.connections.clone(), f.conn_owners.clone(), f.store.clone(), f.auth.clone(), viewer.clone());
        async move { discover(&c, &o, &s, &a, link, "alice", &v, &nicks).await.unwrap().len() }
    };
    assert_eq!(ask(1).await, 1);
    // Audit M (avatar.rs:656): irc-core is unreachable (no link): cached flags are stale.
    assert_eq!(ask(0).await, 0);
    // ...even for connections never synced on any link (synced_link 0 == link 0).
    f.edit(&viewer, |c| c.synced_link = 0).await;
    f.edit(&bob_conn, |c| c.synced_link = 0).await;
    assert_eq!(ask(0).await, 0);
    f.edit(&viewer, |c| c.synced_link = 1).await;
    f.edit(&bob_conn, |c| c.synced_link = 1).await;
    // A new link whose SessionSync has not arrived yet for these connections.
    assert_eq!(ask(2).await, 0);
    f.edit(&viewer, |c| c.synced_link = 2).await;
    assert_eq!(ask(2).await, 0, "the holder is not fresh yet");
    f.edit(&bob_conn, |c| c.synced_link = 2).await;
    assert_eq!(ask(2).await, 1);
}

#[test]
fn observed_user_at_hosts_follow_the_irc_lines() {
    let mut c = IrcConnection::for_test("c1", "me", "irc.test", 6667);
    let v = |c: &IrcConnection| c.seen_userhosts.latest_by(|n| n.to_ascii_lowercase());
    observe_line(&mut c, Some("Bob!~b@h1"), "PRIVMSG", &["#x".into(), "hi".into()]);
    assert_eq!(v(&c).get("bob").map(String::as_str), Some("~b@h1"));
    observe_line(&mut c, Some("bob!~b@h1"), "CHGHOST", &["~b".into(), "h2".into()]);
    assert_eq!(v(&c).get("bob").map(String::as_str), Some("~b@h2"));
    observe_line(&mut c, Some("bob!~b@h2"), "NICK", &["bobby".into()]);
    assert!(v(&c).get("bob").is_none());
    assert_eq!(v(&c).get("bobby").map(String::as_str), Some("~b@h2"));
    observe_line(&mut c, Some("srv"), "311", &["me".into(), "carol".into(), "~c".into(), "h3".into(), "*".into(), "Carol".into()]);
    assert_eq!(v(&c).get("carol").map(String::as_str), Some("~c@h3"));
    observe_line(&mut c, Some("srv"), "353", &["me".into(), "=".into(), "#x".into(), "@dave!~d@h4 +erin!e@h5 frank".into()]);
    assert_eq!(v(&c).get("dave").map(String::as_str), Some("~d@h4"));
    assert_eq!(v(&c).get("erin").map(String::as_str), Some("e@h5"));
    assert!(v(&c).get("frank").is_none());
    observe_line(&mut c, Some("bobby!~b@h2"), "QUIT", &["bye".into()]);
    assert!(v(&c).get("bobby").is_none());
    for i in 0..(SEEN_HOSTS_MAX + 10) {
        c.seen_userhosts.note(&format!("n{i}"), "u@h");
    }
    assert!(c.seen_userhosts.map.len() <= SEEN_HOSTS_MAX, "bounded");
    assert!(v(&c).contains_key(&format!("n{}", SEEN_HOSTS_MAX + 9)), "the newest are kept");
}

#[tokio::test]
async fn pictures_stop_as_soon_as_the_owner_is_being_deleted() {
    let f = fixture();
    let bob = f.auth.issue_session("bob");
    let meta = f.give_avatar("carol", [9, 9, 9]).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = router(f.route_state(), "");
    let _server = Server(tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); }));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let img = format!("http://{address}/avatar/{}?v={}", meta.token, meta.v);
    assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 200);
    f.auth.begin_account_deletion("carol").await;
    assert_eq!(client.get(&img).bearer_auth(&bob).send().await.unwrap().status(), 404);
}

// ─── Web restart: per-connection records ──────────────────────────────────────

#[test]
fn a_record_is_restored_only_for_the_same_irc_core_session() {
    let rec = SessionRecord { owner: "bob".into(), host: "irc.test".into(), port: 6667, bouncer: false };
    let same = ReplayEvidence { first_backlog: Some(false), restarted: false, no_backlog_info: false };
    let ep = Some(("IRC.Test.", 6667));
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, Some(same)), Some(false), "same session, plain");
    let bnc = SessionRecord { bouncer: true, ..rec.clone() };
    assert_eq!(restorable(Some(&bnc), Some("bob"), ep, Some(same)), Some(true), "a bouncer stays a bouncer");
    // Anything missing or different: not restored (fail closed).
    assert_eq!(restorable(None, Some("bob"), ep, Some(same)), None, "no record");
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, None), None, "no replay seen");
    assert_eq!(restorable(Some(&rec), Some("mallory"), ep, Some(same)), None, "another owner now");
    assert_eq!(restorable(Some(&rec), None, ep, Some(same)), None, "no owner");
    assert_eq!(restorable(Some(&rec), Some("bob"), Some(("other.test", 6667)), Some(same)), None, "another host");
    assert_eq!(restorable(Some(&rec), Some("bob"), Some(("irc.test", 6697)), Some(same)), None, "another port");
    assert_eq!(restorable(Some(&rec), Some("bob"), None, Some(same)), None, "endpoint unknown");
    let restarted = ReplayEvidence { restarted: true, ..same };
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, Some(restarted)), None, "irc-core reconnected while no web was attached");
    let truncated = ReplayEvidence { first_backlog: Some(true), ..same };
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, Some(truncated)), None, "unseen lines may have been evicted");
    let empty = ReplayEvidence { first_backlog: None, ..same };
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, Some(empty)), None, "nothing replayed");
    let old_core = ReplayEvidence { no_backlog_info: true, ..same };
    assert_eq!(restorable(Some(&rec), Some("bob"), ep, Some(old_core)), None, "an irc-core that does not report backlog");
}

#[test]
fn replayed_lines_tell_whether_the_session_restarted() {
    let id = uuid::Uuid::new_v4().to_string();
    let l = |s: &str| -> Vec<String> { s.split(' ').map(str::to_string).collect() };
    note_replayed_line(&id, false, 100, "PRIVMSG", &l("#a hi"));
    note_replayed_line(&id, true, 101, "PRIVMSG", &l("#a hi"));
    note_replayed_line(&id, false, 102, "001", &l("me Welcome"));
    assert_eq!(take_replay_evidence(&id), Some(ReplayEvidence { first_backlog: Some(false), restarted: false, no_backlog_info: false }),
        "an already-delivered 001 is the session the previous web saw start");
    note_replayed_line(&id, false, 100, "PRIVMSG", &l("#a hi"));
    note_replayed_line(&id, true, 105, "CAP", &l("* LS :multi-prefix"));
    assert_eq!(take_replay_evidence(&id).map(|e| e.restarted), Some(true));
    note_replayed_line(&id, true, 100, "PRIVMSG", &l("#a hi"));
    assert_eq!(take_replay_evidence(&id).map(|e| e.first_backlog), Some(Some(true)));
    note_replayed_line(&id, false, 0, "PRIVMSG", &l("#a hi"));
    assert_eq!(take_replay_evidence(&id).map(|e| e.no_backlog_info), Some(true));
    assert_eq!(take_replay_evidence(&id), None);
}

#[tokio::test]
async fn records_are_bounded_by_saved_networks_cleared_and_persisted() {
    let f = fixture();
    let (a, b, gone) = (uuid::Uuid::new_v4().to_string(), uuid::Uuid::new_v4().to_string(), uuid::Uuid::new_v4().to_string());
    let owners: DashMap<String, String> = DashMap::new();
    owners.insert(a.clone(), "alice".into());
    owners.insert(b.clone(), "bob".into());
    let store = AvatarStore::load(f.dir.to_str().unwrap(), true).await;
    store.record_session(&a, "alice", ("IRC.Test.", 6667), false, &owners);
    store.record_session(&b, "mallory", ("irc.test", 6667), false, &owners);
    store.record_session(&gone, "alice", ("irc.test", 6667), false, &owners);
    assert_eq!(store.session(&a), Some(SessionRecord { owner: "alice".into(), host: "irc.test".into(), port: 6667, bouncer: false }));
    assert!(store.session(&b).is_none(), "only for the owner's own saved network");
    assert!(store.session(&gone).is_none(), "only for a saved network");
    store.record_session(&b, "bob", ("irc.test", 6697), false, &owners);
    store.mark_session_bouncer(&b);
    assert_eq!(store.session(&b).map(|r| r.bouncer), Some(true));
    // Persisted, and pruned at startup against the networks that still exist.
    let file = f.dir.join(SESSIONS_FILE);
    for _ in 0..50 {
        if std::fs::read_to_string(&file).map_or(false, |t| t.contains(&b) && t.contains("true")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let again = AvatarStore::load(f.dir.to_str().unwrap(), true).await;
    assert_eq!(again.session(&b).map(|r| r.bouncer), Some(true));
    owners.remove(&b);
    again.prune_sessions(&owners);
    assert!(again.session(&b).is_none() && again.session(&a).is_some());
    // Cleared on Dial / (re)connect / edit / removal, and on account purge.
    again.forget_session(&a);
    assert!(again.session(&a).is_none());
    again.record_session(&a, "alice", ("irc.test", 6667), false, &owners);
    again.purge_user("alice").await;
    assert!(again.session(&a).is_none());
    // Junk ids in the file are ignored.
    std::fs::write(&file, r#"{"../x":{"owner":"a","host":"h","port":1,"bouncer":false}}"#).unwrap();
    assert!(AvatarStore::load(f.dir.to_str().unwrap(), true).await.sessions.is_empty());
}


// ─── Re-check round (Codex) ───────────────────────────────────────────────────

#[test]
fn replayed_nick_history_never_rewrites_a_connections_identity() {
    // Codex re-check H avatar.rs:1005: Old renamed to Victim earlier; the attacker then took
    // Old. After a reattach the snapshot says this connection is Old (u@attacker); replaying
    // the history must not make it "be" Victim.
    let mut c = IrcConnection::for_test("c1", "Old", "irc.test", 6667);
    c.self_userhost = "u@attacker".into();
    assert!(!c.adopt_self_nick("Old", "Victim", "u@victim", true), "replayed :Old!u@victim NICK Victim");
    assert!(!c.adopt_self_nick("Evil", "Old", "u@attacker", true), "replayed :Evil!u@attacker NICK Old");
    assert_eq!((c.nick.as_str(), c.self_userhost.as_str()), ("Old", "u@attacker"));
    c.adopt_self_join_userhost("Old", "u@victim", true);
    c.adopt_self_chghost("Old", "u@attacker", "u", "victim", true);
    assert_eq!(c.self_userhost, "u@attacker", "replayed JOIN / CHGHOST neither");
    // Live lines still work, under the #30 ident rule.
    assert!(!c.adopt_self_nick("Old", "Victim", "x@victim", false), "another ident");
    assert!(c.adopt_self_nick("Old", "New", "u@attacker", false));
    assert_eq!(c.nick, "New");
    c.adopt_self_chghost("New", "u@attacker", "u", "cloak", false);
    assert_eq!(c.self_userhost, "u@cloak");
}

#[tokio::test]
async fn nothing_is_vouched_for_until_the_attach_replay_is_over() {
    use crate::ipc_client::attached_link_of;
    assert_eq!(attached_link_of(0, 0), 0, "no link");
    assert_eq!(attached_link_of(3, 2), 0, "link 3 still replaying (AttachComplete handled for link 2)");
    assert_eq!(attached_link_of(3, 3), 3);
    let f = fixture();
    f.give_avatar("bob", [0, 0, 255]).await;
    let viewer = f.add_conn("alice", "alice", "irc.test", 6667, &[("#room", ROOM)]);
    f.add_conn("bob", "bob", "irc.test", 6667, &[("#room", ROOM)]);
    let nicks = vec!["bob".to_string()];
    let during = discover(&f.connections, &f.conn_owners, &f.store, &f.auth, attached_link_of(1, 0), "alice", &viewer, &nicks).await.unwrap();
    assert!(during.is_empty());
    let after = discover(&f.connections, &f.conn_owners, &f.store, &f.auth, attached_link_of(1, 1), "alice", &viewer, &nicks).await.unwrap();
    assert_eq!(after.len(), 1);
}

#[test]
fn replayed_cap_lines_only_ever_add_restrictions() {
    // Codex re-check M avatar.rs:383: a replayed final LS fragment (earlier ones evicted)
    // must not make a connection "negotiated and clean".
    let mut c = IrcConnection::for_test("c1", "me", "bnc", 6667);
    c.cap_ls_done = false;
    note_cap_line(&mut c, Some("bnc"), "LS", false, "sasl server-time", true);
    assert!(!c.cap_ls_done && !c.behind_bouncer, "a replayed final fragment proves nothing");
    note_cap_line(&mut c, Some("bnc"), "NEW", false, "soju.im/bouncer-networks", true);
    assert!(c.behind_bouncer, "but a replayed bouncer sign counts");
    // Restoring a saved record keeps any bouncer mark: saved, or added by replay.
    let mut r = IrcConnection::for_test("c2", "me", "bnc", 6667);
    r.cap_ls_done = false;
    assert!(apply_restore(&mut r, Some(true)));
    assert!(r.cap_ls_done && r.behind_bouncer, "saved bouncer=true");
    let mut r2 = IrcConnection::for_test("c3", "me", "bnc", 6667);
    r2.cap_ls_done = false;
    r2.behind_bouncer = true;
    assert!(apply_restore(&mut r2, Some(false)));
    assert!(r2.behind_bouncer, "a bouncer mark from replay is never cleared by a clean record");
    let mut r3 = IrcConnection::for_test("c4", "me", "bnc", 6667);
    r3.cap_ls_done = false;
    assert!(!apply_restore(&mut r3, None) && !r3.cap_ls_done, "no decision, no restore");
    r3.registered = false;
    assert!(!apply_restore(&mut r3, Some(false)), "not live");
}
