//! Remote-avatar tests: announce parsing and tagging, URL rules, per-connection bindings and
//! their invalidation, metadata lines, the limits, and the fetcher against a local HTTP
//! server (good picture, SVG, HTML, oversized, redirect, huge dimensions, slow, gone,
//! revalidation) — plus the private-address refusal outside the test mode.

use super::*;
use std::io::Cursor;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn conn(nick: &str) -> IrcConnection {
    IrcConnection::for_test("c1", nick, "irc.test", 6667)
}

/// A connection in #x with these members.
fn conn_in(nick: &str, members: &[&str]) -> IrcConnection {
    let mut c = conn(nick);
    let key = c.casemapping.fold("#x");
    c.channels.insert(key, crate::irc::ChannelState { name: "#x".into(), topic: String::new(), names: std::iter::once(nick).chain(members.iter().copied()).map(str::to_string).collect(), key: None });
    c
}

fn svc(test_loopback: bool, timeout: Duration) -> Arc<RemoteAvatars> {
    let dir = std::env::temp_dir().join(format!("cryptirc-remote-av-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    Arc::new(RemoteAvatars::with(dir, Arc::new(Semaphore::new(8)), Arc::new(DashMap::new()), "https://me.example/chat", test_loopback, timeout))
}

fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(w, h, image::Rgb([10, 200, 30])));
    let mut c = Cursor::new(Vec::new());
    img.write_to(&mut c, image::ImageFormat::Png).unwrap();
    c.into_inner()
}

fn waiter() -> Waiter {
    Waiter { owner: "viewer".into(), conn_id: "c1".into(), nick: "bob".into() }
}

#[derive(Clone)]
enum Reply {
    Body(&'static str, Vec<u8>, Option<&'static str>),
    Redirect(&'static str),
    Status(u16),
    Slow,
    NotModifiedIf(&'static str, Vec<u8>),
}

/// A tiny HTTP/1.1 server: `route(path)` decides the reply; every request path is recorded.
async fn http(route: impl Fn(&str) -> Reply + Send + Sync + 'static) -> (u16, Arc<std::sync::Mutex<Vec<String>>>, tokio::task::JoinHandle<()>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    let hits = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (h2, route) = (hits.clone(), Arc::new(route));
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let (h3, route) = (h2.clone(), route.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 2048];
                while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => buf.extend_from_slice(&tmp[..n]),
                    }
                }
                let head = String::from_utf8_lossy(&buf).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let inm = head.lines().find_map(|l| l.strip_prefix("If-None-Match: ").or_else(|| l.strip_prefix("if-none-match: "))).map(str::to_string);
                h3.lock().unwrap().push(path.clone());
                let out: Vec<u8> = match route(&path) {
                    Reply::Body(ct, body, etag) => {
                        let mut h = format!("HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n", ct, body.len());
                        if let Some(e) = etag {
                            h.push_str(&format!("ETag: {}\r\n", e));
                        }
                        h.push_str("\r\n");
                        let mut o = h.into_bytes();
                        o.extend_from_slice(&body);
                        o
                    }
                    Reply::NotModifiedIf(etag, body) => {
                        if inm.as_deref() == Some(etag) {
                            b"HTTP/1.1 304 Not Modified\r\nConnection: close\r\n\r\n".to_vec()
                        } else {
                            let mut o = format!("HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nETag: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", etag, body.len()).into_bytes();
                            o.extend_from_slice(&body);
                            o
                        }
                    }
                    Reply::Redirect(to) => format!("HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", to).into_bytes(),
                    Reply::Status(code) => format!("HTTP/1.1 {} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code).into_bytes(),
                    Reply::Slow => {
                        let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 100000\r\n\r\n").await;
                        for _ in 0..100 {
                            tokio::time::sleep(Duration::from_millis(200)).await;
                            if s.write_all(b"x").await.is_err() {
                                return;
                            }
                        }
                        return;
                    }
                };
                let _ = s.write_all(&out).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (port, hits, task)
}

async fn settle(r: &RemoteAvatars, url: &str) -> Status {
    for _ in 0..200 {
        let st = r.status(url);
        if st != Status::Pending {
            return st;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    r.status(url)
}

// ─── Line-level helpers ───────────────────────────────────────────────────────

#[test]
fn ctcp_avatar_requests_and_answers_are_recognised() {
    assert_eq!(ctcp_avatar("\u{1}AVATAR\u{1}"), Some(""));
    assert_eq!(ctcp_avatar("\u{1}avatar\u{1}"), Some(""));
    assert_eq!(ctcp_avatar("\u{1}AVATAR https://x.example/a.png 1234\u{1}"), Some("https://x.example/a.png 1234"));
    assert_eq!(reply_url("https://x.example/a.png 1234"), Some("https://x.example/a.png"));
    assert_eq!(ctcp_avatar("\u{1}AVATARS\u{1}"), None);
    assert_eq!(ctcp_avatar("\u{1}VERSION\u{1}"), None);
    assert_eq!(ctcp_avatar("AVATAR"), None);
}

#[test]
fn the_announce_tag_is_escaped_merged_and_dropped_when_too_long() {
    assert_eq!(escape_tag_value("a;b c\\d\r\n"), "a\\:b\\sc\\\\d\\r\\n");
    let url = "https://x.example/avatar/pub/aa-bb.png";
    assert_eq!(with_tag("PRIVMSG #a :hi", url).unwrap(), format!("@+cryptirc.com/avatar={} PRIVMSG #a :hi", url));
    assert_eq!(with_tag("@+draft/reply=1 PRIVMSG #a :hi", url).unwrap(), format!("@+draft/reply=1;+cryptirc.com/avatar={} PRIVMSG #a :hi", url));
    let own = "@+cryptirc.com/avatar=https://y.example/z.png TAGMSG #a";
    assert_eq!(with_tag(own, url).unwrap(), own, "a tag the user set is left alone");
    let big = format!("@+x={} PRIVMSG #a :hi", "v".repeat(4080));
    assert_eq!(with_tag(&big, url), None, "over the client tag limit: no tag (the caller sends the line as it was)");
    // The tag round-trips through the parser.
    let tagged = with_tag("PRIVMSG #a :hi", "https://x.example/a;b.png").unwrap();
    let (tags, rest) = tagged.split_once(' ').unwrap();
    let p = cryptirc::ircproto::parse_irc(&format!("{} :n!u@h {}", tags, rest));
    assert_eq!(p.tags.get(TAG_KEY).map(String::as_str), Some("https://x.example/a;b.png"));
}

#[test]
fn clienttagdeny_is_respected() {
    assert!(client_tag_allowed(None));
    assert!(client_tag_allowed(Some("draft/typing")));
    assert!(!client_tag_allowed(Some("*")));
    assert!(client_tag_allowed(Some("*,-cryptirc.com/avatar")));
    assert!(!client_tag_allowed(Some("cryptirc.com/avatar")));
    let isup = |t: &[&str]| clienttagdeny_from_isupport(&t.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(isup(&["me", "CLIENTTAGDENY=*,-draft/typing", "are supported"]), Some(Some("*,-draft/typing".into())));
    assert_eq!(isup(&["me", "-CLIENTTAGDENY"]), Some(None));
    assert_eq!(isup(&["me", "NETWORK=x"]), None);
    assert!(cap_list_has("sasl draft/metadata-2=before-connect,max-subs=100 echo-message", META_CAP));
    assert!(!cap_list_has("draft/metadata-3", META_CAP));
}

#[test]
fn announced_urls_must_be_public_https_and_not_this_instance() {
    let own = own_origin("https://me.example/chat");
    let ok = |u: &str| checked_url(u, own.as_ref(), false);
    assert_eq!(ok("https://friend.example/avatar/pub/a-b.png").as_deref(), Some("https://friend.example/avatar/pub/a-b.png"));
    assert_eq!(ok("https://Friend.Example./x.png#frag").as_deref(), Some("https://friend.example/x.png"));
    for bad in [
        "http://friend.example/x.png",
        "https://friend.example:8443/x.png",
        "https://user:pw@friend.example/x.png",
        "https://me.example/avatar/pub/a-b.png",
        "https://ME.example:443/other",
        "https://10.0.0.1/x.png",
        "https://127.0.0.1/x.png",
        "https://[::1]/x.png",
        "https://169.254.169.254/latest",
        "https://localhost/x.png",
        "https://printer.local/x.png",
        "https://intranet/x.png",
        "javascript:alert(1)",
        "data:image/png;base64,AAAA",
        "ftp://friend.example/x.png",
        "not a url",
        "",
    ] {
        assert_eq!(ok(bad), None, "{bad}");
    }
    assert_eq!(ok(&format!("https://friend.example/{}", "a".repeat(URL_MAX))), None, "too long");
    // Test mode: http and loopback with a port, but never this instance's own origin.
    let own_t = own_origin("http://127.0.0.1:28621/cryptirc");
    assert!(checked_url("http://127.0.0.1:28622/cryptirc/avatar/pub/a-b.png", own_t.as_ref(), true).is_some());
    assert!(checked_url("http://127.0.0.1:28621/cryptirc/avatar/pub/a-b.png", own_t.as_ref(), true).is_none());
    assert!(checked_url("http://10.1.2.3/x.png", own_t.as_ref(), true).is_none(), "private addresses stay refused");
}

#[test]
fn only_a_public_base_url_announces() {
    assert_eq!(announce_base("https://chat.example.org/cryptirc/", false).as_deref(), Some("https://chat.example.org/cryptirc"));
    for b in ["http://localhost:9000", "http://chat.example.org", "https://localhost", "https://192.168.1.5", "https://box.local", "nonsense"] {
        assert_eq!(announce_base(b, false), None, "{b}");
    }
    assert_eq!(announce_base("http://127.0.0.1:28621/cryptirc", true).as_deref(), Some("http://127.0.0.1:28621/cryptirc"));
}

fn tags(pairs: &[(&str, String)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
}
const NOW: i64 = 1_800_000_000;
const PLAIN: Arrival = Arrival { replayed: false, restricted: false };
const REPLAYED: Arrival = Arrival { replayed: true, restricted: false };
const RESTRICTED: Arrival = Arrival { replayed: false, restricted: true };
fn at(ago: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(NOW - ago, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[test]
fn announces_on_playback_are_ignored() {
    // A live line of a plain connection (not strict): no stamp = now.
    assert!(announce_is_fresh(&tags(&[]), NOW, PLAIN));
    assert!(announce_is_fresh(&tags(&[("time", at(5))]), NOW, PLAIN));
    assert!(!announce_is_fresh(&tags(&[("time", at(3600))]), NOW, PLAIN), "bouncer playback of an old line");
    assert!(!announce_is_fresh(&tags(&[("batch", "a1".into()), ("time", at(1))]), NOW, PLAIN), "inside a (playback) batch");
    assert!(announce_is_fresh(&tags(&[("time", "not a time".into())]), NOW, PLAIN));
    // Self-review (security review 2): fail closed for a replayed line or a bouncer
    // connection — a missing or unreadable stamp does not count there.
    assert!(!announce_is_fresh(&tags(&[]), NOW, REPLAYED), "strict: no stamp");
    assert!(!announce_is_fresh(&tags(&[("time", "not a time".into())]), NOW, REPLAYED), "strict: unreadable stamp");
    assert!(announce_is_fresh(&tags(&[("time", at(5))]), NOW, REPLAYED));
    // Stamps from the future beyond what irc.rs accepts (5 min) never count.
    assert!(!announce_is_fresh(&tags(&[("time", at(-3600))]), NOW, PLAIN), "an hour ahead");
    assert!(announce_is_fresh(&tags(&[("time", at(-60))]), NOW, PLAIN), "a minute ahead (clock skew)");
    assert!(!time_is_fresh(&tags(&[("time", at(-301))]), NOW, true));
    // Codex astra re-check M remote.rs:493 / irc.rs:1284: on a restricted connection (behind
    // a bouncer, or not classified) no unsolicited announce counts at all — no freshness
    // window tells playback from a live line.
    for t in [tags(&[("time", at(3))]), tags(&[("time", at(60))]), tags(&[])] {
        assert!(!announce_is_fresh(&t, NOW, RESTRICTED), "{t:?}");
        assert!(!announce_is_fresh(&t, NOW, Arrival { replayed: true, restricted: true }), "{t:?}");
    }
    assert!(announce_is_fresh(&tags(&[("time", at(60))]), NOW, PLAIN), "a plain connection keeps the 2-minute window");
}

#[test]
fn unknown_classification_counts_as_a_bouncer() {
    let mut c = conn("me");
    assert!(!restricted(&c), "negotiated, no bouncer");
    c.cap_ls_done = false;
    assert!(restricted(&c), "not classified (e.g. after a web restart that proved nothing)");
    c.cap_ls_done = true;
    c.behind_bouncer = true;
    assert!(restricted(&c), "behind a bouncer");
}

#[test]
fn restricted_connections_learn_no_remote_avatar_at_all() {
    // Codex astra re-check 2: like v1's bouncer exclusion — nothing, solicited or not.
    let r = svc(false, FETCH_TIMEOUT);
    let mut c = conn_in("me", &["bob", "erin"]);
    c.seen_userhosts.note("bob", "u@bob.host");
    c.seen_userhosts.note("erin", "e@erin.host");
    c.behind_bouncer = true;
    let url = "https://f.example/b.png";
    assert_eq!(learn_from_prefix(&mut c, &r, Some("bob!u@bob.host"), url, Source::Ctcp, "me"), None, "not even a CTCP answer");
    c.behind_bouncer = false;
    c.cap_ls_done = false;
    assert_eq!(learn_from_prefix(&mut c, &r, Some("bob!u@bob.host"), url, Source::Tag, "me"), None, "not classified");
    c.avx.batch_open("m1", "metadata", None);
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let erin = v(&["me", "erin", "avatar", "*", "https://f.example/e.png"]);
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "m1".into())]), &erin, "me", NOW, RESTRICTED), Some(None), "a GET answer / sync");
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[]), &erin, "me", NOW, RESTRICTED), Some(None), "a notification");
    assert_eq!(c.avx.bindings_len() + c.avx.held_len(), 0);
    // A deletion still applies (forgetting is safe).
    c.avx.learn("erin", Binding { url: url.into(), userhost: "e@erin.host".into(), source: Source::Meta, at: Instant::now() });
    assert_eq!(metadata_line(&mut c, &r, "766", &tags(&[]), &v(&["*", "erin", "avatar", "Key deleted"]), "me", NOW, RESTRICTED), Some(Some("erin".into())));
    // On a plain connection an answer to our CTCP query counts once, within the window,
    // from the user we asked; any answer (or NICK / QUIT / PART / KICK of that nick, or a
    // reconnect) voids the query.
    assert!(answer_matches(Some("u@bob.host"), "u@BOB.host"));
    assert!(!answer_matches(Some("u@bob.host"), "x@other.host"), "someone else answered");
    assert!(answer_matches(None, "u@bob.host"));
    assert_eq!(r.take_ctcp_answer("c1", "bob"), None, "never asked");
    r.note_ctcp_sent("c1", "Bob", Some("u@bob.host".into()));
    assert_eq!(r.take_ctcp_answer("c1", "bob"), Some(Some("u@bob.host".into())));
    assert_eq!(r.take_ctcp_answer("c1", "bob"), None, "once");
    r.note_ctcp_sent("c1", "bob", None);
    r.ctcp_pending.get_mut("c1\nbob").unwrap().0 = Instant::now().checked_sub(ANSWER_WINDOW + Duration::from_secs(1)).unwrap();
    assert_eq!(r.take_ctcp_answer("c1", "bob"), None, "too late");
    r.note_ctcp_sent("c1", "bob", None);
    r.forget_query("c1", "BOB");
    assert_eq!(r.take_ctcp_answer("c1", "bob"), None, "voided (NICK / QUIT / PART / KICK / negative answer)");
    r.note_ctcp_sent("c1", "bob", None);
    r.note_ctcp_sent("c2", "bob", None);
    r.forget_conn("c1");
    assert_eq!(r.take_ctcp_answer("c1", "bob"), None, "voided by reconnect / forget_conn");
    assert!(r.take_ctcp_answer("c2", "bob").is_some(), "another connection's query stays");
}

#[test]
fn metadata_never_binds_without_a_known_user_at_host() {
    // Codex astra re-check 2 M remote.rs:583: a value that arrives before the nick's
    // user@host is held (bounded, short-lived) and bound only when one is observed.
    let r = svc(false, FETCH_TIMEOUT);
    let mut c = conn_in("me", &["dave", "fred"]);
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "dave", "avatar", "*", "https://f.example/d.png"]), "me", NOW, PLAIN), Some(None));
    assert!(c.avx.binding("dave").is_none());
    assert_eq!(c.avx.held_len(), 1);
    assert!(promote_held(&mut c).is_empty(), "still no user@host");
    c.seen_userhosts.note("dave", "d@dave.host");   // NAMES with userhost-in-names, WHO, JOIN, WHOIS
    assert_eq!(promote_held(&mut c), vec!["dave".to_string()]);
    assert_eq!(c.avx.binding("dave").map(|b| b.userhost.as_str()), Some("d@dave.host"));
    assert_eq!(c.avx.held_len(), 0);
    // An old held value is dropped, never bound.
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "fred", "avatar", "*", "https://f.example/f.png"]), "me", NOW, PLAIN);
    c.avx.meta_held.get_mut("fred").unwrap().1 = Instant::now().checked_sub(META_HELD_TTL + Duration::from_secs(1)).unwrap();
    c.seen_userhosts.note("fred", "f@fred.host");
    assert!(promote_held(&mut c).is_empty());
    assert!(c.avx.binding("fred").is_none() && c.avx.held_len() == 0);
    // A deletion while held drops it; the hold is bounded.
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "fred", "avatar", "*", "https://f.example/f.png"]), "me", NOW, PLAIN);
    c.seen_userhosts.forget("fred");
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "fred", "avatar", "*", "https://f.example/f.png"]), "me", NOW, PLAIN);
    metadata_line(&mut c, &r, "766", &tags(&[]), &v(&["*", "fred", "avatar", "Key deleted"]), "me", NOW, PLAIN);
    assert_eq!(c.avx.held_len(), 0);
    let mut s = ConnState::default();
    for i in 0..(META_HELD_MAX + 20) {
        s.hold_meta(&format!("n{i}"), "https://f.example/x.png".into());
    }
    assert!(s.held_len() <= META_HELD_MAX);
}

/// Codex astra re-check 3 M irc.rs:1125 — the exact dispatch sequence: Bob's metadata is
/// held (no user@host yet), Bob is KICKed (no completed bindings on the connection), Bob
/// changes nick out of sight and a replacement JOINs as Bob with a new user@host: the held
/// value must never be bound to the replacement.
#[test]
fn a_held_value_never_outlives_its_nicks_departure() {
    let r = svc(false, FETCH_TIMEOUT);
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let kick = |c: &mut IrcConnection, nick: &str| {
        for ch in c.channels.values_mut() { ch.names.retain(|n| !n.eq_ignore_ascii_case(nick)); }   // irc.rs KICK / PART
        on_departure(c, Some(nick))
    };
    let join = |c: &mut IrcConnection, nick: &str, uh: &str| {
        for ch in c.channels.values_mut() { ch.names.push(nick.to_string()); }                     // irc.rs JOIN
        c.seen_userhosts.note(nick, uh);                                                          // observe_line
        promote_held(c)                                                                           // after the line
    };
    // KICK from the last shared channel.
    let mut c = conn_in("me", &["bob"]);
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "bob", "avatar", "*", "https://f.example/old-bob.png"]), "me", NOW, PLAIN);
    assert_eq!((c.avx.held_len(), c.avx.bindings_len()), (1, 0));
    assert!(kick(&mut c, "bob").is_empty());
    assert_eq!(c.avx.held_len(), 0, "KICK drops the held value");
    assert!(join(&mut c, "bob", "new@replacement.host").is_empty());
    assert!(c.avx.binding("bob").is_none(), "the replacement gets nothing");
    // Also when the nick still shares another channel (it may change while unseen there too
    // before its identity is known): any PART / KICK drops the held value.
    let mut c = conn_in("me", &["bob"]);
    let key = c.casemapping.fold("#y");
    c.channels.insert(key.clone(), crate::irc::ChannelState { name: "#y".into(), topic: String::new(), names: vec!["me".into(), "bob".into()], key: None });
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "bob", "avatar", "*", "https://f.example/old-bob.png"]), "me", NOW, PLAIN);
    c.channels.get_mut(&c.casemapping.fold("#x")).unwrap().names.retain(|n| n != "bob");
    on_departure(&mut c, Some("bob"));
    assert_eq!(c.avx.held_len(), 0);
    // QUIT / NICK / CHGHOST paths drop held values too.
    let mut c = conn_in("me", &["bob", "carl"]);
    for n in ["bob", "carl"] {
        metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", n, "avatar", "*", "https://f.example/x.png"]), "me", NOW, PLAIN);
    }
    c.avx.forget("bob");                 // QUIT / CHGHOST
    c.avx.renamed("carl", "carl2");      // NICK
    assert_eq!(c.avx.held_len(), 0);
    // Our own PART of the only shared channel drops everything held for nicks no longer seen.
    let mut c = conn_in("me", &["bob"]);
    metadata_line(&mut c, &r, "761", &tags(&[]), &v(&["*", "bob", "avatar", "*", "https://f.example/x.png"]), "me", NOW, PLAIN);
    c.channels.clear();
    on_departure(&mut c, None);
    assert_eq!(c.avx.held_len(), 0);
}

#[test]
fn metadata_sync_publishes_or_deletes() {
    // Codex astra re-check 2: whenever metadata-2 becomes active, our value is synced —
    // published when sharing, explicitly deleted otherwise.
    assert_eq!(meta_sync_line(Some("https://me.example/avatar/pub/a-b.png")), "METADATA * SET avatar :https://me.example/avatar/pub/a-b.png\r\n");
    assert_eq!(meta_sync_line(None), "METADATA * SET avatar\r\n");
}

#[test]
fn metadata_is_asked_for_again_after_an_unproven_reattach() {
    assert!(meta_recheck(true, true, true, false));
    assert!(!meta_recheck(false, true, true, false), "never had it");
    assert!(!meta_recheck(true, false, true, false), "state kept (continuity proven)");
    assert!(!meta_recheck(true, true, false, false), "not live: the next negotiation asks");
    assert!(!meta_recheck(true, true, true, true), "the network config disables it");
}

#[test]
fn ctcp_avatar_is_answered_only_on_live_fresh_direct_lines() {
    // Codex astra L irc.rs:1486: never for replayed or playback (batch / stale) requests.
    assert!(may_answer_ctcp(false, true, true, false, false));
    assert!(!may_answer_ctcp(true, true, true, false, false), "replayed");
    assert!(!may_answer_ctcp(false, false, true, false, false), "playback (batch or stale stamp)");
    assert!(!may_answer_ctcp(false, true, false, false, false), "to a channel");
    assert!(!may_answer_ctcp(false, true, true, true, false), "from ourselves");
    assert!(!may_answer_ctcp(false, announce_is_fresh(&tags(&[("batch", "h".into()), ("time", at(1))]), NOW, PLAIN), true, false, false));
    // Codex astra re-check L irc.rs:1487: never on a restricted connection.
    assert!(!may_answer_ctcp(false, true, true, false, true), "behind a bouncer / not classified");
}

#[test]
fn delayed_announces_are_checked_again_at_send_time() {
    // Codex astra L remote.rs:1123: a reconnect, a CLIENTTAGDENY change, a recipient who left
    // or changed host cancels a queued welcome / answer. (Sharing, the admin switch and the
    // account's state are checked again by announce_url in send_delayed.)
    let mut c = conn_in("me", &["joiner"]);
    c.message_tags = true;
    c.seen_userhosts.note("joiner", "j@host");
    let gen = c.resync_gen;
    assert!(delayed_send_ok(&c, gen, "joiner", Some("j@host"), Some("#x")));
    assert!(delayed_send_ok(&c, gen, "joiner", Some("j@host"), None));
    assert!(!delayed_send_ok(&c, gen + 1, "joiner", Some("j@host"), Some("#x")), "reconnected meanwhile");
    assert!(!delayed_send_ok(&c, gen, "joiner", Some("other@host"), Some("#x")), "another user now");
    assert!(!delayed_send_ok(&c, gen, "joiner", Some("j@host"), Some("#y")), "not in that channel");
    c.avx.client_tag_deny = Some("*".into());
    assert!(!delayed_send_ok(&c, gen, "joiner", Some("j@host"), Some("#x")), "CLIENTTAGDENY now refuses it");
    c.avx.client_tag_deny = None;
    c.message_tags = false;
    assert!(!delayed_send_ok(&c, gen, "joiner", Some("j@host"), Some("#x")), "message-tags gone");
    c.message_tags = true;
    for ch in c.channels.values_mut() { ch.names.retain(|n| n != "joiner"); }
    assert!(!delayed_send_ok(&c, gen, "joiner", Some("j@host"), Some("#x")), "left");
}

#[test]
fn open_batches_are_tracked_with_their_types() {
    let mut s = ConnState::default();
    s.batch_open("m1", "metadata", None);
    s.batch_open("h1", "chathistory", None);
    s.batch_open("m2", "metadata", Some("h1"));
    s.batch_open("m3", "metadata", Some("m1"));
    assert!(s.batch_is_metadata("m1") && s.batch_is_metadata("m3"));
    assert!(!s.batch_is_metadata("h1"), "playback");
    assert!(!s.batch_is_metadata("m2"), "a metadata batch nested in playback");
    assert!(!s.batch_is_metadata("unknown"));
    s.batch_close("m1");
    assert!(!s.batch_is_metadata("m1"));
    for i in 0..(BATCHES_MAX + 5) {
        s.batch_open(&format!("x{i}"), "metadata", None);
    }
    assert!(s.batches.len() <= BATCHES_MAX);
    s.reset();
    assert!(!s.batch_is_metadata("x70"));
}

// ─── Bindings ─────────────────────────────────────────────────────────────────

#[test]
fn bindings_follow_nick_quit_and_visibility() {
    let mut s = ConnState::default();
    let b = |src| Binding { url: "https://f.example/a.png".into(), userhost: "u@h".into(), source: src, at: Instant::now() };
    assert!(s.learn("Bob", b(Source::Tag)));
    assert!(!s.learn("bob", b(Source::Tag)), "the same announce again is no change");
    assert!(s.binding("BOB").is_some());
    // NICK: a tag / CTCP announce does not follow; metadata does; the new nick's old entry goes.
    assert!(s.learn("carol", b(Source::Tag)));
    assert!(s.renamed("bob", "carol"));
    assert!(s.binding("bob").is_none() && s.binding("carol").is_none());
    assert!(s.learn("dave", b(Source::Meta)));
    assert!(s.renamed("dave", "dave2"));
    assert!(s.binding("dave").is_none() && s.binding("dave2").is_some());
    assert!(!s.forget_meta("nobody"));
    assert!(s.learn("erin", b(Source::Ctcp)));
    assert!(!s.forget_meta("erin"), "a metadata deletion does not drop a CTCP announce");
    assert!(s.forget("erin"));
    let visible: HashSet<String> = ["dave2".to_string()].into_iter().collect();
    s.learn("frank", b(Source::Tag));
    assert_eq!(s.retain_visible(&visible), vec!["frank".to_string()]);
    assert_eq!(s.bindings_len(), 1);
    s.reset();
    assert_eq!(s.bindings_len(), 0);
}

#[test]
fn bindings_are_bounded() {
    let mut s = ConnState::default();
    for i in 0..(BINDINGS_MAX + 50) {
        s.learn(&format!("n{i}"), Binding { url: "https://f.example/a.png".into(), userhost: "u@h".into(), source: Source::Tag, at: Instant::now() });
    }
    assert_eq!(s.bindings_len(), BINDINGS_MAX);
}

#[test]
fn announces_come_only_from_users_never_servers_or_ourselves() {
    let r = svc(false, FETCH_TIMEOUT);
    let mut c = conn_in("me", &["@bob"]);
    let url = "https://friend.example/avatar/pub/a-b.png";
    assert_eq!(learn_from_prefix(&mut c, &r, Some("irc.server.example"), url, Source::Tag, "me"), None, "server source");
    assert_eq!(learn_from_prefix(&mut c, &r, None, url, Source::Tag, "me"), None);
    assert_eq!(learn_from_prefix(&mut c, &r, Some("ME!u@h"), url, Source::Tag, "me"), None, "our own line");
    assert_eq!(learn_from_prefix(&mut c, &r, Some("bob!u@h"), "http://friend.example/x.png", Source::Tag, "me"), None, "not https");
    assert_eq!(learn_from_prefix(&mut c, &r, Some("bob!u@h"), "https://me.example/avatar/pub/a-b.png", Source::Tag, "me"), None, "this instance");
    assert_eq!(learn_from_prefix(&mut c, &r, Some("stranger!u@h"), url, Source::Tag, "me"), None, "a nick this connection does not see");
    assert_eq!(learn_from_prefix(&mut c, &r, Some("bob!u@h"), url, Source::Tag, "me").as_deref(), Some("bob"));
    let b = c.avx.binding("bob").unwrap();
    assert_eq!((b.url.as_str(), b.userhost.as_str(), b.source), (url, "u@h", Source::Tag));
    // A fresh WHOIS makes a nick seen.
    c.whois_seen.note("stranger");
    assert_eq!(learn_from_prefix(&mut c, &r, Some("stranger!u@h"), url, Source::Ctcp, "me").as_deref(), Some("stranger"));
}

#[test]
fn metadata_lines_about_the_avatar_key_are_learned_and_consumed() {
    let r = svc(false, FETCH_TIMEOUT);
    let mut c = conn_in("me", &["bob", "carol", "dave"]);
    let v = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let none = HashMap::new();
    for (n, uh) in [("bob", "u@bob.host"), ("carol", "c@carol.host"), ("erin", "e@erin.host")] {
        c.seen_userhosts.note(n, uh);
    }
    // RPL_KEYVALUE (Ergo's notification form uses `*` as the client).
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &v(&["*", "bob", "avatar", "*", "https://f.example/b.png"]), "me", NOW, PLAIN), Some(Some("bob".into())));
    let b = c.avx.binding("bob").unwrap();
    assert_eq!((b.source, b.userhost.as_str()), (Source::Meta, "u@bob.host"));
    // The METADATA command form.
    assert_eq!(metadata_line(&mut c, &r, "METADATA", &none, &v(&["carol", "avatar", "*", "https://f.example/c.png"]), "me", NOW, PLAIN), Some(Some("carol".into())));
    // Deletion / key not set.
    assert_eq!(metadata_line(&mut c, &r, "766", &none, &v(&["*", "bob", "avatar", "Key deleted"]), "me", NOW, PLAIN), Some(Some("bob".into())));
    assert!(c.avx.binding("bob").is_none());
    assert_eq!(metadata_line(&mut c, &r, "METADATA", &none, &v(&["carol", "avatar", "*"]), "me", NOW, PLAIN), Some(Some("carol".into())));
    // Our own value, a channel's, a bad URL: consumed, nothing learned.
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &v(&["me", "me", "avatar", "*", "https://f.example/m.png"]), "me", NOW, PLAIN), Some(None));
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &v(&["me", "#chan", "avatar", "*", "https://f.example/m.png"]), "me", NOW, PLAIN), Some(None));
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &v(&["me", "dave", "avatar", "*", "http://10.0.0.1/x"]), "me", NOW, PLAIN), Some(None));
    assert!(c.avx.binding("dave").is_none());
    // Subscription replies and FAIL METADATA: consumed. Other keys / other FAILs: not ours.
    assert_eq!(metadata_line(&mut c, &r, "770", &none, &v(&["me", "avatar"]), "me", NOW, PLAIN), Some(None));
    assert_eq!(metadata_line(&mut c, &r, "774", &none, &v(&["*", "*ALL", "0", "later"]), "me", NOW, PLAIN), Some(None));
    assert_eq!(metadata_line(&mut c, &r, "FAIL", &none, &v(&["METADATA", "INVALID_TARGET", "x", "bad"]), "me", NOW, PLAIN), Some(None));
    assert_eq!(metadata_line(&mut c, &r, "FAIL", &none, &v(&["CHATHISTORY", "X", "bad"]), "me", NOW, PLAIN), None);
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &v(&["me", "bob", "url", "*", "https://f.example/"]), "me", NOW, PLAIN), None);
    assert_eq!(metadata_line(&mut c, &r, "770", &none, &v(&["me", "display-name"]), "me", NOW, PLAIN), None);
    // A nick not seen: only inside a metadata (sync / GET) batch.
    let erin = v(&["me", "erin", "avatar", "*", "https://f.example/e.png"]);
    assert_eq!(metadata_line(&mut c, &r, "761", &none, &erin, "me", NOW, PLAIN), Some(None));
    assert!(c.avx.binding("erin").is_none());
    // Self-review (security review 1): never inside a playback / history batch, nor a
    // metadata batch nested in one, nor with a stale stamp — only a real metadata batch.
    c.avx.batch_open("h1", "chathistory", None);
    c.avx.batch_open("z1", "znc.in/playback", None);
    c.avx.batch_open("m2", "metadata", Some("h1"));
    for b in ["h1", "z1", "m2", "unknown"] {
        assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", b.into())]), &erin, "me", NOW, PLAIN), Some(None), "{b}");
        assert!(c.avx.binding("erin").is_none(), "{b}");
    }
    // Not even for a seen nick inside a playback batch (an old value for a nick someone else
    // may hold now).
    let carol2 = v(&["me", "carol", "avatar", "*", "https://f.example/c2.png"]);
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "h1".into())]), &carol2, "me", NOW, PLAIN), Some(None));
    assert!(c.avx.binding("carol").is_none());
    c.avx.batch_open("m1", "metadata", None);
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "m1".into()), ("time", at(3600))]), &erin, "me", NOW, PLAIN), Some(None), "stale stamp");
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "m1".into())]), &erin, "me", NOW, REPLAYED), Some(None), "strict without a stamp");
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "m1".into()), ("time", at(3))]), &erin, "me", NOW, RESTRICTED), Some(None), "restricted: a push, even freshly stamped");
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("batch", "m1".into())]), &erin, "me", NOW, PLAIN), Some(Some("erin".into())));
    assert_eq!(metadata_line(&mut c, &r, "761", &tags(&[("time", at(3600))]), &carol2, "me", NOW, PLAIN), Some(None), "a seen nick, stale stamp");
}

// ─── Limits ───────────────────────────────────────────────────────────────────

#[test]
fn queries_answers_announces_and_welcomes_are_limited() {
    let r = svc(false, FETCH_TIMEOUT);
    // A query per nick per window; a few per viewer.
    assert!(r.probe_allowed("v", "c1", "Bob"));
    assert!(!r.probe_allowed("v", "c1", "bob"), "same nick again");
    for i in 1..PROBE_VIEWER_10MIN {
        assert!(r.probe_allowed("v", "c1", &format!("n{i}")));
    }
    assert!(!r.probe_allowed("v", "c1", "one-more"), "viewer budget used up");
    assert!(r.probe_allowed("w", "c2", "one-more"), "another viewer has its own");
    // A CTCP answer counts only after our query, once.
    assert!(r.take_ctcp_answer("c1", "bob").is_none());
    r.note_ctcp_sent("c1", "Bob", None);
    assert!(r.take_ctcp_answer("c1", "BOB").is_some());
    assert!(r.take_ctcp_answer("c1", "bob").is_none());
    // One answer per asker per window; a few per connection.
    assert!(r.reply_allowed("c1", "x!u@h"));
    assert!(!r.reply_allowed("c1", "x!u@h"));
    for i in 1..REPLY_PER_CONN_MIN {
        assert!(r.reply_allowed("c1", &format!("y{i}!u@h")));
    }
    assert!(!r.reply_allowed("c1", "z!u@h"));
    // Announces: first time, URL change, else not before ANNOUNCE_EVERY; forget_conn resets.
    assert!(r.announce_due("c1", "#a", "https://me.example/1.png"));
    assert!(!r.announce_due("c1", "#A", "https://me.example/1.png"));
    assert!(r.announce_due("c1", "#a", "https://me.example/2.png"));
    assert!(r.announce_due("c1", "#b", "https://me.example/2.png"));
    r.forget_conn("c1");
    assert!(r.announce_due("c1", "#a", "https://me.example/2.png"));
    // Welcomes: once per joiner per window, WELCOME_PER_CHANNEL_MIN per channel per minute.
    assert!(r.welcome_allowed("c1", "#a", "j0"));
    assert!(!r.welcome_allowed("c1", "#a", "J0"));
    for i in 1..WELCOME_PER_CHANNEL_MIN {
        assert!(r.welcome_allowed("c1", "#a", &format!("j{i}")));
    }
    assert!(!r.welcome_allowed("c1", "#a", "flood"), "per-channel cap");
    let mut more = 0;
    for i in 0..50 {
        if r.welcome_allowed("c1", &format!("#c{i}"), &format!("k{i}")) {
            more += 1;
        }
    }
    assert_eq!(more as u32, WELCOME_PER_CONN_MIN - WELCOME_PER_CHANNEL_MIN, "per-connection cap across channels");
    // A peer's announce is answered — not right after a welcome to it, once per window.
    let r = svc(false, FETCH_TIMEOUT);
    assert!(r.welcome_allowed("c1", "#a", "newbie"));
    assert!(!r.peer_reply_allowed("c1", "newbie"), "a welcome is already on its way");
    assert!(r.peer_reply_allowed("c1", "peer"));
    assert!(!r.peer_reply_allowed("c1", "PEER"), "once per window");
    r.cooldowns.insert(format!("w:c1\nold"), Instant::now().checked_sub(Duration::from_secs(120)).unwrap());
    assert!(r.peer_reply_allowed("c1", "old"), "an old welcome does not stop an answer (the peer lost us)");
    r.forget_target("c1", "#a");
}

// ─── Fetching ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_good_picture_is_fetched_once_reencoded_and_served() {
    let pic = png(300, 200);
    let (port, hits, _t) = http(move |_| Reply::Body("image/png", pic.clone(), Some("\"e1\""))).await;
    let r = svc(true, Duration::from_secs(5));
    let url = format!("http://127.0.0.1:{port}/a.png");
    assert!(r.start_fetch(&url, "viewer", waiter()));
    assert!(r.start_fetch(&url, "viewer", waiter()), "joins the fetch in flight");
    let Status::Ready { rid, v, host, refresh } = settle(&r, &url).await else { panic!("not ready") };
    assert_eq!((host.as_str(), refresh), ("127.0.0.1", false));
    assert_eq!(hits.lock().unwrap().len(), 1, "one request");
    let small = r.read_picture(&rid, &v, super::super::SIZE_SMALL).await.unwrap();
    let img = image::load_from_memory(&small).unwrap();
    assert_eq!((img.width(), img.height()), (48, 48));
    assert!(r.read_picture(&rid, "0000000000000000", 48).await.is_none(), "wrong version");
    assert!(r.read_picture(&"0".repeat(32), &v, 48).await.is_none(), "unknown id");
    // Fresh: a later view does not fetch again.
    assert!(matches!(r.status(&url), Status::Ready { refresh: false, .. }));
}

#[tokio::test]
async fn hostile_responses_are_refused_safely() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#.to_vec();
    let html = b"<!doctype html><html><body>hi</body></html>".to_vec();
    let big = {
        let mut b = png(8, 8);
        b.resize(3 * 1024 * 1024, 0);
        b
    };
    let huge = {
        // A valid PNG whose header claims 20000 × 20000 pixels.
        let mut p = png(8, 8);
        p[16..20].copy_from_slice(&20000u32.to_be_bytes());
        p[20..24].copy_from_slice(&20000u32.to_be_bytes());
        let crc = {
            let body = &p[12..29];
            let mut c = 0xFFFF_FFFFu32;
            for &b in body {
                c ^= b as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        };
        p[29..33].copy_from_slice(&crc.to_be_bytes());
        p
    };
    let good = png(64, 64);
    let (port, hits, _t) = http(move |path| match path {
        "/svg" => Reply::Body("image/svg+xml", svg.clone(), None),
        "/html" => Reply::Body("image/png", html.clone(), None),
        "/big" => Reply::Body("image/png", big.clone(), None),
        "/huge" => Reply::Body("image/png", huge.clone(), None),
        "/redir" => Reply::Redirect("/good"),
        "/loop" => Reply::Redirect("/loop"),
        "/gone" => Reply::Status(404),
        "/slow" => Reply::Slow,
        _ => Reply::Body("image/png", good.clone(), None),
    })
    .await;
    let r = svc(true, Duration::from_secs(2));
    for path in ["/svg", "/html", "/big", "/huge", "/redir", "/loop", "/gone", "/slow"] {
        let url = format!("http://127.0.0.1:{port}{path}");
        assert!(r.start_fetch(&url, "viewer", waiter()), "{path}");
        assert_eq!(settle(&r, &url).await, Status::Failed, "{path}");
    }
    assert!(!hits.lock().unwrap().iter().any(|p| p == "/good"), "a redirect is never followed");
    assert_eq!(hits.lock().unwrap().iter().filter(|p| p.as_str() == "/loop").count(), 1);
    // A failure is remembered: no new request until FAIL_TTL.
    assert_eq!(r.status(&format!("http://127.0.0.1:{port}/svg")), Status::Failed);
}

#[tokio::test]
async fn private_addresses_are_never_fetched_outside_the_test_mode() {
    let good = png(64, 64);
    let (port, hits, _t) = http(move |_| Reply::Body("image/png", good.clone(), None)).await;
    let r = svc(false, Duration::from_secs(2));
    for url in [format!("http://127.0.0.1:{port}/a.png"), "https://127.0.0.1/a.png".to_string(), "https://10.0.0.1/a.png".to_string(), "https://localhost/a.png".to_string()] {
        assert!(r.start_fetch(&url, "viewer", waiter()));
        assert_eq!(settle(&r, &url).await, Status::Failed, "{url}");
    }
    assert!(hits.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fetches_are_capped_per_host_and_per_viewer() {
    let (port, _hits, _t) = http(|_| Reply::Status(404)).await;
    let r = svc(true, Duration::from_secs(2));
    let mut started = 0;
    for i in 0..(FETCH_HOST_10MIN + 5) {
        if r.start_fetch(&format!("http://127.0.0.1:{port}/{i}"), &format!("v{i}"), waiter()) {
            started += 1;
        }
    }
    assert_eq!(started, FETCH_HOST_10MIN.min(FETCH_GLOBAL_MIN), "per remote host / process");
    // The per-host window on its own (the process window reset in between).
    let r2 = svc(true, Duration::from_secs(2));
    let mut host_started = 0;
    for i in 0..(FETCH_HOST_10MIN + 5) {
        r2.rates.remove("fg");
        if r2.start_fetch(&format!("http://127.0.0.1:{port}/h{i}"), &format!("v{i}"), waiter()) {
            host_started += 1;
        }
    }
    assert_eq!(host_started, FETCH_HOST_10MIN, "per remote host");
    let r = svc(true, Duration::from_secs(2));
    let mut started = 0;
    for i in 0..(FETCH_VIEWER_10MIN + 5) {
        // Different hosts (all of 127/8 is loopback, allowed in the test mode).
        if r.start_fetch(&format!("http://127.0.0.{}:{port}/{i}", 1 + (i % 200)), "one-viewer", waiter()) {
            started += 1;
        }
    }
    assert!(started <= FETCH_VIEWER_10MIN, "per viewer ({started})");
    let r3 = svc(true, Duration::from_secs(2));
    let mut viewer_started = 0;
    for i in 0..(FETCH_VIEWER_10MIN + 5) {
        r3.rates.remove("fg");
        if r3.start_fetch(&format!("http://127.0.0.{}:{port}/{i}", 1 + (i % 200)), "one-viewer", waiter()) {
            viewer_started += 1;
        }
    }
    assert_eq!(viewer_started, FETCH_VIEWER_10MIN, "per viewer");
}

#[tokio::test]
async fn a_stale_picture_is_revalidated_and_dropped_when_gone() {
    let pic = png(64, 64);
    let gone = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let g2 = gone.clone();
    let (port, hits, _t) = http(move |_| if g2.load(std::sync::atomic::Ordering::SeqCst) { Reply::Status(404) } else { Reply::NotModifiedIf("\"v1\"", pic.clone()) }).await;
    let r = svc(true, Duration::from_secs(5));
    let url = format!("http://127.0.0.1:{port}/a.png");
    assert!(r.start_fetch(&url, "viewer", waiter()));
    let Status::Ready { rid, v, .. } = settle(&r, &url).await else { panic!() };
    let age = |r: &RemoteAvatars| {
        r.entries.get_mut(&url).unwrap().at = Instant::now().checked_sub(OK_TTL + Duration::from_secs(1)).unwrap();
    };
    let done = |r: Arc<RemoteAvatars>, url: String| async move {
        for _ in 0..200 {
            if !r.entries.get(&url).unwrap().fetching {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    // 304: kept, same version, fresh again.
    age(&r);
    assert!(matches!(r.status(&url), Status::Ready { refresh: true, .. }));
    assert!(r.start_fetch(&url, "viewer", waiter()));
    assert!(matches!(r.status(&url), Status::Ready { refresh: false, .. }), "shown while it is revalidated");
    done(r.clone(), url.clone()).await;
    assert_eq!(r.status(&url), Status::Ready { rid: rid.clone(), v: v.clone(), host: "127.0.0.1".into(), refresh: false });
    // Gone (opt-out / removal at the source): no longer shown, files removed.
    gone.store(true, std::sync::atomic::Ordering::SeqCst);
    age(&r);
    assert!(r.start_fetch(&url, "viewer", waiter()));
    done(r.clone(), url.clone()).await;
    assert_eq!(r.status(&url), Status::Failed);
    assert!(r.read_picture(&rid, &v, 48).await.is_none());
    assert_eq!(hits.lock().unwrap().len(), 3);
}

#[tokio::test]
async fn the_cache_is_bounded() {
    let r = svc(true, Duration::from_secs(2));
    for i in 0..(CACHE_MAX_ENTRIES + 20) {
        let url = format!("http://f{}.example/a.png", i);
        r.entries.insert(url.clone(), Entry { rid: r.rid(&url), host: "f".into(), ready_v: None, etag: None, fetching: false, failed: true, at: Instant::now(), fetch_started: Instant::now() });
    }
    r.evict();
    assert_eq!(r.entry_count(), CACHE_MAX_ENTRIES);
}
