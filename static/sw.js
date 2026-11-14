// CryptIRC Service Worker v12
// Handles: offline caching, push notifications, notification click actions

// v210: navigations are cached under ONE normalised key (no query string), so the
// v209 cache — which held a copy of index.html per notification-click / pop-out URL,
// incl. ?target=<nick>&from=<nick> DM metadata — is dropped on activate.
const CACHE = 'cryptirc-v210';
// The single cache key for the app shell. Every navigation (/cryptirc, /cryptirc/,
// /cryptirc/?conn=…&target=…, /cryptirc/?detached=1) serves the same index.html.
const NAV_KEY = '/cryptirc/';
// notif-intent cache: a fallback bridge that stores a single notification-click
// intent so the client can read it on startup if postMessage is lost. It stores
// only minimal opaque IDs (conn_id/target/from/ts) — no auth material (audit #75).
const NOTIF_INTENT_CACHE = 'cryptirc-notif-intent';
// push-resub bridge: when the browser rotates the push subscription in the
// background (pushsubscriptionchange) with no app window open, the SW cannot reach
// the server (no auth token lives here). We stash the NEW subscription JSON here so
// the client re-registers it on its next startup — otherwise the server keeps the
// stale endpoint (410-pruned) and never learns the new one → push silently dies
// until a full re-enable. Holds the browser-issued subscription (endpoint +
// p256dh/auth push keys) — same material getSubscription() already exposes to any
// same-origin script, NOT the session token. Same-origin/per-profile like the push
// store itself, so no new exposure. Whitelisted in `activate` so a version bump
// doesn't drop a pending one; the client deletes it right after re-registering.
const PUSH_RESUB_CACHE = 'cryptirc-push-resub';
const STATIC = ['/cryptirc/manifest.json', '/cryptirc/icon.svg', '/cryptirc/icon-192.png', '/cryptirc/icon-512.png'];

// Only cache first-party, non-redirected, 200 responses. This rejects opaque
// (cross-origin/no-cors) and proxy-injected responses that could poison the
// cache (audit #74).
function isCacheable(res) {
  return res && res.ok && res.type === 'basic' && !res.redirected && res.status === 200;
}
// App scripts: needed for an offline launch to actually boot (audit #95). Served
// network-first with a cache fallback so online deploys always take effect immediately
// while a cached copy remains available offline.
const APP_SCRIPTS = ['/cryptirc/app.js', '/cryptirc/e2e.js', '/cryptirc/Sortable.min.js'];

// ─── Install ──────────────────────────────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(async c => {
        await c.addAll(STATIC);
        // Precache app scripts so the PWA can boot offline (audit #95). Best-effort:
        // a single failing script must not abort the whole install.
        await Promise.all(APP_SCRIPTS.map(p => c.add(p).catch(() => {})));
      })
      .then(() => self.skipWaiting())
  );
});

// ─── Activate ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', e => {
  // Whitelist of caches that survive a version bump. The notif-intent cache is
  // explicitly managed here so it is no longer an orphan that survives forever
  // outside version control (audit #75).
  const KEEP = [CACHE, NOTIF_INTENT_CACHE, PUSH_RESUB_CACHE];
  // r4 (codex-p3 LOW sw.js:62): CacheStorage belongs to the whole ORIGIN, not to this
  // worker's scope — another app on the same host (e.g. a PWA under /notes/) shares it.
  // Only CryptIRC's own caches are dropped: every cache any CryptIRC version created is
  // named 'cryptirc-…' (cryptirc-v4 … cryptirc-v210, -notif-intent, -push-resub).
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => typeof k === 'string' && k.startsWith('cryptirc-') && !KEEP.includes(k)).map(k => caches.delete(k))
      ))
      .then(() => pruneQueryEntries())
      .then(() => self.clients.claim())
  );
});

// Drop any cached entry whose URL carries a query string (navigation copies keyed
// on ?conn=…&target=…). Nothing current writes them; this is a belt-and-braces
// sweep so they can never accumulate again even without a CACHE bump.
async function pruneQueryEntries() {
  try {
    const c = await caches.open(CACHE);
    const reqs = await c.keys();
    await Promise.all(reqs.filter(r => { try { return new URL(r.url).search !== ''; } catch { return false; } })
      .map(r => c.delete(r)));
  } catch (err) { /* non-fatal */ }
}

// Allow the app to clear the notif-intent bridge on logout (audit #75), and sweep
// any query-string navigation copies while at it.
self.addEventListener('message', e => {
  if (e.data && e.data.type === 'clear_notif_intent') {
    e.waitUntil(Promise.all([caches.delete(NOTIF_INTENT_CACHE), pruneQueryEntries()]));
  }
});

// ─── Fetch (network-first for HTML, cache-first for static assets) ───────────
self.addEventListener('fetch', e => {
  // r6 (agy-flash sw.js:97): only GETs of the app's own page, scripts and cached static
  // files are handled here. Everything else (POST/PUT/DELETE, API routes, previews, pastes,
  // admin calls, other origins) goes straight to the network as if there were no service
  // worker — it used to be proxied, and on a network failure it got a synthetic
  // "503 Offline" text reply (callers expecting JSON then failed on parsing) instead of the
  // network error they handle. Nothing dynamic was ever cached.
  if (e.request.method !== 'GET') return;
  const url = new URL(e.request.url);
  // Skip API calls entirely
  if (['/cryptirc/ws', '/cryptirc/auth', '/cryptirc/upload', '/cryptirc/files', '/cryptirc/push', '/cryptirc/pub'].some(p =>
      url.pathname.startsWith(p))) return;

  // Main HTML page — always network-first so deploys take effect immediately.
  // On failure fall back to cache, and if nothing is cached synthesize an offline
  // Response so we never resolve to undefined / a blank document (audit #136).
  if (url.pathname === '/cryptirc/' || url.pathname === '/cryptirc') {
    // Store/look up under NAV_KEY, never the full request URL: keying on the URL
    // stored a ~300 KB copy per distinct query string (unbounded, and it kept DM
    // metadata after logout), and offline a notification-click URL missed the
    // cache and showed a bare "Offline" page instead of booting the app.
    e.respondWith(
      fetch(e.request).then(res => {
        if (isCacheable(res)) { const c = res.clone(); caches.open(CACHE).then(cache => cache.put(NAV_KEY, c)); }
        return res;
      }).catch(async () => (await caches.match(NAV_KEY)) || (await caches.match(e.request, { ignoreSearch: true })) || offlineResponse())
    );
    return;
  }

  // App scripts — network-first so deploys take effect immediately, but fall back
  // to the cached copy when offline so the PWA can still boot (audit #95). If
  // neither is available, synthesize an offline Response (audit #136).
  if (APP_SCRIPTS.includes(url.pathname)) {
    e.respondWith(
      fetch(e.request).then(res => {
        if (isCacheable(res)) { const c = res.clone(); caches.open(CACHE).then(cache => cache.put(e.request, c)); }
        return res;
      }).catch(async () => (await caches.match(e.request)) || offlineResponse())
    );
    return;
  }

  if (url.origin !== self.location.origin || !STATIC.includes(url.pathname)) return;   // r6: not ours to cache
  // Other static assets — stale-while-revalidate: serve the cached copy
  // immediately (fast, offline-capable) but always kick off a background fetch
  // to refresh the cache, so a bad/stale cache fill self-heals on the next load
  // instead of being pinned forever (audit #73).
  e.respondWith(
    caches.match(e.request).then(cached => {
      const network = fetch(e.request).then(res => {
        if (isCacheable(res) && STATIC.includes(url.pathname)) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      }).catch(() => cached || offlineResponse());
      return cached || network;
    })
  );
});

// Synthesized response for the network-first paths when there is nothing cached,
// so respondWith never resolves to undefined (which renders a blank doc offline).
function offlineResponse() {
  return new Response('Offline', {
    status: 503,
    statusText: 'Service Unavailable',
    headers: { 'Content-Type': 'text/plain' },
  });
}

// ─── Push notification received ───────────────────────────────────────────────
self.addEventListener('push', e => {
  if (!e.data) return;

  let payload;
  try {
    payload = e.data.json();
  } catch {
    payload = { title: 'CryptIRC', body: e.data.text() };
  }

  // The push payload is attacker-influenceable, so clamp the visible strings and
  // do NOT honour an attacker-chosen tag. Clamp title<=100 / body<=300 chars and
  // derive a stable, deterministic tag from conn_id+target so a flood of messages
  // for the same conversation coalesces into one notification instead of stacking
  // up an unbounded pile (audit #76).
  const clamp = (v, n) => String(v == null ? '' : v).slice(0, n);

  const conn_id = clamp(payload.conn_id, 200);
  const target  = clamp(payload.target,  200);

  const title   = clamp(payload.title || 'CryptIRC', 100);
  const tag     = 'cryptirc:' + conn_id + ':' + target;
  const options = {
    body:              clamp(payload.body, 300),
    icon:              '/cryptirc/icon-192.png',
    badge:             '/cryptirc/icon-192.png',
    tag:               tag,
    // renotify so a new message in an already-notified conversation still alerts,
    // but requireInteraction is off so coalesced floods auto-dismiss and don't
    // pin a permanent banner (audit #76).
    renotify:          true,
    vibrate:           [150, 50, 150],
    silent:            false,
    requireInteraction: false,
    data: {
      conn_id: conn_id,
      target:  target,
      from:    clamp(payload.from, 200),
      ts:      payload.ts      || 0,
      url:     self.location.origin + '/cryptirc/',
    },
    actions: [
      { action: 'open',    title: 'Open' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  e.waitUntil(
    // Only show notification if no client window is focused
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clients => {
      const focused = clients.some(c => {
        try { const u = new URL(c.url); return u.origin === self.location.origin &&
          (u.pathname === '/cryptirc' || u.pathname.startsWith('/cryptirc/')) &&
          c.visibilityState === 'visible' && c.focused; } catch { return false; }
      });
      if (!focused) {
        return self.registration.showNotification(title, options);
      }
    })
  );
});

// ─── Notification click ───────────────────────────────────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();

  if (e.action === 'dismiss') return;

  const data    = e.notification.data || {};
  // Only ever open our own app URL. Notifications shown without data.url (e.g. the
  // diagnostic SW test) used to open '/cryptirc/undefined'.
  let baseUrl = self.location.origin + '/cryptirc/';
  try { if (data.url && new URL(data.url).origin === self.location.origin) baseUrl = data.url; } catch (err) {}
  // Build the open URL by passing conn_id and target as SEPARATE, individually
  // URL-encoded query params instead of '/'-joining them. Joining was unsafe: a
  // '/' inside conn_id or target could shift the boundary between the two fields
  // (audit #77). app.js must read these distinct params.
  //
  // notificationclick query-param format (app.js must match):
  //   ?conn=<encodeURIComponent(conn_id)>&target=<encodeURIComponent(target)>
  //    [&ts=<ts>][&from=<encodeURIComponent(from)>]
  const qs      = [];
  if (data.conn_id) qs.push(`conn=${encodeURIComponent(data.conn_id)}`);
  if (data.target)  qs.push(`target=${encodeURIComponent(data.target)}`);
  if (data.ts)      qs.push(`ts=${encodeURIComponent(data.ts)}`);
  if (data.from)    qs.push(`from=${encodeURIComponent(data.from)}`);
  const openUrl = baseUrl + (qs.length ? `?${qs.join('&')}` : '');

  // `t` tags this click: the page deletes the cache-bridge entry carrying the same
  // `t` once the postMessage arrives (extra field — older pages ignore it).
  const clickT = Date.now();
  const payload = {
    type:    'notification_click',
    conn_id: data.conn_id,
    target:  data.target,
    ts:      data.ts,
    from:    data.from,
    t:       clickT,
  };

  e.waitUntil((async () => {
    // Write intent to Cache API as a fallback bridge — client reads this on
    // startup in case postMessage is lost (iOS PWA wake races, etc.)
    try {
      const cache = await caches.open(NOTIF_INTENT_CACHE);
      const body = JSON.stringify({ ...payload, t: clickT });
      await cache.put('/__notif_click__', new Response(body, {
        headers: { 'Content-Type': 'application/json' },
      }));
    } catch (err) { /* non-fatal */ }

    const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
    // Prefer a focused, then a visible, main window. A ?detached=1 pop-out is a
    // single-conversation view and must not be navigated by a notification click,
    // so it is skipped (a main window is opened instead if none exists).
    const rank = c => (c.focused ? 0 : 2) + (c.visibilityState === 'visible' ? 0 : 1);
    clientsList.sort((a, b) => rank(a) - rank(b));

    // Try to focus an existing same-origin client. Compare parsed origins rather
    // than startsWith(origin), which could match a malicious lookalike origin
    // (e.g. https://evil.example.com.attacker.test) (audit #135).
    for (const client of clientsList) {
      let sameOrigin = false;
      try { const u = new URL(client.url); sameOrigin = u.origin === self.location.origin &&
        (u.pathname === '/cryptirc' || u.pathname.startsWith('/cryptirc/')) &&
        u.searchParams.get('detached') !== '1'; } catch (err) {}
      if (sameOrigin) {
        try { client.postMessage(payload); } catch (err) {}
        if ('focus' in client) {
          try { return await client.focus(); } catch (err) {}
        }
      }
    }
    // No existing client — open a new window at the URL with nav params
    if (self.clients.openWindow) {
      try { return await self.clients.openWindow(openUrl); } catch (err) {}
    }
  })());
});

// ─── Push subscription change (browser revoked permission) ───────────────────
self.addEventListener('pushsubscriptionchange', e => {
  // Re-subscribe and update the server
  e.waitUntil(
    self.registration.pushManager.subscribe({
      userVisibleOnly:      true,
      applicationServerKey: e.oldSubscription
        ? e.oldSubscription.options.applicationServerKey
        : null,
    }).then(async sub => {
      // Stash the new subscription in the resub bridge FIRST, so it survives even if
      // no window is open to receive the postMessage below. The client drains this on
      // its next startup and re-registers with the server (audit #2: rotation gap).
      try {
        const c = await caches.open(PUSH_RESUB_CACHE);
        await c.put('/__push_resub__', new Response(JSON.stringify(sub.toJSON()), {
          headers: { 'Content-Type': 'application/json' },
        }));
      } catch (err) { /* non-fatal — postMessage path below still covers open clients */ }
      // Notify any open client app to re-register immediately (fast path).
      return self.clients.matchAll().then(clients => {
        clients.forEach(c => c.postMessage({
          type: 'push_resubscribe',
          subscription: sub.toJSON(),
        }));
      });
    }).catch(err => {
      // Re-subscribe failed (e.g. permission revoked). Don't swallow it silently —
      // tell the clients so the app can surface the lost-push state and prompt the
      // user to re-enable notifications (audit #136).
      return self.clients.matchAll().then(clients => {
        clients.forEach(c => c.postMessage({
          type: 'push_resubscribe_failed',
          error: String(err && err.message ? err.message : err),
        }));
      }).catch(() => {});
    })
  );
});
