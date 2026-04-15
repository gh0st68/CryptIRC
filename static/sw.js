// CryptIRC Service Worker v9
// Handles: offline caching, push notifications, notification click actions

const CACHE = 'cryptirc-v203';
const STATIC = ['/cryptirc/manifest.json', '/cryptirc/icon.svg', '/cryptirc/icon-192.png', '/cryptirc/icon-512.png'];

// ─── Install ──────────────────────────────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(STATIC))
      .then(() => self.skipWaiting())
  );
});

// ─── Activate ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(
        keys.filter(k => k !== CACHE).map(k => caches.delete(k))
      ))
      .then(() => self.clients.claim())
  );
});

// ─── Fetch (network-first for HTML, cache-first for static assets) ───────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Skip API calls entirely
  if (['/cryptirc/ws', '/cryptirc/auth', '/cryptirc/upload', '/cryptirc/files', '/cryptirc/push', '/cryptirc/pub'].some(p =>
      url.pathname.startsWith(p))) return;

  // Main HTML page — always network-first so deploys take effect immediately
  if (url.pathname === '/cryptirc/' || url.pathname === '/cryptirc') {
    e.respondWith(
      fetch(e.request).then(res => {
        if (res.ok) { const c = res.clone(); caches.open(CACHE).then(cache => cache.put(e.request, c)); }
        return res;
      }).catch(() => caches.match(e.request))
    );
    return;
  }

  // Other static assets — cache-first
  e.respondWith(
    caches.match(e.request).then(r => {
      if (r) return r;
      return fetch(e.request).then(res => {
        if (res.ok && STATIC.includes(url.pathname)) {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      });
    })
  );
});

// ─── Push notification received ───────────────────────────────────────────────
self.addEventListener('push', e => {
  if (!e.data) return;

  let payload;
  try {
    payload = e.data.json();
  } catch {
    payload = { title: 'CryptIRC', body: e.data.text() };
  }

  const title   = payload.title  || 'CryptIRC';
  const options = {
    body:              payload.body  || '',
    icon:              '/cryptirc/icon-192.png',
    badge:             '/cryptirc/icon-192.png',
    tag:               payload.tag   || 'cryptirc-default',
    renotify:          true,
    vibrate:           [150, 50, 150],
    silent:            false,
    requireInteraction: true,
    data: {
      conn_id: payload.conn_id || '',
      target:  payload.target  || '',
      from:    payload.from    || '',
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
      const focused = clients.some(c => c.visibilityState === 'visible');
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
  const target  = encodeURIComponent(data.conn_id + '/' + data.target);
  const qs      = [];
  if (data.conn_id) qs.push(`open=${target}`);
  if (data.ts)      qs.push(`ts=${encodeURIComponent(data.ts)}`);
  if (data.from)    qs.push(`from=${encodeURIComponent(data.from)}`);
  const openUrl = data.url + (qs.length ? `?${qs.join('&')}` : '');

  const payload = {
    type:    'notification_click',
    conn_id: data.conn_id,
    target:  data.target,
    ts:      data.ts,
    from:    data.from,
  };

  e.waitUntil((async () => {
    // Write intent to Cache API as a fallback bridge — client reads this on
    // startup in case postMessage is lost (iOS PWA wake races, etc.)
    try {
      const cache = await caches.open('cryptirc-notif-intent');
      const body = JSON.stringify({ ...payload, t: Date.now() });
      await cache.put('/__notif_click__', new Response(body, {
        headers: { 'Content-Type': 'application/json' },
      }));
    } catch (err) { /* non-fatal */ }

    const clientsList = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });

    // Try to focus an existing same-origin client
    for (const client of clientsList) {
      if (client.url.startsWith(self.location.origin)) {
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
    }).then(sub => {
      // Notify the client app to re-register
      return self.clients.matchAll().then(clients => {
        clients.forEach(c => c.postMessage({
          type: 'push_resubscribe',
          subscription: sub.toJSON(),
        }));
      });
    }).catch(() => {})
  );
});
