// CryptIRC Service Worker v9
// Handles: offline caching, push notifications, notification click actions

const CACHE = 'cryptirc-v157';
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
    requireInteraction: false,
    data: {
      conn_id: payload.conn_id || '',
      target:  payload.target  || '',
      from:    payload.from    || '',
      url:     self.location.origin + '/cryptirc/',
    },
    actions: [
      { action: 'open',    title: 'Open' },
      { action: 'dismiss', title: 'Dismiss' },
    ],
  };

  e.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// ─── Notification click ───────────────────────────────────────────────────────
self.addEventListener('notificationclick', e => {
  e.notification.close();

  if (e.action === 'dismiss') return;

  const data    = e.notification.data || {};
  const target  = encodeURIComponent(data.conn_id + '/' + data.target);
  const openUrl = data.url + (data.conn_id ? `?open=${target}` : '');

  e.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(clients => {
        // Focus an existing tab if one is open
        for (const client of clients) {
          if (client.url.startsWith(self.location.origin) && 'focus' in client) {
            client.postMessage({ type: 'notification_click', conn_id: data.conn_id, target: data.target });
            return client.focus();
          }
        }
        // Otherwise open a new window
        if (self.clients.openWindow) {
          return self.clients.openWindow(openUrl);
        }
      })
  );
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
