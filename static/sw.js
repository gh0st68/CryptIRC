// CryptIRC Service Worker v9
// Handles: offline caching, push notifications, notification click actions

const CACHE = 'cryptirc-v110';
const STATIC = ['/cryptirc/', '/cryptirc/manifest.json', '/cryptirc/icon.svg'];

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

// ─── Fetch (cache-first for statics) ─────────────────────────────────────────
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  // Skip API calls
  if (['/cryptirc/ws', '/cryptirc/auth', '/cryptirc/upload', '/cryptirc/files', '/cryptirc/push'].some(p =>
      url.pathname.startsWith(p))) return;

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
    icon:              '/cryptirc/icon.svg',
    badge:             '/cryptirc/icon.svg',
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
