// AZAPLUG service worker: shows push notifications and opens the right app when one is tapped.
// It does not cache pages, so the apps always load fresh from the server.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

const windows = () => self.clients.matchAll({ type: 'window', includeUncontrolled: true });

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { body: e.data ? e.data.text() : '' }; }
  const app = d.app || '/app.html';
  e.waitUntil(Promise.all([
    self.registration.showNotification(d.title || 'AZAPLUG', {
      body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png', data: { go: d.go || '', app }
    }),
    // Tell any open copy of that app to refresh, so counts and lists update straight away.
    windows().then(list => list.filter(c => c.url.indexOf(app) !== -1).forEach(c => c.postMessage({ refresh: true })))
  ]));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const data = e.notification.data || {}, app = data.app || '/app.html', go = data.go || '';
  e.waitUntil(windows().then(list => {
    const open = list.find(c => c.url.indexOf(app) !== -1);
    if (open) { open.postMessage({ go }); return open.focus(); }
    return self.clients.openWindow(app + (go ? '#' + go : ''));
  }));
});
