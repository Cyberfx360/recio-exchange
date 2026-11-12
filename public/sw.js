// AZAPLUG service worker: shows push notifications and opens the app when one is tapped.
// It does not cache pages, so the app always loads fresh from the server.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('push', e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) { d = { body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'AZAPLUG', {
    body: d.body || '', icon: '/icon-192.png', badge: '/icon-192.png', data: { go: d.go || 'notifications' }
  }));
});

self.addEventListener('notificationclick', e => {
  e.notification.close();
  const go = (e.notification.data && e.notification.data.go) || 'notifications';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
    const open = list.find(c => c.url.indexOf('/app.html') !== -1);
    if (open) { open.postMessage({ go }); return open.focus(); }
    return self.clients.openWindow('/app.html#' + go);
  }));
});
