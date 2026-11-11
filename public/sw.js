const CACHE_NAME = 'arthur-ssh-pwa-v1';
const ASSETS = [
  '/ssh',
  '/ssh/icon.svg',
  '/ssh/manifest.webmanifest'
];

self.addEventListener('install', event => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then(cache => cache.addAll(ASSETS).catch(() => {}))
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET') return;
  if (event.request.url.includes('/api/') || event.request.url.includes('/ws')) return;
  event.respondWith(
    fetch(event.request).catch(() => caches.match(event.request))
  );
});
