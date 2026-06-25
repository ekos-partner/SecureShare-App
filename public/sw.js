const CACHE_NAME = 'secureshare-v1';
const ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon.svg',
  '/icon-maskable.svg'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Pre-caching offline pages');
      return cache.addAll(ASSETS);
    }).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            console.log('[Service Worker] Removing old cache', key);
            return caches.delete(key);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  const url = new URL(req.url);

  // Skip API requests and external telemetry, we don't want to cache dynamic secret endpoints
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Network-First for navigation and root documents to prevent loading old asset references
  if (req.mode === 'navigate' || url.pathname === '/' || url.pathname === '/index.html') {
    event.respondWith(
      fetch(req)
        .then((networkResponse) => {
          if (networkResponse && networkResponse.status === 200 && req.method === 'GET') {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(req, responseToCache);
            });
          }
          return networkResponse;
        })
        .catch(() => {
          return caches.match('/');
        })
    );
    return;
  }

  // Cache-first for static files and web app shell (images, assets, etc.)
  event.respondWith(
    caches.match(req).then((cachedResponse) => {
      if (cachedResponse) {
        // Fetch fresh copy in background to keep it updated (Stale-While-Revalidate)
        if (navigator.onLine) {
          fetch(req).then((networkResponse) => {
            if (networkResponse.status === 200) {
              caches.open(CACHE_NAME).then((cache) => cache.put(req, networkResponse));
            }
          }).catch(() => {/* Ignore network errors on background update */});
        }
        return cachedResponse;
      }

      // If not in cache, fallback to network
      return fetch(req).then((networkResponse) => {
        // Only cache successful standard responses
        if (networkResponse && networkResponse.status === 200 && req.method === 'GET') {
          const responseToCache = networkResponse.clone();
          caches.open(CACHE_NAME).then((cache) => {
            cache.put(req, responseToCache);
          });
        }
        return networkResponse;
      }).catch(() => {
        // If offline and request is document/page navigation, return cached index.html
        if (req.mode === 'navigate') {
          return caches.match('/');
        }
      });
    })
  );
});
