// Cawala service worker.
//
// The `__BUILD_ID__` placeholder is replaced at build time by
// web/scripts/stamp-sw.mjs (invoked from the `build` npm script), so every
// deploy gets a fresh cache name: `install` re-populates the shell and
// `activate` purges the previous cache. This is what prevents a stale cached
// shell from pinning users to an old build.
//
// Strategy:
//   - navigations: network-first (so a new index.html + its hashed assets win),
//     falling back to the cached shell when offline.
//   - other same-origin GETs: stale-while-revalidate.
//   - cross-origin requests (relays, discovery): not intercepted.
const BUILD_ID = '__BUILD_ID__';
const CACHE = `cawala-${BUILD_ID}`;
const SHELL = ['./', './index.html', './manifest.webmanifest'];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;

  const url = new URL(request.url);
  // Let cross-origin traffic (iroh relays / pkarr discovery) go straight to the
  // network; only manage our own app shell and assets.
  if (url.origin !== self.location.origin) return;

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const copy = response.clone();
          caches.open(CACHE).then((cache) => cache.put('./index.html', copy));
          return response;
        })
        .catch(() =>
          caches
            .match('./index.html')
            .then((cached) => cached || caches.match('./')),
        ),
    );
    return;
  }

  event.respondWith(
    caches.match(request).then((cached) => {
      const network = fetch(request)
        .then((response) => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => cached);
      return cached || network;
    }),
  );
});
