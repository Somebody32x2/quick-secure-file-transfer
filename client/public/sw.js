/**
 * QSFT service worker.
 *
 * Purpose: make the app installable and let the shell start without a network
 * round trip. It is deliberately narrow, because a service worker on a
 * cryptography tool is a persistent, privileged thing.
 *
 * Rules it will not break:
 *
 *   1. Nothing under /api/ is ever cached or served from cache. That path
 *      carries ciphertext, upload tokens, and code lookups. A cached blob would
 *      outlive the "delete after reading" guarantee the server just honoured,
 *      which would quietly turn a burn-after-read transfer into a stored copy.
 *   2. /socket.io/ is never touched. Live payload frames pass through there.
 *   3. Only same-origin GET requests are considered at all.
 *   4. Only status-200 basic responses are stored - never opaque or error ones.
 *
 * Update policy: a new worker does NOT take over automatically. Swapping the
 * cryptographic code out from under a page is not something to do silently, so
 * the new version waits and the page offers the user a reload.
 *
 * Note that hashed asset filenames mean an app update propagates without this
 * file changing: index.html is fetched network-first, and the new asset URLs it
 * references simply miss the cache and are fetched fresh.
 */

const VERSION = 'qsft-v1';

/**
 * Where this deployment is mounted, derived from the worker's own URL:
 * "/sw.js" gives "/", "/filetransfer/sw.js" gives "/filetransfer/". This file is
 * copied verbatim by the bundler, so it cannot read the build-time base and
 * works it out at runtime instead. A worker can only control paths at or below
 * its own URL, so this is exactly the scope it has anyway.
 */
const BASE = self.location.pathname.replace(/sw\.js$/, '') || '/';

// Cache is keyed by mount point too, so two deployments on one origin cannot
// collide.
const SHELL_CACHE = `${VERSION}-shell${BASE === '/' ? '' : BASE.replace(/\//g, '_')}`;

/** Fetched at install so the app opens offline. */
const SHELL = [
  BASE,
  `${BASE}manifest.webmanifest`,
  `${BASE}icons/icon-192.png`,
  `${BASE}icons/icon-512.png`,
  `${BASE}icons/icon-maskable-192.png`,
  `${BASE}icons/icon-maskable-512.png`,
  `${BASE}icons/apple-touch-icon.png`,
];

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(SHELL_CACHE);
    // Individually, so one missing icon cannot fail the whole install.
    await Promise.all(SHELL.map(async (url) => {
      try {
        const response = await fetch(url, { cache: 'reload' });
        if (response.ok) await cache.put(url, response);
      } catch { /* offline at install time; runtime caching will fill in */ }
    }));
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(
      names.filter((name) => name !== SHELL_CACHE).map((name) => caches.delete(name)),
    );
    await self.clients.claim();
  })());
});

/** The page asks for this explicitly, after the user agrees to reload. */
self.addEventListener('message', (event) => {
  if (event.data?.type === 'SKIP_WAITING') self.skipWaiting();
});

function isCacheable(request, url) {
  if (request.method !== 'GET') return false;
  if (url.origin !== self.location.origin) return false;
  // Anything carrying transfer data, at this mount point or the origin root
  // (belt and braces if a proxy rewrites the prefix).
  if (url.pathname.startsWith(`${BASE}api/`) || url.pathname.startsWith('/api/')) return false;
  if (url.pathname.startsWith(`${BASE}socket.io`) || url.pathname.startsWith('/socket.io')) return false;
  return true;
}

function storable(response) {
  return response && response.status === 200 && response.type === 'basic';
}

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Anything carrying transfer data goes straight to the network, untouched.
  if (!isCacheable(request, url)) return;

  // Navigations: network first, so a deployed update is picked up immediately;
  // fall back to the cached shell when offline.
  if (request.mode === 'navigate') {
    event.respondWith((async () => {
      try {
        const response = await fetch(request);
        if (storable(response)) {
          const cache = await caches.open(SHELL_CACHE);
          cache.put(BASE, response.clone());
        }
        return response;
      } catch {
        const cached = await caches.match(BASE, { cacheName: SHELL_CACHE });
        return cached ?? Response.error();
      }
    })());
    return;
  }

  // Build assets carry a content hash in the filename, so a hit is always
  // correct and never stale.
  if (url.pathname.startsWith(`${BASE}assets/`)) {
    event.respondWith((async () => {
      const cached = await caches.match(request, { cacheName: SHELL_CACHE });
      if (cached) return cached;
      const response = await fetch(request);
      if (storable(response)) {
        const cache = await caches.open(SHELL_CACHE);
        cache.put(request, response.clone());
      }
      return response;
    })());
    return;
  }

  // Everything else same-origin (icons, manifest): network first, cache as backup.
  event.respondWith((async () => {
    try {
      const response = await fetch(request);
      if (storable(response)) {
        const cache = await caches.open(SHELL_CACHE);
        cache.put(request, response.clone());
      }
      return response;
    } catch {
      const cached = await caches.match(request, { cacheName: SHELL_CACHE });
      if (cached) return cached;
      throw new Error('offline and not cached');
    }
  })());
});
