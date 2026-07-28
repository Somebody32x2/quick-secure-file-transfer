/**
 * Service worker routing rules.
 *
 * The invariant that matters: nothing carrying transfer data may ever be
 * cached. A cached ciphertext blob would outlive the server's "delete after
 * reading" guarantee and quietly turn a burn-after-read transfer into a stored
 * copy on the device. That is a security property, so it gets a test rather
 * than a comment.
 *
 * sw.js is evaluated in a sandbox with the worker globals mocked, and its
 * registered fetch handler is driven directly.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ORIGIN = 'https://qsft.test';

interface FakeCache {
  store: Map<string, unknown>;
  put(request: unknown, response: unknown): Promise<void>;
  keys(): Promise<unknown[]>;
}

/**
 * @param base mount point the worker is served from. The worker derives this
 *             from its own URL, so "/filetransfer/" simulates a subpath deploy.
 */
function loadWorker(base = '/') {
  const source = fs.readFileSync(path.join(root, 'client', 'public', 'sw.js'), 'utf8');
  const listeners: Record<string, ((event: any) => void)[]> = {};
  const cacheStore = new Map<string, FakeCache>();
  const putCalls: string[] = [];

  const makeCache = (): FakeCache => ({
    store: new Map(),
    async put(request: any) {
      putCalls.push(typeof request === 'string' ? request : request.url);
    },
    async keys() { return []; },
  });

  const sandbox: Record<string, unknown> = {
    self: {
      addEventListener(type: string, handler: (event: any) => void) {
        (listeners[type] ??= []).push(handler);
      },
      location: { origin: ORIGIN, pathname: `${base}sw.js` },
      clients: { claim: async () => {} },
      skipWaiting() {},
    },
    caches: {
      async open(name: string) {
        if (!cacheStore.has(name)) cacheStore.set(name, makeCache());
        return cacheStore.get(name)!;
      },
      async keys() { return [...cacheStore.keys()]; },
      async match() { return undefined; },
      async delete() { return true; },
    },
    fetch: async () => ({ ok: true, status: 200, type: 'basic', clone: () => ({}) }),
    Response: { error: () => ({ type: 'error' }) },
    URL,
    console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(source, sandbox);

  return { listeners, putCalls };
}

/** Drive the fetch handler and report whether the worker claimed the request. */
function dispatchFetch(
  listeners: Record<string, ((event: any) => void)[]>,
  url: string,
  { method = 'GET', mode = 'cors' } = {},
): { handled: boolean } {
  let handled = false;
  const event = {
    request: { method, url, mode },
    respondWith(promise: Promise<unknown>) {
      handled = true;
      // Swallow rejections: we are asserting on routing, not on the response.
      Promise.resolve(promise).catch(() => {});
    },
  };
  for (const handler of listeners.fetch ?? []) handler(event);
  return { handled };
}

test('the worker registers the lifecycle handlers it needs', () => {
  const { listeners } = loadWorker();
  for (const type of ['install', 'activate', 'fetch', 'message']) {
    assert.ok(listeners[type]?.length, `missing a ${type} handler`);
  }
});

test('API traffic is never intercepted', () => {
  const { listeners } = loadWorker();
  const apiPaths = [
    '/api/config',
    '/api/resolve/123456',
    '/api/store/123456',          // the ciphertext download
    '/api/store/123456/meta',
    '/api/store/abc/part',
    '/api/health',
  ];
  for (const p of apiPaths) {
    const { handled } = dispatchFetch(listeners, `${ORIGIN}${p}`);
    assert.equal(handled, false, `${p} must go straight to the network, uncached`);
  }
});

test('live relay traffic is never intercepted', () => {
  const { listeners } = loadWorker();
  const { handled } = dispatchFetch(listeners, `${ORIGIN}/socket.io/?EIO=4&transport=polling`);
  assert.equal(handled, false, 'socket.io carries payload frames and must bypass the worker');
});

test('non-GET and cross-origin requests are ignored', () => {
  const { listeners } = loadWorker();

  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/`, { method: 'POST' }).handled, false,
    'only GET may be served from cache',
  );
  assert.equal(
    dispatchFetch(listeners, 'https://elsewhere.example/thing.js').handled, false,
    'cross-origin requests must not be touched',
  );
});

test('the app shell is intercepted so it can work offline', () => {
  const { listeners } = loadWorker();

  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/`, { mode: 'navigate' }).handled, true,
    'navigations must be served so the app opens offline',
  );
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/assets/index-abc123.js`).handled, true,
    'hashed build assets must be cacheable',
  );
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/icons/icon-512.png`).handled, true,
    'icons must be cacheable',
  );
});

test('a subpath deployment scopes itself to that subpath', () => {
  const { listeners } = loadWorker('/filetransfer/');

  // Still refuses transfer data, now at the mounted prefix.
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/filetransfer/api/store/123456`).handled, false,
    'ciphertext must never be cached, at any mount point',
  );
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/filetransfer/socket.io/?EIO=4`).handled, false,
    'relay traffic must bypass the worker, at any mount point',
  );

  // And still serves the shell, now at the mounted prefix.
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/filetransfer/`, { mode: 'navigate' }).handled, true,
    'the subpath shell must be served offline',
  );
  assert.equal(
    dispatchFetch(listeners, `${ORIGIN}/filetransfer/assets/index-abc123.js`).handled, true,
    'subpath assets must be cacheable',
  );

  // Requests outside the mount point are never delivered to this worker at all
  // - the browser enforces scope - so there is nothing to assert about them
  // here beyond the API/socket rules above, which hold at both prefixes.
});

test('the precache list contains only shell resources', () => {
  const source = fs.readFileSync(path.join(root, 'client', 'public', 'sw.js'), 'utf8');
  const start = source.indexOf('const SHELL = [');
  const block = source.slice(start, source.indexOf('];', start));

  // Entries are template literals rooted at the runtime-derived BASE.
  const urls = [...block.matchAll(/`([^`]+)`/g)].map((m) => m[1]);

  assert.ok(urls.length > 0, 'expected a precache list');
  for (const url of urls) {
    assert.ok(!url.includes('api/'), `${url} must not be precached`);
    assert.ok(!url.includes('socket.io'), `${url} must not be precached`);
    assert.ok(url.startsWith('${BASE}'), `${url} must be relative to the mount point`);
  }
  assert.ok(block.includes('\n  BASE,'), 'the shell entry point must be precached');
});

test('the manifest points at icons that exist and cover both purposes', () => {
  const manifest = JSON.parse(
    fs.readFileSync(path.join(root, 'client', 'public', 'manifest.webmanifest'), 'utf8'),
  );

  // Relative URLs resolve against the manifest's own location, so one file
  // serves both a root deployment and a subpath one.
  assert.equal(manifest.start_url, '.', 'start_url must be relative to the mount point');
  assert.equal(manifest.scope, '.', 'scope must be relative to the mount point');
  assert.equal(manifest.display, 'standalone');
  assert.ok(manifest.name && manifest.short_name);

  for (const icon of manifest.icons) {
    assert.ok(!icon.src.startsWith('/'), `${icon.src} must be relative, not origin-absolute`);
  }

  const purposes = new Set(manifest.icons.map((i: { purpose: string }) => i.purpose));
  assert.ok(purposes.has('any'), 'needs a standard icon');
  assert.ok(purposes.has('maskable'), 'needs a maskable icon for Android launchers');

  for (const icon of manifest.icons) {
    const file = path.join(root, 'client', 'public', icon.src.replace(/^\//, ''));
    assert.ok(fs.existsSync(file), `manifest references a missing icon: ${icon.src}`);

    // Confirm it is a real PNG of the declared size, not a placeholder.
    const bytes = fs.readFileSync(file);
    assert.equal(bytes.subarray(0, 8).toString('hex'), '89504e470d0a1a0a', `${icon.src} is not a PNG`);
    const [width, height] = [bytes.readUInt32BE(16), bytes.readUInt32BE(20)];
    assert.equal(`${width}x${height}`, icon.sizes, `${icon.src} is ${width}x${height}, declared ${icon.sizes}`);
  }
});
