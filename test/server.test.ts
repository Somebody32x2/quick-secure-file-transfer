/**
 * Server behaviour: access control, retention, and the one-client-at-a-time
 * rules. Boots a real server on a scratch data directory.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { io, type Socket } from 'socket.io-client';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8137;
const BASE = `http://127.0.0.1:${PORT}`;
const API = `${BASE}/api`;

/**
 * A second instance that believes it sits behind two proxies, so the tests can
 * play the appending proxy and hand it a chosen "real" client address. The main
 * instance trusts no proxy, which is the right default and what every other test
 * here assumes.
 */
const PROXY_PORT = 8138;
const PROXY_API = `http://127.0.0.1:${PROXY_PORT}/api`;

let server: ChildProcess;
let proxied: ChildProcess;
let dataDir: string;
let proxyDataDir: string;
const sockets: Socket[] = [];

async function waitFor(url: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      if ((await fetch(url)).ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`server did not start: ${url}`);
}

before(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qsft-test-'));
  proxyDataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qsft-proxy-test-'));

  server = spawn(process.execPath, ['server/index.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(PORT),
      DATA_DIR: dataDir,
      HOST: '127.0.0.1',
      // Tight limits so the throttling tests do not take minutes.
      CODE_ATTEMPTS_PER_IP: '8',
      CODE_ATTEMPT_WINDOW_MS: '60000',
      // Exercises the alias redirect with no BASE_PATH, which is the shape that
      // used to produce a protocol-relative off-origin Location.
      ALIAS_PATHS: '/qsft',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  proxied = spawn(process.execPath, ['server/index.js'], {
    cwd: root,
    env: {
      ...process.env,
      PORT: String(PROXY_PORT),
      DATA_DIR: proxyDataDir,
      HOST: '127.0.0.1',
      CODE_ATTEMPTS_PER_IP: '8',
      CODE_ATTEMPT_WINDOW_MS: '60000',
      TRUST_PROXY: '2',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  await Promise.all([waitFor(`${API}/health`), waitFor(`${PROXY_API}/health`)]);
});

after(async () => {
  for (const socket of sockets) socket.close();
  server?.kill();
  proxied?.kill();
  await new Promise((r) => setTimeout(r, 200));
  await fs.rm(dataDir, { recursive: true, force: true }).catch(() => {});
  await fs.rm(proxyDataDir, { recursive: true, force: true }).catch(() => {});
});

/**
 * A lookup as it would arrive through a trusted proxy. `claimed` is the part a
 * client can forge; `real` is what the proxy actually observed and appended.
 */
function proxiedLookup(code: string, claimed: string, real: string): Promise<Response> {
  return fetch(`${PROXY_API}/resolve/${code}`, {
    headers: { 'X-Forwarded-For': `${claimed}, ${real}, 127.0.0.1` },
  });
}

function connect(origin = BASE): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = io(origin, { transports: ['websocket'], reconnection: false });
    sockets.push(socket);
    socket.on('connect', () => resolve(socket));
    socket.on('connect_error', reject);
  });
}

function emit<T>(socket: Socket, event: string, payload: unknown): Promise<T> {
  return new Promise((resolve) => socket.emit(event, payload, resolve));
}

async function uploadBlob(bytes: Buffer, opts: { ttlSeconds?: number; maxReads?: number } = {}) {
  const ticket = await (await fetch(`${API}/store/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ttlSeconds: opts.ttlSeconds ?? 600, maxReads: opts.maxReads ?? 1, declaredSize: bytes.length }),
  })).json();

  await fetch(`${API}/store/${ticket.id}/part`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'x-upload-token': ticket.token,
      'x-part-index': '0',
    },
    body: bytes,
  });

  const committed = await (await fetch(`${API}/store/${ticket.id}/commit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-upload-token': ticket.token },
    body: '{}',
  })).json();

  return { ticket, committed };
}

// ---------------------------------------------------------------------------
// Live sessions
// ---------------------------------------------------------------------------

test('a live room admits exactly one receiver', async () => {
  const host = await connect();
  const { code } = await emit<{ code: string }>(host, 'live:host', {});
  assert.match(code, /^\d{6}$/);

  const first = await connect();
  assert.deepEqual(await emit(first, 'live:join', { code }), { ok: true });

  // The requirement is one client at a time; a third device must be turned away.
  const second = await connect();
  const rejected = await emit<{ error: string }>(second, 'live:join', { code });
  assert.match(rejected.error, /already has a receiver/);
});

test('joining a code that no one is hosting fails cleanly', async () => {
  const socket = await connect();
  const result = await emit<{ error: string }>(socket, 'live:join', { code: '000000' });
  assert.match(result.error, /No live session/);
});

test('malformed join codes are rejected', async () => {
  const socket = await connect();
  assert.match((await emit<{ error: string }>(socket, 'live:join', { code: 'abc' })).error, /six digits/);
  assert.match((await emit<{ error: string }>(socket, 'live:join', { code: '12345' })).error, /six digits/);
});

test('a live code resolves as live, and frames only reach the paired peer', async () => {
  const host = await connect();
  const { code } = await emit<{ code: string }>(host, 'live:host', {});

  const resolved = await (await fetch(`${API}/resolve/${code}`)).json();
  assert.equal(resolved.kind, 'live');

  const guest = await connect();
  await emit(guest, 'live:join', { code });

  const received = new Promise<Uint8Array>((resolve) => {
    guest.on('live:data', (frame: ArrayBuffer) => resolve(new Uint8Array(frame)));
  });
  host.emit('live:data', new Uint8Array([9, 8, 7]));
  assert.deepEqual([...(await received)], [9, 8, 7]);

  // An unrelated socket must never see the room's traffic.
  const outsider = await connect();
  let leaked = false;
  outsider.on('live:data', () => { leaked = true; });
  host.emit('live:data', new Uint8Array([1, 2, 3]));
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(leaked, false, 'relay leaked a frame to a socket outside the room');
});

test('the receiver is told when the sender disconnects', async () => {
  const host = await connect();
  const { code } = await emit<{ code: string }>(host, 'live:host', {});
  const guest = await connect();
  await emit(guest, 'live:join', { code });

  const left = new Promise<string>((resolve) => {
    guest.on('live:peer-left', (p: { reason: string }) => resolve(p.reason));
  });
  host.close();
  assert.match(await left, /disconnect/);
});

// ---------------------------------------------------------------------------
// Stored transfers
// ---------------------------------------------------------------------------

test('read budget deletes the blob and frees its code', async () => {
  const payload = Buffer.from('ciphertext-stand-in'.repeat(100));
  const { committed } = await uploadBlob(payload, { maxReads: 1 });

  const resolved = await (await fetch(`${API}/resolve/${committed.code}`)).json();
  assert.equal(resolved.kind, 'stored');
  assert.equal(resolved.readsRemaining, 1);

  const download = await fetch(`${API}/store/${committed.code}`);
  assert.equal(download.status, 200);
  assert.deepEqual(Buffer.from(await download.arrayBuffer()), payload);

  const second = await fetch(`${API}/store/${committed.code}`);
  assert.equal(second.status, 404, 'a one-read transfer must be gone after collection');

  // The record leaves memory before the unlink is awaited, so a 404 does not by
  // itself mean the bytes are gone yet. Poll rather than assume: asserting
  // straight after the 404 made this test fail intermittently for a reason that
  // had nothing to do with what it is testing.
  const blobs = path.join(dataDir, 'blobs');
  for (let waited = 0; waited < 2000 && (await fs.readdir(blobs)).length > 0; waited += 25) {
    await new Promise((r) => setTimeout(r, 25));
  }
  const files = await fs.readdir(blobs);
  assert.equal(files.length, 0, 'the blob must be removed from disk, not just hidden');
});

test('a partial download does not consume the read budget', async () => {
  // 6 MB so the response is still streaming when we abort it.
  const payload = Buffer.alloc(6 * 1024 * 1024, 7);
  const { committed } = await uploadBlob(payload, { maxReads: 1 });

  const controller = new AbortController();
  const response = await fetch(`${API}/store/${committed.code}`, { signal: controller.signal });
  const reader = response.body!.getReader();
  await reader.read();
  controller.abort();
  await new Promise((r) => setTimeout(r, 300));

  // The interrupted attempt must not have burned the single read.
  const retry = await fetch(`${API}/store/${committed.code}`);
  assert.equal(retry.status, 200, 'an aborted download must not consume the read budget');
  assert.equal(Buffer.from(await retry.arrayBuffer()).length, payload.length);
});

test('only one download at a time is served', async () => {
  const payload = Buffer.alloc(8 * 1024 * 1024, 3);
  const { committed } = await uploadBlob(payload, { maxReads: 5 });

  const first = await fetch(`${API}/store/${committed.code}`);
  const reader = first.body!.getReader();
  await reader.read(); // hold the stream open

  const second = await fetch(`${API}/store/${committed.code}`);
  assert.equal(second.status, 409);
  assert.match((await second.json()).error, /downloading this right now/);

  await reader.cancel();
});

test('the sender can revoke before expiry', async () => {
  const { ticket, committed } = await uploadBlob(Buffer.from('x'.repeat(500)), { maxReads: 5 });

  const revoked = await fetch(`${API}/store/${ticket.id}/revoke`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-upload-token': ticket.token },
    body: '{}',
  });
  assert.equal(revoked.status, 200);
  assert.equal((await fetch(`${API}/store/${committed.code}`)).status, 404);
});

test('retention is capped at 48 hours however long the sender asks for', async () => {
  const before = Date.now();
  const ticket = await (await fetch(`${API}/store/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ttlSeconds: 60 * 60 * 24 * 30, maxReads: 1, declaredSize: 10 }),
  })).json();

  const maxAllowed = before + 48 * 3600 * 1000 + 5000;
  assert.ok(ticket.expiresAt <= maxAllowed, `expiry ${ticket.expiresAt} exceeds the 48h cap`);
});

test('an upload token is required to write or finalise', async () => {
  const ticket = await (await fetch(`${API}/store/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ttlSeconds: 600, maxReads: 1, declaredSize: 10 }),
  })).json();

  const noToken = await fetch(`${API}/store/${ticket.id}/part`, {
    method: 'PUT',
    headers: { 'content-type': 'application/octet-stream', 'x-part-index': '0' },
    body: Buffer.from('hello'),
  });
  assert.equal(noToken.status, 403);

  const wrongToken = await fetch(`${API}/store/${ticket.id}/commit`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-upload-token': 'not-the-token' },
    body: '{}',
  });
  assert.equal(wrongToken.status, 403);
});

// ---------------------------------------------------------------------------
// Abuse resistance
// ---------------------------------------------------------------------------

test('legitimate collections do not eat the guess budget', async () => {
  // Well past the 8-attempt limit configured for this server: a person
  // collecting many real transfers must never be throttled for it.
  for (let i = 0; i < 20; i++) {
    const { committed } = await uploadBlob(Buffer.from(`payload-${i}`), { maxReads: 1 });
    const resolved = await fetch(`${API}/resolve/${committed.code}`);
    assert.equal(resolved.status, 200, `resolve #${i} should succeed`);
    const download = await fetch(`${API}/store/${committed.code}`);
    assert.equal(download.status, 200, `download #${i} should succeed`);
    await download.arrayBuffer();
  }
});

test('code guessing is throttled', async () => {
  let sawRateLimit = false;
  let attempts = 0;
  for (; attempts < 25; attempts++) {
    const response = await fetch(`${API}/resolve/${String(100000 + attempts)}`);
    if (response.status === 429) { sawRateLimit = true; break; }
    assert.equal(response.status, 404);
  }
  assert.equal(sawRateLimit, true, 'brute-forcing codes must hit a rate limit');
  assert.ok(attempts <= 10, `expected throttling within the configured budget, took ${attempts}`);
});

test('guessing over the socket is throttled on the same budget as HTTP', async () => {
  // The socket path used to have no limiter at all, which walked the whole 10^6
  // code space in about five minutes. Two separate budgets would be almost as
  // bad, so this also pins that a fresh socket does not reset it.
  const socket = await connect();
  let allowed = 0;
  for (let i = 0; i < 40; i++) {
    const result = await emit<{ error?: string }>(socket, 'live:join', {
      code: String(200000 + i),
    });
    if (!/Too many code attempts/.test(result.error ?? '')) allowed++;
    else break;
  }
  assert.ok(allowed <= 8, `socket guessing must hit the shared limit, got ${allowed} through`);

  const fresh = await connect();
  const afterReconnect = await emit<{ error?: string }>(fresh, 'live:join', { code: '999999' });
  assert.match(
    afterReconnect.error ?? '',
    /Too many code attempts/,
    'opening a new socket must not hand out a fresh guess budget',
  );
});

test('a code that was guessed at is still usable by its real receiver', async () => {
  // Failed lookups used to lock a code for ten minutes regardless of whether it
  // was allocated, so a sweep of the space left dead zones behind it: the next
  // transfer handed one of those codes had its receiver turned away.
  // Hosted on the proxied instance, because that is where the lookups below go
  // and each instance keeps its own code registry.
  const host = await connect(`http://127.0.0.1:${PROXY_PORT}`);
  const { code } = await emit<{ code: string }>(host, 'live:host', {});

  // Distinct real addresses, so only the per-code counter moves.
  for (let i = 0; i < 20; i++) await proxiedLookup(code, 'spoofed', `192.0.2.${i}`);

  const receiver = await proxiedLookup(code, 'spoofed', '198.51.100.200');
  assert.equal(receiver.status, 200, 'the genuine receiver must not be locked out of its own code');
  assert.equal((await receiver.json()).kind, 'live');

  // A code nobody is using still locks, which harms no one.
  const unallocated = '000123';
  for (let i = 0; i < 20; i++) await proxiedLookup(unallocated, 'x', `192.0.2.${100 + i}`);
  const locked = await proxiedLookup(unallocated, 'x', '198.51.100.201');
  assert.equal(locked.status, 429);
});

test('a forged X-Forwarded-For does not buy a fresh identity', async () => {
  // Reading the leftmost value let anyone mint a new client per request and walk
  // straight through the limiter. Only the rightmost entries are proxy-written.
  let accepted = 0;
  for (let i = 0; i < 30; i++) {
    const response = await proxiedLookup(String(300000 + i), `10.9.0.${i}`, '198.51.100.5');
    if (response.status !== 429) accepted++;
  }
  assert.ok(accepted <= 8, `rotating a forged header bought ${accepted} attempts, limit is 8`);

  // A genuinely different client, distinguished by what the proxy appended, is
  // not collateral damage.
  const other = await proxiedLookup('310000', 'anything', '203.0.113.77');
  assert.notEqual(other.status, 429, 'a different real client must keep its own budget');
});

test('alias redirects stay on this origin', async () => {
  const cases: [string, string][] = [
    ['/qsft', '/'],
    ['/qsft/x', '/x'],
    // Stripping only one leading slash left "//evil.example", a
    // protocol-relative URL pointing off-origin entirely.
    ['/qsft//evil.example', '/evil.example'],
    ['/qsft///evil.example', '/evil.example'],
  ];
  for (const [from, expected] of cases) {
    const response = await fetch(`${BASE}${from}`, { redirect: 'manual' });
    assert.equal(response.status, 301);
    const location = response.headers.get('location');
    assert.equal(location, expected, `${from} must redirect to ${expected}`);
    assert.ok(!location!.startsWith('//'), `${from} produced an off-origin redirect`);
  }
});

test('concurrent parts at the same index cannot double-append', async () => {
  // Validating the index synchronously and only then awaiting the write let
  // every concurrent request pass the check before any of them advanced
  // nextIndex - so all of them appended, silently corrupting the blob.
  const ticket = await (await fetch(`${API}/store/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ttlSeconds: 600, maxReads: 1, declaredSize: 1024 * 1024 }),
  })).json();

  const CHUNK = 32 * 1024;
  const body = Buffer.alloc(CHUNK, 0x41);
  const head = `PUT /api/store/${ticket.id}/part HTTP/1.1\r\nHost: 127.0.0.1:${PORT}\r\n`
    + `x-part-index: 0\r\nx-upload-token: ${ticket.token}\r\n`
    + `content-type: application/octet-stream\r\ncontent-length: ${CHUNK}\r\n`
    + 'connection: close\r\n\r\n';

  // Raw sockets with the head sent first, then every body flushed together, so
  // the request-complete events land in one event-loop batch. Plain concurrent
  // fetches stagger too much to expose it.
  const connections = await Promise.all(Array.from({ length: 8 }, () => new Promise<net.Socket>(
    (resolve, reject) => {
      const socket = net.connect(PORT, '127.0.0.1', () => { socket.write(head); resolve(socket); });
      socket.setNoDelay(true);
      socket.on('error', reject);
    },
  )));
  await new Promise((r) => setTimeout(r, 60));
  const replies = connections.map((socket) => new Promise<string>((resolve) => {
    let buffer = '';
    const timer = setTimeout(() => resolve(buffer), 8000);
    socket.on('data', (d) => {
      buffer += d.toString('latin1');
      if (buffer.includes('\r\n\r\n')) { clearTimeout(timer); resolve(buffer); }
    });
    socket.on('close', () => { clearTimeout(timer); resolve(buffer); });
  }));
  for (const socket of connections) socket.write(body);
  await Promise.all(replies);
  for (const socket of connections) socket.destroy();

  const written = (await fs.stat(path.join(dataDir, 'blobs', `${ticket.id}.bin`))).size;
  assert.equal(written, CHUNK, `blob holds ${written} bytes; the part was appended more than once`);

  // The retry-after-a-dropped-response case must still be a no-op, not an error.
  const repeat = await fetch(`${API}/store/${ticket.id}/part`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'x-upload-token': ticket.token,
      'x-part-index': '0',
    },
    body,
  });
  assert.equal(repeat.status, 200);
  assert.equal((await repeat.json()).duplicate, true);
});

test('an unauthenticated part upload is refused before its body is read', async () => {
  // express.raw would buffer the full 8 MiB into memory and only then hand it to
  // a handler that rejected the token, making an anonymous request an 8 MiB
  // allocation with nothing capping how many could be in flight.
  const response = await fetch(`${API}/store/deadbeef-not-a-real-upload/part`, {
    method: 'PUT',
    headers: { 'content-type': 'application/octet-stream', 'x-part-index': '0' },
    body: Buffer.alloc(64 * 1024, 1),
  });
  assert.equal(response.status, 404);

  const ticket = await (await fetch(`${API}/store/init`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ ttlSeconds: 600, maxReads: 1, declaredSize: 1024 }),
  })).json();
  const wrongToken = await fetch(`${API}/store/${ticket.id}/part`, {
    method: 'PUT',
    headers: {
      'content-type': 'application/octet-stream',
      'x-part-index': '0',
      'x-upload-token': 'not-the-token',
    },
    body: Buffer.alloc(64 * 1024, 1),
  });
  assert.equal(wrongToken.status, 403);
});

test('one address cannot hoard upload reservations', async () => {
  // A reservation is free to make, holds a code from the shared registry for an
  // hour, and declaredSize:0 skips the quota check - so unbounded, one caller
  // could saturate the whole code space and deny every transfer on the server.
  const statuses: number[] = [];
  for (let i = 0; i < 40; i++) {
    const response = await fetch(`${API}/store/init`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ttlSeconds: 600, maxReads: 1, declaredSize: 0 }),
    });
    statuses.push(response.status);
  }
  assert.ok(statuses.includes(429), 'unbounded reservations must be refused at some point');
  const created = statuses.filter((s) => s === 201).length;
  assert.ok(created <= 12, `expected the uncommitted ceiling to bite, ${created} got through`);
});

test('sockets are same-origin only, without shutting out real clients', async () => {
  // Socket.IO's `cors` option governs polling only - WebSocket upgrades are not
  // subject to CORS - so without an explicit check any page could drive this
  // signalling channel from every visitor's browser. The risk in fixing it is
  // over-rejecting: a browser always sends Origin, so getting the allowed cases
  // wrong breaks live transfers for everybody.
  const attempt = (origin: string | null, host?: string): Promise<'up' | 'refused'> =>
    new Promise((resolve) => {
      const headers: Record<string, string> = {};
      if (origin !== null) headers.Origin = origin;
      if (host) headers.Host = host;
      const socket = io(BASE, {
        transports: ['websocket'],
        reconnection: false,
        extraHeaders: headers,
      });
      const timer = setTimeout(() => { socket.close(); resolve('refused'); }, 4000);
      socket.on('connect', () => { clearTimeout(timer); socket.close(); resolve('up'); });
      socket.on('connect_error', () => { clearTimeout(timer); resolve('refused'); });
    });

  assert.equal(await attempt(BASE), 'up', 'a browser on this origin must connect');
  assert.equal(await attempt(null), 'up', 'a client that sends no Origin must connect');
  assert.equal(
    await attempt('http://192.168.1.50:5173', '192.168.1.50:5173'), 'up',
    'a LAN origin, and the Vite dev proxy which preserves Host, must connect',
  );

  assert.equal(await attempt('https://evil.example'), 'refused');
  assert.equal(
    await attempt('https://files.example.com.evil.test', 'files.example.com'), 'refused',
    'a lookalike host must not pass as a prefix match',
  );
  assert.equal(await attempt('null'), 'refused', 'a sandboxed iframe must not connect');
});

test('security headers are set on the app response', async () => {
  const response = await fetch(`${BASE}/api/health`);
  const csp = response.headers.get('content-security-policy') ?? '';
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
});
