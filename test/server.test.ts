/**
 * Server behaviour: access control, retention, and the one-client-at-a-time
 * rules. Boots a real server on a scratch data directory.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { io, type Socket } from 'socket.io-client';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8137;
const BASE = `http://127.0.0.1:${PORT}`;
const API = `${BASE}/api`;

let server: ChildProcess;
let dataDir: string;
const sockets: Socket[] = [];

before(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qsft-test-'));
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
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  for (let attempt = 0; attempt < 100; attempt++) {
    try {
      const response = await fetch(`${API}/health`);
      if (response.ok) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('server did not start');
});

after(async () => {
  for (const socket of sockets) socket.close();
  server?.kill();
  await new Promise((r) => setTimeout(r, 200));
  await fs.rm(dataDir, { recursive: true, force: true }).catch(() => {});
});

function connect(): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = io(BASE, { transports: ['websocket'], reconnection: false });
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

  const files = await fs.readdir(path.join(dataDir, 'blobs'));
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

test('security headers are set on the app response', async () => {
  const response = await fetch(`${BASE}/api/health`);
  const csp = response.headers.get('content-security-policy') ?? '';
  assert.match(csp, /default-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.match(csp, /object-src 'none'/);
  assert.equal(response.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(response.headers.get('referrer-policy'), 'no-referrer');
});
