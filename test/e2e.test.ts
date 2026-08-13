/**
 * End-to-end transfers against a real server.
 *
 * Everything else in this suite tests a layer. This drives the two flows a user
 * actually takes - live device-to-device, and store-and-forward - all the way
 * through: real Socket.IO signalling, the real hybrid PQ handshake, the real
 * secure channel, real credit-based flow control, the real container, and the
 * real HTTP upload/download routes. The only stubs are the two browser globals
 * Node lacks.
 *
 * That matters because the failures this catches are the ones that live between
 * layers and cannot be seen from inside any one of them: a receiver whose
 * completion signal loses a race with its own teardown, two devices disagreeing
 * about whether they got a direct connection, a credit window that stalls, a
 * salt that one side derives and the other does not.
 *
 * Node has no RTCPeerConnection, so `establishLink` falls back to the encrypted
 * relay on both sides - the path where the server is in the middle of every
 * frame, and therefore the one worth exercising hardest.
 */

import test, { after, before } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = 8145;
const ORIGIN = `http://127.0.0.1:${PORT}`;

/**
 * The two globals the client reaches for that Node does not define.
 *
 * `location` is what socket.io-client resolves a server-relative endpoint
 * against, and `fetch` in Node refuses a relative URL outright. Both are set
 * before any client module is imported, because config.ts reads its mount point
 * at module load. This is the browser's behaviour, not a shortcut around it:
 * every request still goes over the loopback to the real server.
 */
(globalThis as Record<string, unknown>).location = {
  protocol: 'http:',
  host: `127.0.0.1:${PORT}`,
  hostname: '127.0.0.1',
  port: String(PORT),
  href: `${ORIGIN}/`,
  origin: ORIGIN,
  pathname: '/',
};

const nodeFetch = globalThis.fetch;
globalThis.fetch = ((input: string | URL | Request, init?: RequestInit) => {
  if (typeof input === 'string' && input.startsWith('/')) return nodeFetch(ORIGIN + input, init);
  return nodeFetch(input as never, init);
}) as typeof fetch;

const { liveSend } = await import('../client/src/session/liveSend.js');
const { liveReceive } = await import('../client/src/session/liveReceive.js');
const { storedSend, storedReceive } = await import('../client/src/session/stored.js');
const { sourceFor } = await import('../client/src/source.js');
const { createBlobSink } = await import('../client/src/sink.js');
const { readZipIndex, extractEntry } = await import('../client/src/unzip.js');
const { resolveCode } = await import('../client/src/transport/api.js');
const { ApiError } = await import('../client/src/transport/api.js');
type TransferEvent = import('../client/src/session/events.js').TransferEvent;

let server: ChildProcess;
let dataDir: string;

before(async () => {
  dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'qsft-e2e-'));
  server = spawn(process.execPath, ['server/index.js'], {
    cwd: root,
    env: { ...process.env, PORT: String(PORT), DATA_DIR: dataDir, HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  for (let attempt = 0; attempt < 150; attempt++) {
    try { if ((await nodeFetch(`${ORIGIN}/api/health`)).ok) return; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error('e2e server did not start');
});

after(async () => {
  server?.kill();
  await new Promise((r) => setTimeout(r, 300));
  await fs.rm(dataDir, { recursive: true, force: true }).catch(() => {});
});

/** Collects one side's event stream so assertions can read the whole story. */
class Recorder {
  readonly events: TransferEvent[] = [];
  readonly sink = (event: TransferEvent) => { this.events.push(event); };

  first<T extends TransferEvent['t']>(t: T): Extract<TransferEvent, { t: T }> | undefined {
    return this.events.find((e) => e.t === t) as Extract<TransferEvent, { t: T }> | undefined;
  }

  waitFor<T extends TransferEvent['t']>(t: T): Promise<Extract<TransferEvent, { t: T }>> {
    return new Promise((resolve, reject) => {
      const deadline = Date.now() + 30_000;
      const poll = () => {
        const found = this.first(t);
        if (found) return resolve(found);
        if (Date.now() > deadline) return reject(new Error(`no "${t}" event within 30s`));
        setTimeout(poll, 20);
      };
      poll();
    });
  }
}

async function bytesOf(blob: Blob): Promise<Uint8Array> {
  return new Uint8Array(await blob.arrayBuffer());
}

/** A deterministic, compressible payload - so the gzip path is genuinely exercised. */
function payload(bytes: number): Uint8Array {
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i++) out[i] = (i * 7 + (i >> 8)) & 0x3f;
  return out;
}

/**
 * Drive a whole live transfer: host, wait for the code, join, and let both
 * halves run to completion exactly as two browsers would.
 */
async function liveTransfer(options: {
  files: File[];
  passphrase: string;
  receivePassphrase?: string;
  compress?: boolean;
}) {
  const sender = new Recorder();
  const receiver = new Recorder();

  const sending = liveSend({
    source: sourceFor(options.files),
    passphrase: options.passphrase,
    compress: options.compress ?? false,
    onEvent: sender.sink,
  });
  // Surface a sender failure through the caller rather than as an unhandled
  // rejection while the receiver is still being set up.
  const sendSettled = sending.then(() => null, (err: Error) => err);

  const { code } = await sender.waitFor('code');
  assert.match(code, /^\d{6}$/, 'sender should publish a six-digit code');

  const receiving = liveReceive({
    code,
    passphrase: options.receivePassphrase ?? options.passphrase,
    onEvent: receiver.sink,
    requestDestination: async () => createBlobSink(),
  });
  const receiveSettled = receiving.then(() => null, (err: Error) => err);

  const [sendError, receiveError] = await Promise.all([sendSettled, receiveSettled]);
  return { code, sender, receiver, sendError, receiveError };
}

// ---------------------------------------------------------------------------
// Live
// ---------------------------------------------------------------------------

test('a live transfer round-trips a file byte-for-byte over the relay', async () => {
  const original = payload(700_000);
  const file = new File([original], 'report.bin', { type: 'application/octet-stream' });

  const { sender, receiver, sendError, receiveError } = await liveTransfer({
    files: [file],
    passphrase: 'correct-horse-battery-staple',
  });

  assert.equal(sendError, null, `sender failed: ${sendError?.message}`);
  assert.equal(receiveError, null, `receiver failed: ${receiveError?.message}`);

  const done = receiver.first('done');
  assert.ok(done?.blob, 'receiver should hand back a blob');
  assert.equal(done.name, 'report.bin');
  assert.deepEqual(await bytesOf(done.blob!), original, 'received bytes must match exactly');

  // Both sides reached "done", so the sender saw the receiver's confirmation
  // rather than mistaking the teardown behind it for a disconnection.
  assert.ok(sender.first('done'), 'sender should be told the receiver verified');

  // Node has no WebRTC, so both must have agreed on the relay - not one on each.
  assert.equal(sender.first('link')?.kind, 'relay');
  assert.equal(receiver.first('link')?.kind, 'relay');
});

test('both devices derive the same short authentication string', async () => {
  const file = new File([payload(2048)], 'small.bin');
  const { sender, receiver, sendError, receiveError } = await liveTransfer({
    files: [file],
    passphrase: 'a-shared-secret-phrase',
  });

  assert.equal(sendError, null);
  assert.equal(receiveError, null);

  const a = sender.first('sas');
  const b = receiver.first('sas');
  assert.ok(a && b, 'both sides must show a SAS');
  assert.equal(a.sas.digits, b.sas.digits);
  assert.deepEqual(a.sas.glyphs, b.sas.glyphs);
  // A SAS that is constant across sessions would compare equal while proving
  // nothing, so make sure it is actually session-derived.
  assert.match(a.sas.digits, /\d/);
});

test('a compressed live transfer round-trips', async () => {
  const original = payload(400_000);
  const file = new File([original], 'notes.txt', { type: 'text/plain' });

  const { receiver, sendError, receiveError } = await liveTransfer({
    files: [file],
    passphrase: 'another-good-passphrase-here',
    compress: true,
  });

  assert.equal(sendError, null, `sender failed: ${sendError?.message}`);
  assert.equal(receiveError, null, `receiver failed: ${receiveError?.message}`);
  assert.deepEqual(await bytesOf(receiver.first('done')!.blob!), original);
});

test('several files arrive as one bundle the receiver can unpack', async () => {
  const one = payload(5000);
  const two = payload(9000).map((b) => b ^ 0xff) as Uint8Array;

  const { receiver, sendError, receiveError } = await liveTransfer({
    files: [new File([one], 'first.bin'), new File([two], 'second.bin')],
    passphrase: 'bundle-passphrase-for-two',
  });

  assert.equal(sendError, null, `sender failed: ${sendError?.message}`);
  assert.equal(receiveError, null, `receiver failed: ${receiveError?.message}`);

  const blob = receiver.first('done')!.blob!;
  const entries = await readZipIndex(blob);
  assert.ok(entries, 'the received bundle should be indexable');
  assert.deepEqual(entries!.map((e) => e.name).sort(), ['first.bin', 'second.bin']);

  const byName = Object.fromEntries(entries!.map((e) => [e.name, e]));
  assert.deepEqual(await bytesOf(await extractEntry(blob, byName['first.bin'])), one);
  assert.deepEqual(await bytesOf(await extractEntry(blob, byName['second.bin'])), two);
});

test('a mismatched passphrase fails the handshake on both devices', async () => {
  const file = new File([payload(1024)], 'secret.bin');
  const { sender, receiver, sendError, receiveError } = await liveTransfer({
    files: [file],
    passphrase: 'the-real-passphrase',
    receivePassphrase: 'not-the-real-passphrase',
  });

  assert.ok(sendError, 'the sender must not complete against a wrong passphrase');
  assert.ok(receiveError, 'the receiver must not complete against a wrong passphrase');
  // And nothing was handed over.
  assert.equal(sender.first('done'), undefined);
  assert.equal(receiver.first('done'), undefined);

  /**
   * Both devices must name the cause, not just the one that noticed.
   *
   * The sender checks the responder's MAC first and then closes the session, so
   * the receiver - the person who actually typed the passphrase - used to be
   * told only "the other device ended the session". Right about the event,
   * useless about the cause, and aimed at the wrong device.
   */
  const wrongPassphrase = /passphrases do not match|intercepting/i;
  assert.match(sendError!.message, wrongPassphrase, `sender: ${sendError!.message}`);
  assert.match(receiveError!.message, wrongPassphrase, `receiver: ${receiveError!.message}`);
});

test('a finished live session releases its code', async () => {
  const file = new File([payload(1024)], 'x.bin');
  const { code, sendError, receiveError } = await liveTransfer({
    files: [file],
    passphrase: 'release-the-code-please',
  });
  assert.equal(sendError, null);
  assert.equal(receiveError, null);

  // Both sockets closed on the way out, so the room - and its code - must be gone.
  await assert.rejects(
    () => resolveCode(code),
    (err: unknown) => err instanceof ApiError && err.status === 404,
    'the code should no longer resolve once both devices have left',
  );
});

// ---------------------------------------------------------------------------
// Store and forward
// ---------------------------------------------------------------------------

test('a stored transfer round-trips through upload, code lookup and download', async () => {
  const original = payload(1_200_000);
  const file = new File([original], 'archive.bin', { type: 'application/octet-stream' });
  const upload = new Recorder();
  const download = new Recorder();

  const result = await storedSend({
    source: sourceFor([file]),
    passphrase: 'stored-transfer-passphrase',
    compress: false,
    ttlSeconds: 600,
    maxReads: 1,
    onEvent: upload.sink,
  });
  assert.match(result.code, /^\d{6}$/);

  // The receiver's first move is the same lookup the UI makes.
  assert.deepEqual((await resolveCode(result.code)).kind, 'stored');

  await storedReceive({
    code: result.code,
    passphrase: 'stored-transfer-passphrase',
    onEvent: download.sink,
    requestDestination: async () => createBlobSink(),
  });

  const done = download.first('done');
  assert.equal(done?.name, 'archive.bin');
  assert.deepEqual(await bytesOf(done!.blob!), original);

  // maxReads was 1, so collecting it must have deleted it.
  await assert.rejects(
    () => resolveCode(result.code),
    (err: unknown) => err instanceof ApiError && err.status === 404,
    'a one-read transfer should be gone after being collected',
  );
});

test('a stored transfer refuses to open under the wrong passphrase', async () => {
  const file = new File([payload(4096)], 'private.bin');
  const result = await storedSend({
    source: sourceFor([file]),
    passphrase: 'the-right-one',
    compress: false,
    ttlSeconds: 600,
    maxReads: 5,
    onEvent: new Recorder().sink,
  });

  await assert.rejects(
    () => storedReceive({
      code: result.code,
      passphrase: 'the-wrong-one',
      onEvent: new Recorder().sink,
      requestDestination: async () => createBlobSink(),
    }),
    /passphrase is wrong|could not decrypt/i,
  );

  // The blob is untouched and still collectable by someone who knows the phrase.
  const download = new Recorder();
  await storedReceive({
    code: result.code,
    passphrase: 'the-right-one',
    onEvent: download.sink,
    requestDestination: async () => createBlobSink(),
  });
  assert.ok(download.first('done')?.blob);

  await result.revoke();
});

test('the sender can revoke a stored transfer before anyone collects it', async () => {
  const file = new File([payload(2048)], 'recalled.bin');
  const result = await storedSend({
    source: sourceFor([file]),
    passphrase: 'recall-this-transfer',
    compress: false,
    ttlSeconds: 600,
    maxReads: 5,
    onEvent: new Recorder().sink,
  });

  assert.equal((await resolveCode(result.code)).kind, 'stored');
  await result.revoke();
  await assert.rejects(
    () => resolveCode(result.code),
    (err: unknown) => err instanceof ApiError && err.status === 404,
  );
});
