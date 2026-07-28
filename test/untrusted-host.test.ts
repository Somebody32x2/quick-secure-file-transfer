/**
 * The untrusted-host requirement.
 *
 * On a plain-http origin (a LAN IP, a dev box, a phone hitting 192.168.x.x)
 * browsers withhold `crypto.subtle` entirely, and some hardened WebViews ship a
 * `crypto` object with no working `getRandomValues` either. QSFT has to keep
 * working in both cases.
 *
 * Each scenario runs in a fresh child process, because the capability probe in
 * env.ts caches its results at module load - the only faithful way to simulate
 * a degraded host is to degrade the globals *before* the first import.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function runScenario(setup: string): Record<string, unknown> {
  const script = `
${setup}

const { caps } = await import('./client/src/crypto/env.ts');
const { randomBytes } = await import('./client/src/crypto/env.ts');
const { preferredSuite, SUITE_XCHACHA20_POLY1305 } = await import('./client/src/crypto/aead.ts');
const { ChunkSealer, ChunkOpener } = await import('./client/src/crypto/stream.ts');
const { decodeHeader } = await import('./client/src/crypto/format.ts');
const { deriveMaster, sessionSalt } = await import('./client/src/crypto/kdf.ts');
const { Initiator, Responder } = await import('./client/src/crypto/kex.ts');
const { shortAuthString } = await import('./client/src/crypto/sas.ts');

const KDF = { memKiB: 1024, timeCost: 1, lanes: 1 };
const payload = randomBytes(40000);

// Full container round trip with whatever primitives this host allows.
const sealer = await ChunkSealer.create({ passphrase: 'pw', chunkSize: 8192, kdfParams: KDF });
const chunks = [await sealer.sealMeta({ name: 'x.bin', size: payload.length, type: '', lastModified: 0 })];
for (let off = 0; off < payload.length; off += 8192) {
  const slice = payload.subarray(off, Math.min(off + 8192, payload.length));
  chunks.push(await sealer.seal(slice, off + 8192 >= payload.length));
}

const fields = decodeHeader(sealer.headerBytes);
const master = await deriveMaster('pw', fields.salt, fields.kdf);
const opener = await ChunkOpener.create(fields, sealer.headerBytes, master);
const meta = await opener.openMeta(chunks[0]);
const out = [];
for (let i = 1; i < chunks.length; i++) out.push(...(await opener.open(chunks[i], i === chunks.length - 1)));
const roundTripped = out.length === payload.length && out.every((b, i) => b === payload[i]);

// The hybrid PQ handshake must also work with no WebCrypto.
const salt = sessionSalt('424242');
const m = await deriveMaster('pw', salt, KDF);
const initiator = Initiator.start(m, salt, KDF);
const responder = Responder.respond(initiator.hello, m);
const { session, confirm } = initiator.accept(responder.response);
responder.verifyConfirm(confirm);
const agreed = session.secret.every((b, i) => b === responder.session.secret[i]);

console.log(JSON.stringify({
  subtle: caps.subtle,
  nativeRandom: caps.nativeRandom,
  degradedRandom: caps.degradedRandom,
  suiteIsXChaCha: preferredSuite() === SUITE_XCHACHA20_POLY1305,
  randomLooksRandom: new Set(randomBytes(256)).size > 100,
  roundTripped,
  metaName: meta.name,
  handshakeAgreed: agreed,
  sasDigits: shortAuthString(session).digits,
}));
`;
  const stdout = execFileSync(
    process.execPath,
    ['--import', 'tsx', '--input-type=module', '--eval', script],
    { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] },
  );
  return JSON.parse(stdout.trim().split('\n').pop()!);
}

test('works on a non-secure origin where crypto.subtle is withheld', () => {
  const result = runScenario(`
    const real = globalThis.crypto;
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: { getRandomValues: (a) => real.getRandomValues(a) },
    });
  `);

  assert.equal(result.subtle, false, 'must detect that WebCrypto is unavailable');
  assert.equal(result.nativeRandom, true, 'getRandomValues is still present in insecure contexts');
  assert.equal(result.degradedRandom, false);
  assert.equal(result.suiteIsXChaCha, true, 'must fall back to the pure-JS cipher');
  assert.equal(result.roundTripped, true, 'file must still encrypt and decrypt');
  assert.equal(result.metaName, 'x.bin');
  assert.equal(result.handshakeAgreed, true, 'PQ handshake must still agree on a key');
  assert.match(String(result.sasDigits), /^\d{6}$/);
});

test('works on a host with no usable getRandomValues at all', () => {
  const result = runScenario(`
    // A WebView that exposes crypto but nothing useful on it.
    Object.defineProperty(globalThis, 'crypto', { configurable: true, value: {} });
  `);

  assert.equal(result.subtle, false);
  assert.equal(result.nativeRandom, false, 'must notice the RNG is missing');
  assert.equal(result.degradedRandom, true, 'must flag the downgrade so the UI can warn');
  assert.equal(result.randomLooksRandom, true, 'software DRBG must produce varied output');
  assert.equal(result.roundTripped, true, 'file must still encrypt and decrypt');
  assert.equal(result.handshakeAgreed, true, 'PQ handshake must still complete');
});

test('a broken getRandomValues that returns all zeros is rejected', () => {
  const result = runScenario(`
    Object.defineProperty(globalThis, 'crypto', {
      configurable: true,
      value: { getRandomValues: (a) => a }, // returns the buffer untouched
    });
  `);

  assert.equal(result.nativeRandom, false, 'a no-op RNG must not be trusted');
  assert.equal(result.degradedRandom, true);
  assert.equal(result.randomLooksRandom, true, 'must have switched to the software DRBG');
  assert.equal(result.roundTripped, true);
});
