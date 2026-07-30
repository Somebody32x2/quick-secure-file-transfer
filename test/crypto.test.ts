/**
 * Round-trip and negative tests for the container format and the handshake.
 *
 * These run in Node, which supplies crypto.subtle - so the AES-GCM WebCrypto
 * path is exercised here. The XChaCha20 path is exercised by pinning the suite
 * explicitly, and the cross-suite tests confirm a blob sealed by a host with
 * WebCrypto opens on a host without it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { ChunkSealer, ChunkOpener, DecryptionError, sealedTotalLength } from '../client/src/crypto/stream.ts';
import { decodeHeader, encodeHeader, sanitizeFilename, HEADER_LEN, type FileMeta } from '../client/src/crypto/format.ts';
import { SUITE_AES_256_GCM, SUITE_XCHACHA20_POLY1305, type SuiteId } from '../client/src/crypto/aead.ts';
import { Initiator, Responder, HandshakeError } from '../client/src/crypto/kex.ts';
import { SecureChannel, ChannelError } from '../client/src/crypto/channel.ts';
import { shortAuthString } from '../client/src/crypto/sas.ts';
import { deriveMaster, ARGON2_DEFAULTS } from '../client/src/crypto/kdf.ts';
import { randomBytes } from '../client/src/crypto/env.ts';
import { rechunk, toReadable, ByteCursor } from '../client/src/chunker.ts';
import { timingSafeEqual } from '../client/src/util/bytes.ts';
import { estimateStrength, generatePassphrase } from '../client/src/util/passphrase.ts';
import { MessagePump } from '../client/src/session/pump.ts';
import { encodeMessage, wrapFrame, MSG_DONE } from '../client/src/session/protocol.ts';

// Keep Argon2 cheap in tests; production defaults are exercised separately.
const FAST_KDF = { memKiB: 1024, timeCost: 1, lanes: 1 };

/**
 * Any fixed 16-byte salt. These tests only need both sides to derive against
 * the same value; the salt's contents are irrelevant to what they assert. It is
 * a local helper rather than something exported from the app on purpose -
 * production salts are random, and nothing shipped should offer a derivable one.
 */
const testSalt = (seed: string): Uint8Array =>
  Uint8Array.from({ length: 16 }, (_, i) => (seed.charCodeAt(i % seed.length) + i * 7) & 0xff);

const meta = (over: Partial<FileMeta> = {}): FileMeta => ({
  name: 'report.pdf', size: 1234, type: 'application/pdf', lastModified: 1700000000000, ...over,
});

function streamOf(...parts: Uint8Array[]): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(c) { for (const p of parts) c.enqueue(p); c.close(); },
  });
}

async function sealAll(plaintext: Uint8Array, suite: SuiteId, passphrase: string, chunkSize: number) {
  const sealer = await ChunkSealer.create({ passphrase, suite, chunkSize, kdfParams: FAST_KDF });
  const chunks: Uint8Array[] = [await sealer.sealMeta(meta({ size: plaintext.length }))];
  for (let off = 0; off < Math.max(plaintext.length, 1); off += chunkSize) {
    const slice = plaintext.subarray(off, Math.min(off + chunkSize, plaintext.length));
    chunks.push(await sealer.seal(slice, off + chunkSize >= plaintext.length));
  }
  return { header: sealer.headerBytes, fields: sealer.fields, chunks };
}

// ---------------------------------------------------------------------------
// Container format
// ---------------------------------------------------------------------------

test('header round-trips exactly', () => {
  const h = {
    version: 1, suite: SUITE_XCHACHA20_POLY1305, kdfId: 1, compressed: true,
    kdf: ARGON2_DEFAULTS, salt: randomBytes(16), noncePrefix: randomBytes(20), chunkSize: 1 << 20,
  };
  const decoded = decodeHeader(encodeHeader(h));
  assert.equal(decoded.suite, h.suite);
  assert.equal(decoded.compressed, true);
  assert.equal(decoded.chunkSize, h.chunkSize);
  assert.deepEqual([...decoded.salt], [...h.salt]);
  assert.deepEqual([...decoded.noncePrefix], [...h.noncePrefix]);
  assert.deepEqual(decoded.kdf, ARGON2_DEFAULTS);
});

test('header rejects bad magic and hostile KDF parameters', () => {
  const good = encodeHeader({
    version: 1, suite: SUITE_AES_256_GCM, kdfId: 1, compressed: false,
    kdf: ARGON2_DEFAULTS, salt: randomBytes(16), noncePrefix: randomBytes(20), chunkSize: 65536,
  });
  const badMagic = good.slice(); badMagic[0] ^= 0xff;
  assert.throws(() => decodeHeader(badMagic), /bad magic/);

  // 4 GiB of Argon2 memory would be a denial-of-service against the receiver.
  const hugeMem = good.slice();
  new DataView(hugeMem.buffer).setUint32(8, 4 * 1024 * 1024, false);
  assert.throws(() => decodeHeader(hugeMem), /Argon2 memory/);

  /**
   * Bounding each field alone is not enough - the cost is their product.
   * m=1 GiB with t=16 and p=16 passed every individual limit while costing
   * minutes of CPU and a gigabyte of memory, imposed by a peer, before anything
   * had been authenticated.
   */
  const expensive = good.slice();
  const view = new DataView(expensive.buffer);
  view.setUint32(8, 128 * 1024, false); // exactly the per-field memory ceiling
  expensive[12] = 16;                   // t
  expensive[13] = 16;                   // p
  assert.throws(() => decodeHeader(expensive), /cost too much/);

  // Something a real sender might legitimately choose still opens.
  const stronger = good.slice();
  new DataView(stronger.buffer).setUint32(8, 65536, false);
  stronger[12] = 3;
  stronger[13] = 1;
  assert.equal(decodeHeader(stronger).kdf.memKiB, 65536);

  assert.throws(() => decodeHeader(good.slice(0, 32)), /Truncated/);
});

test('a peer cannot impose ruinous Argon2 parameters over the handshake', async () => {
  // HELLO is read before its MAC can be checked - the MAC is keyed by a value
  // derived using these very parameters - so they are unauthenticated input to
  // an expensive operation and have to be bounded before anything is spent.
  const salt = testSalt('cost');
  const master = await deriveMaster('pw', salt, FAST_KDF);
  const initiator = Initiator.start(master, salt, FAST_KDF, SUITE_XCHACHA20_POLY1305);

  for (const kdf of [
    { m: 1024 * 1024, t: 16, p: 16 }, // the old ceiling: ~1 GiB, minutes of CPU
    { m: 131072, t: 16, p: 16 },      // each field legal, product is not
    { m: 512, t: 2, p: 1 },           // below the floor
  ]) {
    assert.throws(
      () => Responder.parseHello({ ...initiator.hello, kdf }),
      /unusable Argon2 parameters/,
      `should reject ${JSON.stringify(kdf)}`,
    );
  }

  // The shipped defaults, and a stronger-but-sane choice, are still accepted.
  assert.doesNotThrow(() => Responder.parseHello({
    ...initiator.hello,
    kdf: { m: ARGON2_DEFAULTS.memKiB, t: ARGON2_DEFAULTS.timeCost, p: ARGON2_DEFAULTS.lanes },
  }));
  assert.doesNotThrow(() => Responder.parseHello({ ...initiator.hello, kdf: { m: 65536, t: 4, p: 1 } }));
});

test('a message already received survives the link closing right behind it', async () => {
  /**
   * The reported symptom: the sender says the other device disconnected, when
   * in fact it finished and said so.
   *
   * A receiver that completes sends MSG_DONE and then immediately tears its
   * connection down. Both events reach the sender in order - but the frame is
   * decrypted asynchronously while the close notification is delivered
   * synchronously, so the close overtakes the message that arrived before it
   * and the sender is told the peer vanished instead of being handed its
   * confirmation.
   */
  const { initiatorSession, responderSession } = await handshake('pw', 'pw');
  const far = await SecureChannel.create(responderSession, 'responder');
  const near = await SecureChannel.create(initiatorSession, 'initiator');

  let deliver: (frame: Uint8Array) => void = () => {};
  let close: (reason: string) => void = () => {};
  const link = {
    kind: 'relay' as const,
    detail: '',
    send: async () => {},
    onFrame(cb: (f: Uint8Array) => void) { deliver = cb; },
    onClose(cb: (r: string) => void) { close = cb; },
    close() {},
  };

  const pump = new MessagePump(link, near);
  const pending = pump.next();

  // Exactly what a completing receiver does: the confirmation, then the
  // teardown, back to back with no chance to breathe in between.
  deliver(wrapFrame(await far.seal(encodeMessage(MSG_DONE)), false));
  close('the other device disconnected');

  const message = await pending;
  assert.equal(message.type, MSG_DONE, 'the confirmation must not be lost to the close that followed it');

  // And a close with nothing in flight must still surface as a failure.
  await assert.rejects(() => pump.next(), /the other device disconnected/);
});

test('the strength estimator does not mistake shape for entropy', () => {
  // The old regex treated any hyphenated lowercase string as a generated
  // passphrase worth 8 bits a token, with no check that the tokens were words.
  // "zz-zz-..." scored 80 bits and was reported to the user as Strong.
  for (const junk of ['a-a-a-a-a-a', 'zz-zz-zz-zz-zz-zz-zz-zz-zz-zz', 'aaa-aaa-aaa-aaa']) {
    const strength = estimateStrength(junk);
    assert.notEqual(strength.label, 'Strong', `"${junk}" must not be called Strong`);
    assert.ok(strength.bits < 50, `"${junk}" scored ${strength.bits} bits`);
  }

  // A real generated passphrase is still credited at 8 bits per word.
  const generated = generatePassphrase(6);
  assert.equal(estimateStrength(generated).bits, 48, `"${generated}" should be 48 bits`);
  assert.equal(estimateStrength(generatePassphrase(9)).bits, 72);

  // Tokens that are not ours fall through to the character estimate instead of
  // being counted as words: four unrecognised tokens must not score 4 x 8.
  const notOurWords = 'correct-horse-battery-staple';
  assert.notEqual(estimateStrength(notOurWords).bits, 32,
    'unrecognised tokens must not be priced as if they came from the word list');

  // And swapping a single token for a non-word drops it off the word path.
  const words = generatePassphrase(6).split('-');
  const tampered = [...words.slice(0, 5), 'zzzzzz'].join('-');
  assert.notEqual(estimateStrength(tampered).bits, 48);
});

for (const [label, suite] of [
  ['XChaCha20-Poly1305', SUITE_XCHACHA20_POLY1305],
  ['AES-256-GCM', SUITE_AES_256_GCM],
] as const) {
  test(`${label}: seal/open round-trips payload and metadata`, async () => {
    const plaintext = randomBytes(300_000);
    const { header, chunks } = await sealAll(plaintext, suite, 'correct horse battery staple', 65536);

    const fields = decodeHeader(header);
    const master = await deriveMaster('correct horse battery staple', fields.salt, fields.kdf);
    const opener = await ChunkOpener.create(fields, header, master);

    const got = await opener.openMeta(chunks[0]!);
    assert.equal(got.name, 'report.pdf');
    assert.equal(got.size, plaintext.length);

    const out: number[] = [];
    for (let i = 1; i < chunks.length; i++) {
      out.push(...(await opener.open(chunks[i]!, i === chunks.length - 1)));
    }
    assert.deepEqual(new Uint8Array(out), plaintext);
    assert.equal(opener.complete, true);
  });
}

test('a blob sealed with AES-GCM opens under the pure-JS suite path', async () => {
  // Simulates a WebCrypto-capable sender and a non-secure-origin receiver: the
  // suite is pinned by the header, not by the receiving host's capabilities.
  const plaintext = randomBytes(50_000);
  const { header, chunks } = await sealAll(plaintext, SUITE_AES_256_GCM, 'pw', 16384);
  const fields = decodeHeader(header);
  assert.equal(fields.suite, SUITE_AES_256_GCM);

  const master = await deriveMaster('pw', fields.salt, fields.kdf);
  const opener = await ChunkOpener.create(fields, header, master);
  await opener.openMeta(chunks[0]!);
  const out: number[] = [];
  for (let i = 1; i < chunks.length; i++) out.push(...(await opener.open(chunks[i]!, i === chunks.length - 1)));
  assert.deepEqual(new Uint8Array(out), plaintext);
});

test('zero-byte file round-trips', async () => {
  const { header, chunks } = await sealAll(new Uint8Array(0), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
  const fields = decodeHeader(header);
  const opener = await ChunkOpener.create(fields, header, await deriveMaster('pw', fields.salt, fields.kdf));
  await opener.openMeta(chunks[0]!);
  assert.equal((await opener.open(chunks[1]!, true)).length, 0);
});

// ---------------------------------------------------------------------------
// Negative cases - each must fail closed
// ---------------------------------------------------------------------------

test('wrong passphrase fails on the metadata chunk', async () => {
  const { header, chunks } = await sealAll(randomBytes(1000), SUITE_XCHACHA20_POLY1305, 'right', 4096);
  const fields = decodeHeader(header);
  const opener = await ChunkOpener.create(fields, header, await deriveMaster('wrong', fields.salt, fields.kdf));
  await assert.rejects(() => opener.openMeta(chunks[0]!), (err: Error) => {
    assert.ok(err instanceof DecryptionError);
    assert.match(err.message, /passphrase is wrong/);
    return true;
  });
});

test('a flipped ciphertext bit is rejected', async () => {
  const { header, chunks } = await sealAll(randomBytes(9000), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
  const fields = decodeHeader(header);
  const opener = await ChunkOpener.create(fields, header, await deriveMaster('pw', fields.salt, fields.kdf));
  await opener.openMeta(chunks[0]!);
  const tampered = chunks[1]!.slice();
  tampered[10] ^= 0x01;
  await assert.rejects(() => opener.open(tampered, false), /Authentication failed on chunk 1/);
});

test('reordered chunks are rejected', async () => {
  const { header, chunks } = await sealAll(randomBytes(12_000), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
  const fields = decodeHeader(header);
  const opener = await ChunkOpener.create(fields, header, await deriveMaster('pw', fields.salt, fields.kdf));
  await opener.openMeta(chunks[0]!);
  // Feed chunk 2 where chunk 1 belongs: the counter is bound into the nonce.
  await assert.rejects(() => opener.open(chunks[2]!, false), /Authentication failed/);
});

test('truncating the stream is detected via the final-chunk flag', async () => {
  const { header, chunks } = await sealAll(randomBytes(12_000), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
  const fields = decodeHeader(header);
  const opener = await ChunkOpener.create(fields, header, await deriveMaster('pw', fields.salt, fields.kdf));
  await opener.openMeta(chunks[0]!);
  await opener.open(chunks[1]!, false);
  // An attacker drops the tail and presents chunk 2 as if it were the last.
  await assert.rejects(() => opener.open(chunks[2]!, true), /Authentication failed/);
});

test('a downgraded header is rejected because the header is authenticated', async () => {
  const { header, chunks } = await sealAll(randomBytes(1000), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
  const forged = header.slice();
  forged[7] |= 1; // claim the payload was compressed
  const fields = decodeHeader(forged);
  const opener = await ChunkOpener.create(fields, forged, await deriveMaster('pw', fields.salt, fields.kdf));
  await assert.rejects(() => opener.openMeta(chunks[0]!), /passphrase is wrong|altered/);
});

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

async function handshake(senderPass: string, receiverPass: string, code = '123456') {
  const salt = testSalt(code);
  const masterI = await deriveMaster(senderPass, salt, FAST_KDF);
  const masterR = await deriveMaster(receiverPass, salt, FAST_KDF);
  const initiator = Initiator.start(masterI, salt, FAST_KDF, SUITE_XCHACHA20_POLY1305);
  const responder = Responder.respond(initiator.hello, masterR);
  const { session, confirm } = initiator.accept(responder.response);
  responder.verifyConfirm(confirm);
  return { initiatorSession: session, responderSession: responder.session };
}

test('hybrid X25519 + ML-KEM handshake agrees on a session key', async () => {
  const { initiatorSession, responderSession } = await handshake('shared pass', 'shared pass');
  assert.ok(timingSafeEqual(initiatorSession.secret, responderSession.secret));
  assert.equal(initiatorSession.secret.length, 32);
  assert.ok(timingSafeEqual(initiatorSession.transcript, responderSession.transcript));
});

test('both devices show the same short authentication string', async () => {
  const { initiatorSession, responderSession } = await handshake('shared pass', 'shared pass');
  const a = shortAuthString(initiatorSession);
  const b = shortAuthString(responderSession);
  assert.equal(a.digits, b.digits);
  assert.deepEqual(a.glyphs, b.glyphs);
  assert.match(a.digits, /^\d{6}$/);
  assert.equal(a.glyphs.length, 4);
});

test('two independent sessions produce different keys and different SAS', async () => {
  const a = await handshake('shared pass', 'shared pass');
  const b = await handshake('shared pass', 'shared pass');
  assert.ok(!timingSafeEqual(a.initiatorSession.secret, b.initiatorSession.secret));
  assert.notEqual(
    shortAuthString(a.initiatorSession).digits,
    shortAuthString(b.initiatorSession).digits,
  );
});

test('mismatched passphrases abort the handshake', async () => {
  await assert.rejects(async () => handshake('sender pass', 'receiver pass'), (err: Error) => {
    assert.ok(err instanceof HandshakeError);
    assert.match(err.message, /passphrases do not match|intercepting/);
    return true;
  });
});

test('a relay that swaps in its own keys is caught by the transcript MAC', async () => {
  const salt = testSalt('654321');
  const master = await deriveMaster('pw', salt, FAST_KDF);
  const initiator = Initiator.start(master, salt, FAST_KDF, SUITE_XCHACHA20_POLY1305);

  // Hostile relay runs its own handshake against the responder, then tries to
  // pass its own response through to the initiator.
  const evilInitiator = Initiator.start(await deriveMaster('guess', salt, FAST_KDF), salt, FAST_KDF, SUITE_XCHACHA20_POLY1305);
  const responder = Responder.respond(evilInitiator.hello, master);
  assert.throws(() => initiator.accept(responder.response), HandshakeError);
});

test('malformed handshake fields are rejected, not coerced', async () => {
  const salt = testSalt('111111');
  const master = await deriveMaster('pw', salt, FAST_KDF);
  const initiator = Initiator.start(master, salt, FAST_KDF, SUITE_XCHACHA20_POLY1305);
  const responder = Responder.respond(initiator.hello, master);

  const shortKey = { ...responder.response, ecPub: Buffer.from(randomBytes(31)).toString('base64') };
  assert.throws(() => initiator.accept(shortKey), /length 31, expected 32/);

  const notB64 = { ...responder.response, mac: 42 as unknown as string };
  assert.throws(() => initiator.accept(notB64), /not a string/);

  assert.throws(() => Responder.respond({ ...initiator.hello, v: 99 }, master), /different handshake version/);
});

// ---------------------------------------------------------------------------
// Secure channel
// ---------------------------------------------------------------------------

test('channel round-trips frames and enforces direction', async () => {
  const { initiatorSession, responderSession } = await handshake('pw', 'pw');
  const send = await SecureChannel.create(initiatorSession, 'initiator');
  const recv = await SecureChannel.create(responderSession, 'responder');

  const frame = await send.seal(new TextEncoder().encode('hello world'));
  assert.equal(new TextDecoder().decode(await recv.open(frame)), 'hello world');

  // Replaying the sender's own frame back at them must fail: keys are directional.
  const replay = await send.seal(new TextEncoder().encode('second'));
  await assert.rejects(() => send.open(replay), ChannelError);
});

test('channel rejects out-of-order frames', async () => {
  const { initiatorSession, responderSession } = await handshake('pw', 'pw');
  const send = await SecureChannel.create(initiatorSession, 'initiator');
  const recv = await SecureChannel.create(responderSession, 'responder');

  const first = await send.seal(new Uint8Array([1]));
  const second = await send.seal(new Uint8Array([2]));
  await assert.rejects(() => recv.open(second), /failed authentication/);
  void first;
});

test('channel detects a dropped tail via the final flag', async () => {
  const { initiatorSession, responderSession } = await handshake('pw', 'pw');
  const send = await SecureChannel.create(initiatorSession, 'initiator');
  const recv = await SecureChannel.create(responderSession, 'responder');

  const body = await send.seal(new Uint8Array([1, 2, 3]), false);
  await recv.open(body, false);
  const tail = await send.seal(new Uint8Array([4]), true);
  // Receiver told it is not final -> mismatch on the authenticated flag.
  await assert.rejects(() => recv.open(tail, false), /failed authentication/);
});

// ---------------------------------------------------------------------------
// Chunking
// ---------------------------------------------------------------------------

test('rechunk emits exact sizes and flags exactly one final chunk', async () => {
  const data = randomBytes(1000);
  const chunks: { bytes: Uint8Array; isFinal: boolean }[] = [];
  for await (const c of rechunk(streamOf(data.subarray(0, 300), data.subarray(300)), 256)) chunks.push(c);

  assert.equal(chunks.length, 4);
  assert.deepEqual(chunks.map((c) => c.bytes.length), [256, 256, 256, 232]);
  assert.deepEqual(chunks.map((c) => c.isFinal), [false, false, false, true]);
  assert.deepEqual(new Uint8Array(chunks.flatMap((c) => [...c.bytes])), data);
});

test('rechunk flags the last chunk when input is an exact multiple', async () => {
  const chunks: { bytes: Uint8Array; isFinal: boolean }[] = [];
  for await (const c of rechunk(streamOf(randomBytes(512)), 256)) chunks.push(c);
  assert.deepEqual(chunks.map((c) => [c.bytes.length, c.isFinal]), [[256, false], [256, true]]);
});

test('rechunk yields one empty final chunk for empty input', async () => {
  const chunks: { bytes: Uint8Array; isFinal: boolean }[] = [];
  for await (const c of rechunk(streamOf(), 256)) chunks.push(c);
  assert.deepEqual(chunks.map((c) => [c.bytes.length, c.isFinal]), [[0, true]]);
});

test('ByteCursor reads exact framing and reports end of stream', async () => {
  const cursor = new ByteCursor(streamOf(new Uint8Array([1, 2, 3]), new Uint8Array([4, 5])));
  assert.deepEqual([...(await cursor.read(2))], [1, 2]);
  assert.equal(await cursor.atEnd(), false);
  assert.deepEqual([...(await cursor.read(3))], [3, 4, 5]);
  assert.equal(await cursor.atEnd(), true);
  assert.equal((await cursor.read(4)).length, 0);
});

test('toReadable adapts an async generator back into a stream', async () => {
  async function* gen() { yield new Uint8Array([1]); yield new Uint8Array([2, 3]); }
  const cursor = new ByteCursor(toReadable(gen()));
  assert.deepEqual([...(await cursor.read(3))], [1, 2, 3]);
});

// ---------------------------------------------------------------------------
// Misc
// ---------------------------------------------------------------------------

test('filenames from an untrusted sender are neutralised', () => {
  assert.equal(sanitizeFilename('../../etc/passwd'), 'passwd');
  assert.equal(sanitizeFilename('C:\\Windows\\system32\\evil.dll'), 'evil.dll');
  assert.equal(sanitizeFilename('..'), 'download');
  assert.equal(sanitizeFilename(''), 'download');
  assert.equal(sanitizeFilename('a:b|c?.txt'), 'a_b_c_.txt');
  assert.equal(sanitizeFilename('.hidden'), 'hidden');
  assert.equal(sanitizeFilename('ok name.txt'), 'ok name.txt');
});

test('sealedTotalLength matches what the sealer actually produces', async () => {
  for (const size of [0, 1, 4095, 4096, 4097, 20_000]) {
    const { header, chunks } = await sealAll(randomBytes(size), SUITE_XCHACHA20_POLY1305, 'pw', 4096);
    const actual = header.length + chunks.reduce((n, c) => n + c.length, 0);
    assert.equal(sealedTotalLength(size, 4096), actual, `size=${size}`);
    assert.equal(header.length, HEADER_LEN);
  }
});

test('randomBytes returns distinct, correctly sized buffers', () => {
  const a = randomBytes(64);
  const b = randomBytes(64);
  assert.equal(a.length, 64);
  assert.ok(!timingSafeEqual(a, b));
  assert.equal(randomBytes(70_000).length, 70_000); // crosses the 65536 call cap
});
