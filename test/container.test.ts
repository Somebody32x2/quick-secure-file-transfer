/**
 * Serializes a full container exactly as storedSend does and parses it exactly
 * as storedReceive does, including the gzip path. This is the test that would
 * catch a framing mistake between the two - the failure mode that would only
 * otherwise show up as a corrupt 2 GB download.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { ChunkOpener, ChunkSealer, sealedTotalLength } from '../client/src/crypto/stream.ts';
import { deriveMaster } from '../client/src/crypto/kdf.ts';
import { TAG_LEN, SUITE_XCHACHA20_POLY1305, type SuiteId } from '../client/src/crypto/aead.ts';
import { decodeHeader, HEADER_LEN, META_BLOCK_LEN } from '../client/src/crypto/format.ts';
import { backpressuredSource, ByteCursor, rechunk } from '../client/src/chunker.ts';
import { randomBytes } from '../client/src/crypto/env.ts';

const FAST_KDF = { memKiB: 1024, timeCost: 1, lanes: 1 };
const CHUNK = 4096;

function streamOf(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    start(c) { c.enqueue(bytes); c.close(); },
  });
}

/** Mirror of storedSend's serialization. */
async function serialize(
  plaintext: Uint8Array,
  name: string,
  passphrase: string,
  { compress = false, suite = SUITE_XCHACHA20_POLY1305 as SuiteId } = {},
): Promise<Uint8Array> {
  const sealer = await ChunkSealer.create({
    passphrase, suite, chunkSize: CHUNK, compressed: compress, kdfParams: FAST_KDF,
  });

  const parts: Uint8Array[] = [sealer.headerBytes];
  parts.push(await sealer.sealMeta({
    name, size: plaintext.length, type: 'application/octet-stream', lastModified: 1700000000000,
  }));

  let source: ReadableStream<Uint8Array> = streamOf(plaintext);
  if (compress) source = source.pipeThrough(new CompressionStream('gzip') as any);

  for await (const { bytes, isFinal } of rechunk(source, CHUNK)) {
    parts.push(await sealer.seal(bytes, isFinal));
  }

  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

/** Mirror of storedReceive's parsing. */
async function deserialize(container: Uint8Array, passphrase: string) {
  const cursor = new ByteCursor(streamOf(container));

  const headerBytes = await cursor.read(HEADER_LEN);
  const fields = decodeHeader(headerBytes);
  const master = await deriveMaster(passphrase, fields.salt, fields.kdf);
  const opener = await ChunkOpener.create(fields, headerBytes, master);

  const meta = await opener.openMeta(await cursor.read(META_BLOCK_LEN + TAG_LEN));

  const collected: Uint8Array[] = [];
  for (;;) {
    const sealed = await cursor.read(fields.chunkSize + TAG_LEN);
    if (sealed.length === 0) throw new Error('ended before final chunk');
    const isFinal = await cursor.atEnd();
    collected.push(await opener.open(sealed, isFinal));
    if (isFinal) break;
  }
  assert.equal(opener.complete, true);

  let bytes = concat(collected);
  if (fields.compressed) {
    bytes = await drain(streamOf(bytes).pipeThrough(new DecompressionStream('gzip') as any));
  }
  return { meta, bytes, fields };
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  const reader = stream.getReader();
  const parts: Uint8Array[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    parts.push(value);
  }
  return concat(parts);
}

// ---------------------------------------------------------------------------

test('container round-trips at every boundary condition', async () => {
  // Sizes chosen around exact chunk multiples, where off-by-one framing lives.
  for (const size of [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7]) {
    const plaintext = randomBytes(size);
    const container = await serialize(plaintext, 'data.bin', 'pw');
    assert.equal(container.length, sealedTotalLength(size, CHUNK), `serialized length, size=${size}`);

    const { meta, bytes } = await deserialize(container, 'pw');
    assert.equal(meta.size, size, `meta size, size=${size}`);
    assert.deepEqual(bytes, plaintext, `payload, size=${size}`);
  }
});

test('compressed container round-trips and actually shrinks', async () => {
  // Highly compressible payload so we can assert compression did something.
  const plaintext = new Uint8Array(200_000).fill(0x41);
  const container = await serialize(plaintext, 'a.txt', 'pw', { compress: true });
  assert.ok(container.length < plaintext.length / 10, 'expected substantial compression');

  const { meta, bytes, fields } = await deserialize(container, 'pw');
  assert.equal(fields.compressed, true);
  assert.equal(meta.size, plaintext.length);
  assert.deepEqual(bytes, plaintext);
});

test('metadata block is fixed width regardless of filename length', async () => {
  const short = await serialize(randomBytes(100), 'a', 'pw');
  const long = await serialize(randomBytes(100), 'a'.repeat(180) + '.txt', 'pw');
  // Same payload size and same total length => the filename length does not leak.
  assert.equal(short.length, long.length);

  const { meta } = await deserialize(long, 'pw');
  assert.equal(meta.name.length, 184);
});

test('a truncated container is rejected rather than silently short', async () => {
  const container = await serialize(randomBytes(3 * CHUNK), 'data.bin', 'pw');
  // Drop the final chunk entirely.
  const truncated = container.subarray(0, container.length - (CHUNK + TAG_LEN));
  await assert.rejects(() => deserialize(truncated, 'pw'), /Authentication failed|ended before/);
});

test('flipping a byte anywhere in the container is caught', async () => {
  const container = await serialize(randomBytes(2 * CHUNK), 'data.bin', 'pw');
  for (const position of [70, HEADER_LEN + 5, container.length - 20]) {
    const damaged = container.slice();
    damaged[position] ^= 0x40;
    await assert.rejects(() => deserialize(damaged, 'pw'), `expected rejection at byte ${position}`);
  }
});

test('the wrong passphrase never yields plaintext', async () => {
  const container = await serialize(randomBytes(5000), 'secret.txt', 'the right one');
  await assert.rejects(() => deserialize(container, 'the wrong one'), /passphrase is wrong/);
});

// ---------------------------------------------------------------------------
// Backpressure
// ---------------------------------------------------------------------------

test('a slow destination paces the producer instead of queueing the file', async () => {
  const source = backpressuredSource();
  let pushed = 0;
  let read = 0;
  let maxOutstanding = 0;

  const consumer = (async () => {
    const reader = source.stream.getReader();
    for (;;) {
      const { done } = await reader.read();
      if (done) break;
      read++;
      await new Promise((r) => setTimeout(r, 5)); // a slow sink
    }
  })();

  for (let i = 0; i < 12; i++) {
    await source.push(new Uint8Array([i]));
    pushed++;
    maxOutstanding = Math.max(maxOutstanding, pushed - read);
  }
  source.close();
  await consumer;

  assert.equal(read, 12, 'every chunk must reach the consumer');
  // Without backpressure this would reach 12: the producer would run to
  // completion while the consumer was still on its first chunk.
  assert.ok(maxOutstanding <= 3, `producer ran ${maxOutstanding} chunks ahead of the consumer`);
});

test('failing the source unblocks a producer waiting on backpressure', async () => {
  const source = backpressuredSource();
  source.stream.getReader(); // never actually reads, so the producer blocks at once

  // The queue holds one chunk, so this push parks waiting for a pull that
  // will never come - exactly the state a dropped link leaves the loop in.
  const blocked = source.push(new Uint8Array([1]));
  source.fail(new Error('link dropped'));

  // The push must reject rather than hang forever, so the receive loop can unwind.
  await assert.rejects(() => blocked, /link dropped/);
});
