/**
 * The streaming ZIP writer.
 *
 * A hand-rolled archive is only worth anything if real extractors accept it, so
 * these tests parse the output back the way an extractor does - central
 * directory first - and verify every entry's CRC and bytes independently.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';

import { bundleName, zipSize, zipStream } from '../client/src/zip.ts';
import { crc32 } from '../client/src/util/crc32.ts';
import { selectionSize, sourceFor, selectionLooksCompressible } from '../client/src/source.ts';

/** Minimal File stand-in: Node 20 has File, but this keeps lastModified fixed. */
function fakeFile(name: string, bytes: Uint8Array, lastModified = Date.UTC(2026, 0, 15, 10, 30, 0)): File {
  return new File([bytes], name, { type: 'application/octet-stream', lastModified });
}

function bytesOf(pattern: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (i * pattern + 7) & 0xff;
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
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

interface ParsedEntry {
  name: string;
  crc: number;
  size: number;
  data: Uint8Array;
}

/**
 * Parse via the central directory, which is how every real extractor reads a
 * ZIP - and the reason streaming writers can leave the local headers blank.
 */
function parseZip(archive: Uint8Array): ParsedEntry[] {
  const dv = new DataView(archive.buffer, archive.byteOffset, archive.byteLength);

  // End of central directory: scan back for its signature.
  let eocd = -1;
  for (let i = archive.length - 22; i >= 0; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  assert.notEqual(eocd, -1, 'no end-of-central-directory record');

  const count = dv.getUint16(eocd + 10, true);
  const cdSize = dv.getUint32(eocd + 12, true);
  const cdOffset = dv.getUint32(eocd + 16, true);
  assert.equal(cdOffset + cdSize, eocd, 'central directory does not abut the EOCD');

  const entries: ParsedEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    assert.equal(dv.getUint32(p, true), 0x02014b50, `bad central header at entry ${i}`);
    const flags = dv.getUint16(p + 8, true);
    const method = dv.getUint16(p + 10, true);
    const crc = dv.getUint32(p + 16, true);
    const csize = dv.getUint32(p + 20, true);
    const usize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOffset = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(archive.subarray(p + 46, p + 46 + nameLen));

    assert.equal(method, 0, `${name} must be STOREd`);
    assert.equal(csize, usize, `${name}: stored entries cannot change size`);
    assert.ok(flags & 0x0800, `${name} must be flagged UTF-8`);
    assert.ok(flags & 0x0008, `${name} must be flagged as using a data descriptor`);

    // Local header, then the data immediately after it.
    assert.equal(dv.getUint32(localOffset, true), 0x04034b50, `bad local header for ${name}`);
    const localNameLen = dv.getUint16(localOffset + 26, true);
    const localExtraLen = dv.getUint16(localOffset + 28, true);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const data = archive.slice(dataStart, dataStart + usize);

    // The data descriptor sits right after the payload and must agree.
    const desc = dataStart + usize;
    assert.equal(dv.getUint32(desc, true), 0x08074b50, `missing data descriptor for ${name}`);
    assert.equal(dv.getUint32(desc + 4, true), crc, `${name}: descriptor CRC disagrees with the directory`);
    assert.equal(dv.getUint32(desc + 12, true), usize, `${name}: descriptor size disagrees with the directory`);

    entries.push({ name, crc, size: usize, data });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

// ---------------------------------------------------------------------------

test('archive round-trips every entry byte-for-byte', async () => {
  const a = bytesOf(3, 5000);
  const b = bytesOf(11, 1);
  const c = bytesOf(7, 64 * 1024);
  const files = [fakeFile('notes.txt', a), fakeFile('tiny.bin', b), fakeFile('big.dat', c)];

  const archive = await drain(zipStream(files));
  const entries = parseZip(archive);

  assert.deepEqual(entries.map((e) => e.name), ['notes.txt', 'tiny.bin', 'big.dat']);
  assert.deepEqual(entries[0].data, a);
  assert.deepEqual(entries[1].data, b);
  assert.deepEqual(entries[2].data, c);
  for (const entry of entries) {
    assert.equal(entry.crc, crc32(entry.data), `${entry.name}: CRC mismatch`);
  }
});

test('zipSize predicts the exact archive length', async () => {
  // The store-and-forward upload declares this before reading a byte, so being
  // off by even one would make the server reject the commit.
  for (const sizes of [[0], [1], [100, 200], [5000, 1, 65536], [10, 20, 30, 40, 50]]) {
    const files = sizes.map((n, i) => fakeFile(`f${i}.bin`, bytesOf(i + 1, n)));
    const archive = await drain(zipStream(files));
    assert.equal(archive.length, zipSize(files), `sizes=${sizes.join(',')}`);
  }
});

test('an empty file is a valid entry', async () => {
  const files = [fakeFile('empty.txt', new Uint8Array(0)), fakeFile('after.txt', bytesOf(5, 10))];
  const entries = parseZip(await drain(zipStream(files)));
  assert.equal(entries[0].size, 0);
  assert.equal(entries[0].crc, 0);
  assert.deepEqual(entries[1].data, bytesOf(5, 10));
});

test('colliding names are made unique instead of silently overwriting', async () => {
  const files = [
    fakeFile('photo.jpg', bytesOf(1, 20)),
    fakeFile('photo.jpg', bytesOf(2, 30)),
    fakeFile('photo.jpg', bytesOf(3, 40)),
    fakeFile('README', bytesOf(4, 50)),
    fakeFile('README', bytesOf(5, 60)),
  ];
  const entries = parseZip(await drain(zipStream(files)));

  assert.deepEqual(entries.map((e) => e.name), [
    'photo.jpg', 'photo (1).jpg', 'photo (2).jpg', 'README', 'README (1)',
  ]);
  // Each kept its own bytes.
  assert.deepEqual(entries[1].data, bytesOf(2, 30));
  assert.deepEqual(entries[2].data, bytesOf(3, 40));
});

test('path components are stripped from entry names', async () => {
  const files = [
    fakeFile('../../etc/passwd', bytesOf(1, 8)),
    fakeFile('C:\\Windows\\evil.dll', bytesOf(2, 8)),
  ];
  const entries = parseZip(await drain(zipStream(files)));
  assert.deepEqual(entries.map((e) => e.name), ['passwd', 'evil.dll']);
});

test('non-ASCII names survive as UTF-8', async () => {
  const files = [fakeFile('résumé — ünïcode 日本語.txt', bytesOf(9, 16))];
  const entries = parseZip(await drain(zipStream(files)));
  assert.equal(entries[0].name, 'résumé — ünïcode 日本語.txt');
});

test('the archive still gzips well, since entries are stored uncompressed', async () => {
  // This is why entries are STOREd: the transfer pipeline gzips the whole
  // stream, and compressing twice would cost CPU for nothing.
  const text = new TextEncoder().encode('the quick brown fox '.repeat(2000));
  const archive = await drain(zipStream([fakeFile('a.txt', text), fakeFile('b.txt', text)]));
  const gzipped = zlib.gzipSync(Buffer.from(archive));
  assert.ok(gzipped.length < archive.length / 10, `expected strong compression, got ${gzipped.length}/${archive.length}`);
});

// ---------------------------------------------------------------------------
// Selection handling
// ---------------------------------------------------------------------------

test('a single file is sent as itself, several become a bundle', () => {
  const one = [fakeFile('report.pdf', bytesOf(1, 100))];
  const single = sourceFor(one);
  assert.equal(single.bundled, false);
  assert.equal(single.name, 'report.pdf');
  assert.equal(single.size, 100);
  assert.equal(selectionSize(one), 100);

  const many = [fakeFile('a.txt', bytesOf(1, 10)), fakeFile('b.txt', bytesOf(2, 20))];
  const bundle = sourceFor(many);
  assert.equal(bundle.bundled, true);
  assert.equal(bundle.fileCount, 2);
  assert.match(bundle.name, /^qsft-2-files-\d{4}-\d{2}-\d{2}\.zip$/);
  assert.equal(bundle.size, zipSize(many));
  assert.equal(bundle.type, 'application/zip');
});

test('a bundle streams the same bytes through the source wrapper', async () => {
  const files = [fakeFile('a.bin', bytesOf(1, 500)), fakeFile('b.bin', bytesOf(2, 700))];
  const viaSource = await drain(sourceFor(files).stream());
  const entries = parseZip(viaSource);
  assert.equal(viaSource.length, sourceFor(files).size);
  assert.deepEqual(entries[0].data, bytesOf(1, 500));
  assert.deepEqual(entries[1].data, bytesOf(2, 700));
});

test('compressibility is judged on the members, not the .zip name', () => {
  const media = [fakeFile('a.jpg', bytesOf(1, 10)), fakeFile('b.mp4', bytesOf(2, 10))];
  const mixed = [fakeFile('a.jpg', bytesOf(1, 10)), fakeFile('notes.txt', bytesOf(2, 10))];

  // The bundle is named ".zip", which would otherwise read as incompressible.
  assert.equal(selectionLooksCompressible(media), false);
  assert.equal(selectionLooksCompressible(mixed), true);
});

test('bundleName reflects how many files were selected', () => {
  const files = [1, 2, 3, 4].map((n) => fakeFile(`f${n}.bin`, bytesOf(n, 4)));
  assert.match(bundleName(files), /^qsft-4-files-/);
});
