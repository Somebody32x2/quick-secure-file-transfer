/**
 * QSFT container format v1.
 *
 * Layout:
 *   [64-byte cleartext header][chunk 0][chunk 1]...[chunk n]
 *
 * Chunk 0 is the encrypted metadata (filename, size, mime type). Chunks 1..n
 * are the encrypted payload. Every chunk is an AEAD frame of
 * `chunkSize` plaintext bytes (the last one may be short) plus a 16-byte tag.
 *
 * The construction is STREAM (Hoang-Reyhanitabar-Rogaway-Vizar):
 *
 *   nonce_i = noncePrefix || u32be(i) || u8(isFinal)
 *   aad_i   = header || u32be(i) || u8(isFinal)
 *
 * Binding the counter into the nonce stops chunk reordering and replay; the
 * final-chunk flag stops silent truncation. Binding the whole header into the
 * AAD stops an attacker downgrading the cipher suite or KDF parameters.
 */

import { assertKdfParams, SALT_LEN, type KdfParams } from './kdf.js';
import { suiteSpec } from './aead.js';

export const MAGIC = new Uint8Array([0x51, 0x53, 0x46, 0x54]); // "QSFT"
export const FORMAT_VERSION = 1;
export const HEADER_LEN = 64;
export const NONCE_PREFIX_FIELD_LEN = 20;

export const KDF_ARGON2ID = 1;

export const FLAG_COMPRESSED = 1 << 0;

/** 1 MiB for stored transfers; live transports override this (see transport/link). */
export const DEFAULT_CHUNK_SIZE = 1024 * 1024;
export const MAX_CHUNK_SIZE = 8 * 1024 * 1024;

/** Hard ceiling on plaintext size, per the product requirement. */
export const MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024;

export interface Header {
  version: number;
  suite: number;
  kdfId: number;
  compressed: boolean;
  kdf: KdfParams;
  salt: Uint8Array;
  noncePrefix: Uint8Array;
  chunkSize: number;
}

export function encodeHeader(h: Header): Uint8Array {
  if (h.salt.length !== SALT_LEN) throw new Error('bad salt length');
  if (h.noncePrefix.length !== NONCE_PREFIX_FIELD_LEN) throw new Error('bad nonce prefix length');

  const out = new Uint8Array(HEADER_LEN);
  const dv = new DataView(out.buffer);
  out.set(MAGIC, 0);
  out[4] = h.version;
  out[5] = h.suite;
  out[6] = h.kdfId;
  out[7] = h.compressed ? FLAG_COMPRESSED : 0;
  dv.setUint32(8, h.kdf.memKiB, false);
  out[12] = h.kdf.timeCost;
  out[13] = h.kdf.lanes;
  // 14..16 reserved
  out.set(h.salt, 16);
  out.set(h.noncePrefix, 32);
  dv.setUint32(52, h.chunkSize, false);
  // 56..64 reserved
  return out;
}

export function decodeHeader(bytes: Uint8Array): Header {
  if (bytes.length < HEADER_LEN) throw new Error('Truncated header');
  for (let i = 0; i < MAGIC.length; i++) {
    if (bytes[i] !== MAGIC[i]) throw new Error('Not a QSFT file (bad magic)');
  }
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const version = bytes[4];
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported format version ${version} (this build understands ${FORMAT_VERSION})`);
  }
  const suite = bytes[5];
  suiteSpec(suite); // throws on unknown suite

  const kdfId = bytes[6];
  if (kdfId !== KDF_ARGON2ID) throw new Error(`Unsupported KDF id ${kdfId}`);

  const chunkSize = dv.getUint32(52, false);
  if (chunkSize === 0 || chunkSize > MAX_CHUNK_SIZE) {
    throw new Error(`Implausible chunk size ${chunkSize}`);
  }

  // Refuse absurd Argon2 parameters: a hostile header could otherwise make the
  // receiver allocate gigabytes or spin for hours. The bound is on the *product*
  // as well as each field, because that is what the cost actually is.
  const kdf = {
    memKiB: dv.getUint32(8, false),
    timeCost: bytes[12],
    lanes: bytes[13],
  };
  assertKdfParams(kdf);

  return {
    version,
    suite,
    kdfId,
    compressed: (bytes[7] & FLAG_COMPRESSED) !== 0,
    kdf,
    salt: bytes.slice(16, 16 + SALT_LEN),
    noncePrefix: bytes.slice(32, 32 + NONCE_PREFIX_FIELD_LEN),
    chunkSize,
  };
}

/** nonce_i = noncePrefix[0..prefixLen] || u32be(counter) || u8(isFinal) */
export function chunkNonce(
  noncePrefix: Uint8Array,
  suite: number,
  counter: number,
  isFinal: boolean,
): Uint8Array {
  const spec = suiteSpec(suite);
  const nonce = new Uint8Array(spec.nonceLen);
  nonce.set(noncePrefix.subarray(0, spec.noncePrefixLen), 0);
  const dv = new DataView(nonce.buffer);
  dv.setUint32(spec.noncePrefixLen, counter, false);
  nonce[spec.noncePrefixLen + 4] = isFinal ? 1 : 0;
  return nonce;
}

/** aad_i = header || u32be(counter) || u8(isFinal) */
export function chunkAad(header: Uint8Array, counter: number, isFinal: boolean): Uint8Array {
  const aad = new Uint8Array(header.length + 5);
  aad.set(header, 0);
  new DataView(aad.buffer).setUint32(header.length, counter, false);
  aad[header.length + 4] = isFinal ? 1 : 0;
  return aad;
}


// ---------------------------------------------------------------------------
// Encrypted metadata (chunk 0)
// ---------------------------------------------------------------------------

export interface FileMeta {
  name: string;
  /** Original (pre-compression) plaintext size in bytes. */
  size: number;
  type: string;
  lastModified: number;
}

/** Strip path separators and control characters a hostile sender might inject. */
export function sanitizeFilename(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? 'download';
  // Control characters plus the characters Windows forbids in filenames.
  const cleaned = base.replace(/[\x00-\x1f\x7f<>:"|?*]/g, '_').trim();
  const safe = cleaned.replace(/^\.+/, '').slice(0, 200);
  return safe.length ? safe : 'download';
}

/**
 * The metadata chunk is a fixed-size block: [u16be jsonLen][json][zero padding].
 *
 * Fixed size does two jobs. It makes the serialized container self-framing -
 * a receiver reading a raw byte stream knows exactly how many bytes chunk 0
 * occupies without a length prefix in the clear. And it stops the ciphertext
 * length from leaking how long the filename is.
 */
export const META_BLOCK_LEN = 1024;

export function encodeMeta(meta: FileMeta): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(meta));
  if (json.length + 2 > META_BLOCK_LEN) {
    throw new Error('File metadata is too large (is the filename extremely long?)');
  }
  const block = new Uint8Array(META_BLOCK_LEN);
  new DataView(block.buffer).setUint16(0, json.length, false);
  block.set(json, 2);
  return block;
}

export function decodeMeta(block: Uint8Array): FileMeta {
  if (block.length !== META_BLOCK_LEN) {
    throw new Error(`Metadata block is ${block.length} bytes, expected ${META_BLOCK_LEN}`);
  }
  const jsonLen = new DataView(block.buffer, block.byteOffset, block.byteLength).getUint16(0, false);
  if (jsonLen + 2 > META_BLOCK_LEN) throw new Error('Corrupt metadata block');
  const raw = JSON.parse(new TextDecoder().decode(block.subarray(2, 2 + jsonLen))) as Partial<FileMeta>;
  const size = Number(raw.size);
  if (!Number.isFinite(size) || size < 0 || size > MAX_FILE_BYTES) {
    throw new Error('Metadata declares an implausible file size');
  }
  return {
    name: sanitizeFilename(String(raw.name ?? 'download')),
    size,
    type: typeof raw.type === 'string' ? raw.type.slice(0, 128) : 'application/octet-stream',
    lastModified: Number(raw.lastModified) || Date.now(),
  };
}
