/**
 * Client-side gzip via CompressionStream, when the host offers it.
 *
 * Compression happens *before* encryption, so the server and any relay only
 * ever see compressed ciphertext. The compressed flag rides in the (integrity
 * protected) header, so a receiver whose host lacks DecompressionStream can
 * tell the user plainly rather than handing back a corrupt file.
 *
 * Note on compress-then-encrypt: this leaks a coarse signal about payload
 * entropy through the ciphertext length. That is a real (if mild) side channel
 * in protocols where an attacker can inject chosen plaintext alongside a
 * secret. Here each transfer is a single user-chosen file with no attacker
 * mixing, so the tradeoff is sound - but it is a per-transfer toggle for anyone
 * who would rather not take it.
 */

import { caps } from './crypto/env.js';

/** Formats that are already compressed; gzipping them just burns CPU. */
const INCOMPRESSIBLE = new Set([
  'zip', 'gz', 'bz2', 'xz', '7z', 'rar', 'zst', 'br', 'lz4',
  'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif', 'heic', 'heif',
  'mp3', 'aac', 'ogg', 'opus', 'flac', 'm4a',
  'mp4', 'mkv', 'webm', 'mov', 'avi', 'm4v',
  'pdf', 'docx', 'xlsx', 'pptx', 'odt', 'epub', 'apk', 'jar',
]);

export function compressionAvailable(): boolean {
  return caps.compression;
}

/** Heuristic default for the compression toggle. */
export function looksCompressible(fileName: string, mimeType: string): boolean {
  if (!caps.compression) return false;
  const ext = fileName.split('.').pop()?.toLowerCase() ?? '';
  if (INCOMPRESSIBLE.has(ext)) return false;
  if (/^(image|video|audio)\//.test(mimeType) && !/svg/.test(mimeType)) return false;
  return true;
}

export function compress(source: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  if (!caps.compression) throw new Error('CompressionStream unavailable on this host');
  return source.pipeThrough(new CompressionStream('gzip') as unknown as ReadableWritablePair<Uint8Array, Uint8Array>);
}

export function decompress(source: ReadableStream<Uint8Array>): ReadableStream<Uint8Array> {
  if (!caps.compression) {
    throw new Error(
      'This transfer was gzip-compressed, but this browser has no DecompressionStream. '
      + 'Open it in a newer browser to decompress.',
    );
  }
  return source.pipeThrough(new DecompressionStream('gzip') as unknown as ReadableWritablePair<Uint8Array, Uint8Array>);
}
