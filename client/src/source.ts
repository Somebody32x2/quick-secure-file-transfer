/**
 * What a transfer sends.
 *
 * One file goes over the wire exactly as it always did. Several files are
 * bundled into a ZIP on the fly, so the protocol below this point never has to
 * know the difference - one transfer, one code, one passphrase, one container.
 *
 * The alternative was sending files sequentially, which would mean a code and a
 * handshake per file and no way to know the set arrived intact. A single
 * archive keeps the "it decrypted and verified" guarantee covering the whole
 * selection.
 */

import { bundleName, zipSize, zipStream } from './zip.js';
import { fileReadable } from './chunker.js';
import { looksCompressible } from './compress.js';

export interface TransferSource {
  name: string;
  /** Exact plaintext byte count that will be streamed. */
  size: number;
  type: string;
  lastModified: number;
  stream(): ReadableStream<Uint8Array>;
  /** True when several files were bundled into one archive. */
  bundled: boolean;
  fileCount: number;
}

export function fileSource(file: File): TransferSource {
  return {
    name: file.name,
    size: file.size,
    type: file.type || 'application/octet-stream',
    lastModified: file.lastModified || Date.now(),
    stream: () => fileReadable(file),
    bundled: false,
    fileCount: 1,
  };
}

export function bundleSource(files: File[]): TransferSource {
  return {
    name: bundleName(files),
    size: zipSize(files),
    type: 'application/zip',
    lastModified: Date.now(),
    stream: () => zipStream(files),
    bundled: true,
    fileCount: files.length,
  };
}

/** Picks the right representation for a selection. */
export function sourceFor(files: File[]): TransferSource {
  if (files.length === 0) throw new Error('No files selected');
  return files.length === 1 ? fileSource(files[0]) : bundleSource(files);
}

/**
 * Whether gzip is worth it for a selection.
 *
 * For a bundle this has to look at the members, not the archive: entries are
 * STOREd, so a ".zip" name says nothing about whether the contents compress.
 * Worth it if any single member is worth it.
 */
export function selectionLooksCompressible(files: File[]): boolean {
  return files.some((file) => looksCompressible(file.name, file.type));
}

/** Total plaintext bytes a selection will produce, including archive overhead. */
export function selectionSize(files: File[]): number {
  if (files.length === 0) return 0;
  return files.length === 1 ? files[0].size : zipSize(files);
}
