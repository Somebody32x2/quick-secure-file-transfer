/**
 * Where decrypted bytes land.
 *
 * At 2 GB the naive approach - accumulate everything in a Uint8Array - is fatal
 * on a phone. Two strategies, in order of preference:
 *
 *   1. File System Access API: stream straight to a file the user picked. Flat
 *      memory regardless of size. Requires a user gesture to open the picker,
 *      which is why the receive flow asks for the destination on a button press
 *      rather than after the metadata arrives.
 *   2. Blob accumulation: collect Blob parts and let the browser spill them to
 *      disk, then hand back an object URL. Works everywhere, including on
 *      non-secure origins, and is the only option on iOS Safari.
 */

import { caps } from './crypto/env.js';

export interface FileSink {
  readonly kind: 'disk' | 'blob';
  write(chunk: Uint8Array): Promise<void>;
  /** @returns an object URL when the sink buffered in memory, nothing when it streamed to disk. */
  close(name: string, type: string): Promise<{ url?: string }>;
  abort(): Promise<void>;
}

/** Coalesce small writes so we create far fewer Blob parts. */
const BLOB_PART_TARGET = 8 * 1024 * 1024;

class BlobSink implements FileSink {
  readonly kind = 'blob';
  private parts: Blob[] = [];
  private pending: Uint8Array[] = [];
  private pendingBytes = 0;

  async write(chunk: Uint8Array): Promise<void> {
    // Copy: the caller reuses its chunk buffers.
    this.pending.push(chunk.slice());
    this.pendingBytes += chunk.length;
    if (this.pendingBytes >= BLOB_PART_TARGET) this.flush();
  }

  private flush(): void {
    if (!this.pendingBytes) return;
    this.parts.push(new Blob(this.pending as BlobPart[]));
    this.pending = [];
    this.pendingBytes = 0;
  }

  async close(_name: string, type: string): Promise<{ url?: string }> {
    this.flush();
    const blob = new Blob(this.parts as BlobPart[], { type: type || 'application/octet-stream' });
    this.parts = [];
    return { url: URL.createObjectURL(blob) };
  }

  async abort(): Promise<void> {
    this.parts = [];
    this.pending = [];
    this.pendingBytes = 0;
  }
}

class DiskSink implements FileSink {
  readonly kind = 'disk';
  constructor(private writable: FileSystemWritableFileStream) {}

  async write(chunk: Uint8Array): Promise<void> {
    await this.writable.write(chunk as unknown as BufferSource);
  }

  async close(): Promise<{ url?: string }> {
    await this.writable.close();
    return {};
  }

  async abort(): Promise<void> {
    try { await this.writable.abort(); } catch { /* already closed */ }
  }
}

/**
 * Ask the user for a destination file. Must be called synchronously from a user
 * gesture. Returns null when unavailable or cancelled, and the caller falls
 * back to a Blob sink.
 */
export async function requestDiskSink(suggestedName: string): Promise<FileSink | null> {
  if (!caps.fileSystemAccess) return null;
  try {
    const handle = await (globalThis as any).showSaveFilePicker({
      suggestedName,
      types: [{ description: 'Received file', accept: { 'application/octet-stream': ['.bin'] } }],
    });
    const writable = await handle.createWritable();
    return new DiskSink(writable);
  } catch {
    // User cancelled, or the host refused the picker.
    return null;
  }
}

export function createBlobSink(): FileSink {
  return new BlobSink();
}

/**
 * Trigger a browser download for a completed Blob sink. Revokes the object URL
 * afterwards so a 2 GB blob is not pinned in memory for the life of the tab.
 */
export function triggerDownload(url: string, filename: string): void {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}
