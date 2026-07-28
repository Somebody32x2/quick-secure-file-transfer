/**
 * Streaming ZIP writer, used to bundle a multi-file selection into one transfer.
 *
 * Entries are STOREd, never deflated. The whole bundle is already gzipped (when
 * the user leaves compression on) and then encrypted, so compressing twice would
 * burn CPU on a phone for nothing.
 *
 * It streams: entries are emitted as their bytes are read, so a 2 GB selection
 * never lands in memory. That means the CRC and sizes are not known when a local
 * header is written, which is exactly what ZIP data descriptors are for - the
 * real values follow each entry, and the central directory at the end carries
 * them too, which is what extractors actually read.
 *
 * No ZIP64. Entries and the archive stay under 4 GiB because the app caps a
 * transfer at 2 GB, so the 32-bit fields cannot overflow.
 */

import { crc32Update } from './util/crc32.js';
import { fileReadable } from './chunker.js';

const LOCAL_HEADER_SIG = 0x04034b50;
const DESCRIPTOR_SIG = 0x08074b50;
const CENTRAL_HEADER_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;

const LOCAL_HEADER_LEN = 30;
const DESCRIPTOR_LEN = 16;
const CENTRAL_HEADER_LEN = 46;
const EOCD_LEN = 22;

/** bit 3: sizes/CRC follow the data. bit 11: the name is UTF-8. */
const FLAG_DATA_DESCRIPTOR = 0x0008;
const FLAG_UTF8 = 0x0800;
const METHOD_STORE = 0;
const VERSION_NEEDED = 20;

interface Entry {
  name: string;
  nameBytes: Uint8Array;
  file: Blob;
  size: number;
  lastModified: number;
}

class Writer {
  private parts: Uint8Array[] = [];

  u16(value: number): void {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, value, true);
    this.parts.push(b);
  }

  u32(value: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, value >>> 0, true);
    this.parts.push(b);
  }

  raw(bytes: Uint8Array): void {
    this.parts.push(bytes);
  }

  take(): Uint8Array {
    const total = this.parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of this.parts) { out.set(p, off); off += p.length; }
    this.parts = [];
    return out;
  }
}

/** MS-DOS timestamp: 2-second resolution, epoch 1980. */
function dosDateTime(ms: number): { time: number; date: number } {
  const d = new Date(ms);
  const year = d.getFullYear();
  if (year < 1980) return { time: 0, date: 33 }; // 1980-01-01
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

/**
 * Strip anything path-like and keep names unique. Two files called photo.jpg
 * from different folders would otherwise collide silently inside the archive.
 */
function uniqueNames(files: File[]): string[] {
  const seen = new Map<string, number>();
  return files.map((file, index) => {
    const base = (file.name.split(/[/\\]/).pop() ?? '').trim() || `file-${index + 1}`;
    const key = base.toLowerCase();
    const count = seen.get(key) ?? 0;
    seen.set(key, count + 1);
    if (count === 0) return base;

    const dot = base.lastIndexOf('.');
    return dot > 0
      ? `${base.slice(0, dot)} (${count})${base.slice(dot)}`
      : `${base} (${count})`;
  });
}

function toEntries(files: File[]): Entry[] {
  const names = uniqueNames(files);
  const encoder = new TextEncoder();
  return files.map((file, i) => ({
    name: names[i],
    nameBytes: encoder.encode(names[i]),
    file,
    size: file.size,
    lastModified: file.lastModified || Date.now(),
  }));
}

/**
 * Exact archive length. Every field is fixed width and entries are stored
 * uncompressed, so this is known before a byte is read - which lets a
 * store-and-forward upload declare its size up front.
 */
export function zipSize(files: File[]): number {
  const entries = toEntries(files);
  let total = 0;
  for (const entry of entries) {
    total += LOCAL_HEADER_LEN + entry.nameBytes.length + entry.size + DESCRIPTOR_LEN;
    total += CENTRAL_HEADER_LEN + entry.nameBytes.length;
  }
  return total + EOCD_LEN;
}

/** A sensible archive name for a bundle of `n` files. */
export function bundleName(files: File[]): string {
  const stamp = new Date().toISOString().slice(0, 10);
  return `qsft-${files.length}-files-${stamp}.zip`;
}

/** Streams the archive. Entry bytes are read lazily, one file at a time. */
export function zipStream(files: File[]): ReadableStream<Uint8Array> {
  const entries = toEntries(files);
  let index = 0;
  let offset = 0;
  const central: { entry: Entry; crc: number; offset: number }[] = [];

  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;
  let current: { entry: Entry; crc: number; written: number; offset: number } | null = null;

  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      // Mid-entry: keep draining the current file.
      if (current && reader) {
        const { done, value } = await reader.read();
        if (!done) {
          current.crc = crc32Update(value, current.crc);
          current.written += value.length;
          offset += value.length;
          controller.enqueue(value);
          return;
        }

        reader.releaseLock();
        reader = null;

        if (current.written !== current.entry.size) {
          controller.error(new Error(
            `"${current.entry.name}" changed while it was being read `
            + `(expected ${current.entry.size} bytes, got ${current.written}). Re-select it and try again.`,
          ));
          return;
        }

        const w = new Writer();
        w.u32(DESCRIPTOR_SIG);
        w.u32(current.crc);
        w.u32(current.written);
        w.u32(current.written);
        const descriptor = w.take();
        offset += descriptor.length;

        central.push({ entry: current.entry, crc: current.crc, offset: current.offset });
        current = null;
        controller.enqueue(descriptor);
        return;
      }

      // Start the next entry.
      if (index < entries.length) {
        const entry = entries[index++];
        const { time, date } = dosDateTime(entry.lastModified);

        const w = new Writer();
        w.u32(LOCAL_HEADER_SIG);
        w.u16(VERSION_NEEDED);
        w.u16(FLAG_DATA_DESCRIPTOR | FLAG_UTF8);
        w.u16(METHOD_STORE);
        w.u16(time);
        w.u16(date);
        w.u32(0); // crc, in the descriptor
        w.u32(0); // compressed size, in the descriptor
        w.u32(0); // uncompressed size, in the descriptor
        w.u16(entry.nameBytes.length);
        w.u16(0); // extra field length
        w.raw(entry.nameBytes);
        const header = w.take();

        current = { entry, crc: 0, written: 0, offset };
        offset += header.length;
        reader = fileReadable(entry.file).getReader();
        controller.enqueue(header);
        return;
      }

      // Central directory, then end-of-central-directory.
      const w = new Writer();
      const centralOffset = offset;
      for (const record of central) {
        const { time, date } = dosDateTime(record.entry.lastModified);
        w.u32(CENTRAL_HEADER_SIG);
        w.u16(VERSION_NEEDED); // version made by
        w.u16(VERSION_NEEDED);
        w.u16(FLAG_DATA_DESCRIPTOR | FLAG_UTF8);
        w.u16(METHOD_STORE);
        w.u16(time);
        w.u16(date);
        w.u32(record.crc);
        w.u32(record.entry.size);
        w.u32(record.entry.size);
        w.u16(record.entry.nameBytes.length);
        w.u16(0); // extra
        w.u16(0); // comment
        w.u16(0); // disk number
        w.u16(0); // internal attributes
        w.u32(0); // external attributes
        w.u32(record.offset);
        w.raw(record.entry.nameBytes);
      }
      const centralBytes = w.take();

      const e = new Writer();
      e.u32(EOCD_SIG);
      e.u16(0); // this disk
      e.u16(0); // disk with the central directory
      e.u16(central.length);
      e.u16(central.length);
      e.u32(centralBytes.length);
      e.u32(centralOffset);
      e.u16(0); // comment length

      controller.enqueue(centralBytes);
      controller.enqueue(e.take());
      controller.close();
    },

    async cancel(reason) {
      await reader?.cancel(reason).catch(() => {});
    },
  });
}
