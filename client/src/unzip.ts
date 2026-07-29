/**
 * Reading a received ZIP without unpacking it into memory.
 *
 * A bundle can be 2 GB, so nothing here reads the whole archive. The index is
 * parsed from the tail (end-of-central-directory, then the central directory),
 * and each entry is produced by slicing the Blob - which the browser keeps
 * backed by disk. Extracting one file out of a large archive costs about as
 * much as that one file.
 *
 * Handles the archives QSFT itself produces (all STOREd) and ordinary deflated
 * ones. ZIP64 is not supported and is reported as unreadable rather than parsed
 * wrongly; QSFT's own bundles never need it, since a transfer caps at 2 GB.
 */

const EOCD_SIG = 0x06054b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;

/** EOCD is 22 bytes plus a comment of up to 64 KiB. */
const TAIL_SCAN_BYTES = 22 + 0xffff;
/** A selection this large is not something a person picked by hand. */
const MAX_ENTRIES = 20_000;

export interface ZipEntry {
  name: string;
  /** Uncompressed size. */
  size: number;
  compressedSize: number;
  method: number;
  /** Offset of the local file header. */
  offset: number;
}

async function readSlice(blob: Blob, start: number, end: number): Promise<DataView> {
  const buffer = await blob.slice(start, end).arrayBuffer();
  return new DataView(buffer);
}

/**
 * Parse the archive index, or return null when this is not a ZIP we can read.
 * Callers treat null as "just hand the user the whole file".
 */
export async function readZipIndex(blob: Blob): Promise<ZipEntry[] | null> {
  try {
    if (blob.size < 22) return null;

    // Find the end-of-central-directory record, scanning back from the tail.
    const tailStart = Math.max(0, blob.size - TAIL_SCAN_BYTES);
    const tail = await readSlice(blob, tailStart, blob.size);
    let eocd = -1;
    for (let i = tail.byteLength - 22; i >= 0; i--) {
      if (tail.getUint32(i, true) === EOCD_SIG) { eocd = i; break; }
    }
    if (eocd === -1) return null;

    const count = tail.getUint16(eocd + 10, true);
    const centralSize = tail.getUint32(eocd + 12, true);
    const centralOffset = tail.getUint32(eocd + 16, true);

    // ZIP64 stores 0xffff/0xffffffff sentinels here; refuse rather than guess.
    if (count === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff) return null;
    if (count === 0 || count > MAX_ENTRIES) return null;
    if (centralOffset + centralSize > blob.size) return null;

    const central = await readSlice(blob, centralOffset, centralOffset + centralSize);
    const decoder = new TextDecoder();
    const entries: ZipEntry[] = [];
    let p = 0;

    for (let i = 0; i < count; i++) {
      if (p + 46 > central.byteLength) return null;
      if (central.getUint32(p, true) !== CENTRAL_SIG) return null;

      const method = central.getUint16(p + 10, true);
      const compressedSize = central.getUint32(p + 20, true);
      const size = central.getUint32(p + 24, true);
      const nameLen = central.getUint16(p + 28, true);
      const extraLen = central.getUint16(p + 30, true);
      const commentLen = central.getUint16(p + 32, true);
      const offset = central.getUint32(p + 42, true);

      const nameBytes = new Uint8Array(central.buffer, central.byteOffset + p + 46, nameLen);
      const name = decoder.decode(nameBytes);

      // Directory markers carry no data and are not offered as files.
      if (!name.endsWith('/')) {
        entries.push({ name, size, compressedSize, method, offset });
      }
      p += 46 + nameLen + extraLen + commentLen;
    }

    return entries.length ? entries : null;
  } catch {
    return null;
  }
}

/** Produce one entry's bytes as a Blob, decompressing only if it was deflated. */
export async function extractEntry(blob: Blob, entry: ZipEntry): Promise<Blob> {
  // The local header repeats the name and extra fields, and its lengths can
  // differ from the central directory's - so the data offset comes from here.
  const header = await readSlice(blob, entry.offset, entry.offset + 30);
  if (header.getUint32(0, true) !== LOCAL_SIG) {
    throw new Error(`"${entry.name}" is not where the archive index said it would be`);
  }
  const nameLen = header.getUint16(26, true);
  const extraLen = header.getUint16(28, true);
  const start = entry.offset + 30 + nameLen + extraLen;
  const raw = blob.slice(start, start + entry.compressedSize);

  if (entry.method === METHOD_STORE) return raw;

  if (entry.method === METHOD_DEFLATE) {
    if (typeof DecompressionStream !== 'function') {
      throw new Error(`"${entry.name}" is compressed and this browser cannot decompress it`);
    }
    const stream = raw.stream().pipeThrough(
      new DecompressionStream('deflate-raw') as unknown as ReadableWritablePair<Uint8Array, Uint8Array>,
    );
    return await new Response(stream as unknown as BodyInit).blob();
  }

  throw new Error(`"${entry.name}" uses an unsupported compression method (${entry.method})`);
}

/** Cheap check before committing to a parse. */
export function looksLikeZip(name: string, type: string): boolean {
  return type === 'application/zip' || /\.zip$/i.test(name);
}
