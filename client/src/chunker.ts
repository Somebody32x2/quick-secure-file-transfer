/**
 * Turning a File into evenly sized plaintext chunks, without ever holding the
 * whole thing in memory. At 2 GB that constraint is the whole ballgame.
 */

/** Read a File as a stream, with a slice-based fallback for older mobile Safari. */
export function fileReadable(file: Blob, sliceSize = 1024 * 1024): ReadableStream<Uint8Array> {
  if (typeof file.stream === 'function') {
    try {
      return file.stream() as unknown as ReadableStream<Uint8Array>;
    } catch { /* fall through */ }
  }
  let offset = 0;
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (offset >= file.size) {
        controller.close();
        return;
      }
      const end = Math.min(offset + sliceSize, file.size);
      const buf = await file.slice(offset, end).arrayBuffer();
      offset = end;
      controller.enqueue(new Uint8Array(buf));
    },
  });
}

/**
 * Re-chunk an arbitrary byte stream into exact `size` pieces. Compression
 * upstream produces wildly uneven output, but the AEAD framing needs a fixed
 * plaintext chunk size, so this sits between them.
 *
 * Yields `{ bytes, isFinal }`; the final chunk may be short and is the only one
 * flagged final. An empty input still yields exactly one empty final chunk, so
 * zero-byte files round-trip.
 */
export async function* rechunk(
  source: ReadableStream<Uint8Array>,
  size: number,
): AsyncGenerator<{ bytes: Uint8Array; isFinal: boolean }> {
  const reader = source.getReader();
  let buffer = new Uint8Array(size);
  let filled = 0;
  // Hold one chunk back so we always know which one is genuinely last.
  let pending: Uint8Array | null = null;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      let input = value;
      while (input.length > 0) {
        const take = Math.min(size - filled, input.length);
        buffer.set(input.subarray(0, take), filled);
        filled += take;
        input = input.subarray(take);
        if (filled === size) {
          if (pending) yield { bytes: pending, isFinal: false };
          pending = buffer;
          buffer = new Uint8Array(size);
          filled = 0;
        }
      }
    }
  } finally {
    reader.releaseLock();
  }

  if (filled > 0) {
    if (pending) yield { bytes: pending, isFinal: false };
    yield { bytes: buffer.subarray(0, filled), isFinal: true };
  } else if (pending) {
    yield { bytes: pending, isFinal: true };
  } else {
    yield { bytes: new Uint8Array(0), isFinal: true };
  }
}

/**
 * Count bytes passing through a stream without buffering them.
 *
 * Progress is measured on the *plaintext* side, upstream of compression, so the
 * bar tracks the file the user actually chose rather than its compressed size.
 */
export function countBytes(
  source: ReadableStream<Uint8Array>,
  onCount: (total: number) => void,
): ReadableStream<Uint8Array> {
  let total = 0;
  const reader = source.getReader();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      const { done, value } = await reader.read();
      if (done) { controller.close(); return; }
      total += value.length;
      onCount(total);
      controller.enqueue(value);
    },
    async cancel(reason) {
      await reader.cancel(reason);
    },
  });
}

/**
 * A stream you push into, which pushes back.
 *
 * The receive path decrypts chunks and feeds them toward a sink, possibly via
 * gzip. Without backpressure a fast network plus a slow destination (a phone
 * writing to slow storage) grows an unbounded queue - exactly the failure that
 * bites at 2 GB and never shows up in a small test. `push` resolves only once
 * the consumer is ready for more, so the whole receive loop, and with it the
 * flow-control credits sent back to the sender, is paced by the sink.
 */
export function backpressuredSource(): {
  stream: ReadableStream<Uint8Array>;
  push(bytes: Uint8Array): Promise<void>;
  close(): void;
  fail(error: Error): void;
} {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  let wake: (() => void) | null = null;
  let stopped: Error | null = null;

  const release = () => { const w = wake; wake = null; w?.(); };

  const stream = new ReadableStream<Uint8Array>({
    start(c) { controller = c; },
    pull() { release(); },
    cancel(reason) {
      stopped = reason instanceof Error ? reason : new Error(String(reason ?? 'cancelled'));
      release();
    },
  });

  return {
    stream,
    async push(bytes: Uint8Array): Promise<void> {
      if (stopped) throw stopped;
      controller.enqueue(bytes);
      if ((controller.desiredSize ?? 1) <= 0) {
        await new Promise<void>((resolve) => { wake = resolve; });
        if (stopped) throw stopped;
      }
    },
    close(): void { if (!stopped) controller.close(); },
    fail(error: Error): void {
      stopped = error;
      try { controller.error(error); } catch { /* already errored */ }
      release();
    },
  };
}

/** Adapt an async iterator of byte arrays back into a ReadableStream. */
export function toReadable(iter: AsyncIterable<Uint8Array>): ReadableStream<Uint8Array> {
  const it = iter[Symbol.asyncIterator]();
  return new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await it.next();
        if (done) controller.close();
        else controller.enqueue(value);
      } catch (err) {
        controller.error(err);
      }
    },
    async cancel(reason) {
      await it.return?.(reason);
    },
  });
}

/**
 * Read exactly `n` bytes from a reader-backed cursor, or fewer at true EOF.
 * Used to parse the fixed-size framing off an incoming ciphertext stream.
 */
export class ByteCursor {
  private reader: ReadableStreamDefaultReader<Uint8Array>;
  private queue: Uint8Array[] = [];
  private queued = 0;
  private eof = false;

  constructor(stream: ReadableStream<Uint8Array>) {
    this.reader = stream.getReader();
  }

  private async fill(target: number): Promise<void> {
    while (this.queued < target && !this.eof) {
      const { done, value } = await this.reader.read();
      if (done) { this.eof = true; break; }
      if (value.length) { this.queue.push(value); this.queued += value.length; }
    }
  }

  /** Returns up to `n` bytes; shorter only at end of stream. */
  async read(n: number): Promise<Uint8Array> {
    await this.fill(n);
    const take = Math.min(n, this.queued);
    const out = new Uint8Array(take);
    let off = 0;
    while (off < take) {
      const head = this.queue[0]!;
      const need = take - off;
      if (head.length <= need) {
        out.set(head, off);
        off += head.length;
        this.queue.shift();
      } else {
        out.set(head.subarray(0, need), off);
        this.queue[0] = head.subarray(need);
        off += need;
      }
    }
    this.queued -= take;
    return out;
  }

  /** True when the stream is drained and nothing is buffered. */
  async atEnd(): Promise<boolean> {
    await this.fill(1);
    return this.queued === 0 && this.eof;
  }

  async cancel(): Promise<void> {
    try { await this.reader.cancel(); } catch { /* already closed */ }
    this.reader.releaseLock();
  }
}
