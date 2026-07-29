/**
 * Store-and-forward: the sender uploads a sealed blob and walks away; the
 * receiver collects it later with the 6-digit code and the passphrase.
 *
 * The container is byte-identical to the one live mode sends, so this is the
 * same crypto with a different pipe. What the server holds is opaque
 * ciphertext with a deletion deadline attached.
 *
 * Serialized layout:
 *   [64-byte header][sealed 1 KiB metadata block][sealed chunk]...[sealed chunk]
 *
 * Every field is fixed width, so the receiver can frame the stream without any
 * cleartext length prefixes.
 */

import { ChunkOpener, ChunkSealer, sealedTotalLength } from '../crypto/stream.js';
import { deriveMaster } from '../crypto/kdf.js';
import { preferredSuite, TAG_LEN } from '../crypto/aead.js';
import {
  decodeHeader, DEFAULT_CHUNK_SIZE, HEADER_LEN, MAX_FILE_BYTES, META_BLOCK_LEN,
  type FileMeta,
} from '../crypto/format.js';
import { compress as gzip, compressionAvailable, decompress } from '../compress.js';
import { backpressuredSource, ByteCursor, countBytes, rechunk } from '../chunker.js';
import type { TransferSource } from '../source.js';
import {
  commitUpload, fetchServerConfig, initUpload, openStoredDownload, revokeUpload,
  uploadPart,
} from '../transport/api.js';
import { throwIfAborted } from '../util/deferred.js';
import type { FileSink } from '../sink.js';
import { ProgressThrottle, RateMeter, type EventSink } from './events.js';

export interface StoredSendOptions {
  source: TransferSource;
  passphrase: string;
  compress: boolean;
  ttlSeconds: number;
  maxReads: number;
  onEvent: EventSink;
  abort?: AbortSignal;
}

export interface StoredSendResult {
  code: string;
  expiresAt: number;
  maxReads: number;
  /** Lets the sender delete the blob before it expires on its own. */
  revoke: () => Promise<void>;
}

export async function storedSend(options: StoredSendOptions): Promise<StoredSendResult> {
  const { source, passphrase, onEvent, abort } = options;
  if (source.size > MAX_FILE_BYTES) {
    throw new Error(
      source.bundled
        ? 'Those files add up to more than the 2 GB limit'
        : 'That file is larger than the 2 GB limit',
    );
  }

  const serverConfig = await fetchServerConfig();
  const useCompression = options.compress && compressionAvailable();
  const partSize = Math.min(serverConfig.maxPartBytes, 4 * 1024 * 1024);

  onEvent({ t: 'status', message: 'Deriving your key from the passphrase...' });
  const sealer = await ChunkSealer.create({
    passphrase,
    suite: preferredSuite(),
    chunkSize: DEFAULT_CHUNK_SIZE,
    compressed: useCompression,
  });

  // Without compression the exact size is known, which lets the server reject
  // an oversized upload before a single byte moves.
  const declaredSize = useCompression
    ? source.size
    : sealedTotalLength(source.size, DEFAULT_CHUNK_SIZE);

  onEvent({ t: 'status', message: 'Reserving a slot on the server...' });
  const ticket = await initUpload({
    ttlSeconds: options.ttlSeconds,
    maxReads: options.maxReads,
    declaredSize,
  });
  onEvent({ t: 'code', code: ticket.code });

  const meter = new RateMeter(source.size);
  const progress = new ProgressThrottle(onEvent, meter, source.size);

  try {
    onEvent({ t: 'status', message: 'Encrypting and uploading...' });
    let plaintextRead = 0;

    let bytes$ = countBytes(source.stream(), (n) => { plaintextRead = n; });
    if (useCompression) bytes$ = gzip(bytes$);

    // Accumulate sealed output into upload-sized parts.
    let buffer = new Uint8Array(partSize);
    let filled = 0;
    let partIndex = 0;

    const flush = async (force: boolean): Promise<void> => {
      if (filled === 0 || (!force && filled < partSize)) return;
      await uploadPart(ticket, partIndex++, buffer.subarray(0, filled), abort);
      filled = 0;
      buffer = new Uint8Array(partSize);
    };

    const push = async (bytes: Uint8Array): Promise<void> => {
      let offset = 0;
      while (offset < bytes.length) {
        const take = Math.min(partSize - filled, bytes.length - offset);
        buffer.set(bytes.subarray(offset, offset + take), filled);
        filled += take;
        offset += take;
        if (filled === partSize) await flush(true);
      }
    };

    await push(sealer.headerBytes);
    await push(await sealer.sealMeta({
      name: source.name, size: source.size, type: source.type, lastModified: source.lastModified,
    }));

    for await (const { bytes, isFinal } of rechunk(bytes$, DEFAULT_CHUNK_SIZE)) {
      throwIfAborted(abort);
      await push(await sealer.seal(bytes, isFinal));
      progress.report(plaintextRead);
    }
    await flush(true);
    sealer.destroy();
    progress.report(source.size, true);

    onEvent({ t: 'status', message: 'Finalising...' });
    const committed = await commitUpload(ticket);

    return {
      code: committed.code,
      expiresAt: committed.expiresAt,
      maxReads: committed.maxReads,
      revoke: () => revokeUpload(ticket),
    };
  } catch (err) {
    // Never leave a half-written blob occupying the server's quota.
    await revokeUpload(ticket);
    throw err;
  }
}

export interface StoredReceiveOptions {
  code: string;
  passphrase: string;
  onEvent: EventSink;
  requestDestination: (meta: FileMeta) => Promise<FileSink>;
  abort?: AbortSignal;
}

export async function storedReceive(options: StoredReceiveOptions): Promise<void> {
  const { code, passphrase, onEvent, requestDestination, abort } = options;

  onEvent({ t: 'status', message: 'Looking up the code...' });
  const { stream } = await openStoredDownload(code, abort);
  const cursor = new ByteCursor(stream);
  let sink: FileSink | null = null;
  let source: ReturnType<typeof backpressuredSource> | null = null;

  try {
    const headerBytes = await cursor.read(HEADER_LEN);
    if (headerBytes.length < HEADER_LEN) throw new Error('The stored transfer is truncated');
    const fields = decodeHeader(headerBytes);

    onEvent({ t: 'status', message: 'Deriving your key from the passphrase...' });
    const master = await deriveMaster(passphrase, fields.salt, fields.kdf);
    const opener = await ChunkOpener.create(fields, headerBytes, master);

    const sealedMeta = await cursor.read(META_BLOCK_LEN + TAG_LEN);
    if (sealedMeta.length < META_BLOCK_LEN + TAG_LEN) throw new Error('The stored transfer is truncated');
    const meta = await opener.openMeta(sealedMeta);
    onEvent({ t: 'meta', meta });

    if (fields.compressed && typeof DecompressionStream !== 'function') {
      throw new Error(
        'This transfer is gzip-compressed but this browser cannot decompress it. '
        + 'Open it in a newer browser.',
      );
    }

    onEvent({ t: 'awaiting-destination', meta });
    sink = await requestDestination(meta);
    throwIfAborted(abort);

    const meter = new RateMeter(meta.size);
    const progress = new ProgressThrottle(onEvent, meter, meta.size);
    let written = 0;

    source = backpressuredSource();
    const plaintext = fields.compressed ? decompress(source.stream) : source.stream;
    const drain = (async () => {
      const reader = plaintext.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        await sink!.write(value);
        written += value.length;
        progress.report(written);
      }
    })();
    drain.catch(() => {});

    onEvent({ t: 'status', message: 'Downloading and decrypting...' });
    const sealedChunkLen = fields.chunkSize + TAG_LEN;

    for (;;) {
      throwIfAborted(abort);
      const sealed = await cursor.read(sealedChunkLen);
      if (sealed.length === 0) throw new Error('The transfer ended before its final chunk');
      // Whatever follows decides whether this was the last chunk - and that
      // answer is authenticated, so a truncated download cannot pass as whole.
      const isFinal = await cursor.atEnd();
      // Awaiting the push paces decryption against how fast the sink can write.
      await source.push(await opener.open(sealed, isFinal));
      if (isFinal) break;
    }

    source.close();
    await drain;

    if (!opener.complete) throw new Error('The transfer ended early and could not be verified');
    opener.destroy();

    progress.report(meta.size, true);
    const { url, blob } = await sink.close(meta.name, meta.type);
    const savedToDisk = sink.kind === 'disk';
    sink = null;

    onEvent({ t: 'status', message: 'Received and verified.' });
    onEvent({ t: 'done', url, blob, name: meta.name, savedToDisk });
  } catch (err) {
    source?.fail(err instanceof Error ? err : new Error(String(err)));
    await sink?.abort();
    await cursor.cancel();
    throw err;
  }
}
