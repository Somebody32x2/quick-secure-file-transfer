/**
 * Receiving device, live mode.
 *
 * Mirrors liveSend. The one asymmetry worth knowing about: the receiver cannot
 * open a save dialog until it knows the filename, and browsers only open that
 * dialog during a user gesture. So the flow pauses after the metadata arrives,
 * hands the metadata to the UI, and waits for the user to press a button before
 * telling the sender to start.
 */

import { ChunkOpener } from '../crypto/stream.js';
import { SecureChannel } from '../crypto/channel.js';
import { shortAuthString } from '../crypto/sas.js';
import { ARGON2_DEFAULTS, deriveMaster, sessionSalt, type KdfParams } from '../crypto/kdf.js';
import { decodeHeader, HEADER_LEN, type FileMeta } from '../crypto/format.js';
import { decompress } from '../compress.js';
import { backpressuredSource } from '../chunker.js';
import { Signal } from '../transport/signal.js';
import { establishLink } from '../transport/link.js';
import { fetchServerConfig } from '../transport/api.js';
import { timingSafeEqual } from '../util/bytes.js';
import { throwIfAborted, withTimeout } from '../util/deferred.js';
import type { FileSink } from '../sink.js';
import { ProgressThrottle, RateMeter, type EventSink } from './events.js';
import { runResponderHandshake } from './handshake.js';
import { MessagePump } from './pump.js';
import {
  CREDIT_REFILL_AT, MSG_ABORT, MSG_CREDIT, MSG_DATA, MSG_DONE, MSG_HEADER,
  MSG_META, MSG_READY, encodeCredit, encodeMessage, wrapFrame,
} from './protocol.js';

export interface LiveReceiveOptions {
  code: string;
  passphrase: string;
  onEvent: EventSink;
  /** Called once the filename is known; must be resolved from a user gesture. */
  requestDestination: (meta: FileMeta) => Promise<FileSink>;
  abort?: AbortSignal;
}

export async function liveReceive(options: LiveReceiveOptions): Promise<void> {
  const { code, passphrase, onEvent, requestDestination, abort } = options;

  const serverConfig = await fetchServerConfig();
  const signal = await Signal.connect();
  let sink: FileSink | null = null;
  let link: { close(): void } | null = null;
  let source: ReturnType<typeof backpressuredSource> | null = null;

  try {
    onEvent({ t: 'status', message: 'Joining the session...' });
    await signal.join(code);
    onEvent({ t: 'peer', joined: true });

    // Start Argon2id immediately against the salt we can predict from the code,
    // so it overlaps the sender's HELLO rather than following it.
    const expectedSalt = sessionSalt(code);
    onEvent({ t: 'status', message: 'Deriving your key from the passphrase...' });
    const precomputed = deriveMaster(passphrase, expectedSalt, ARGON2_DEFAULTS);

    const deriveMasterFor = async (salt: Uint8Array, kdf: KdfParams): Promise<Uint8Array> => {
      const sameParams = kdf.memKiB === ARGON2_DEFAULTS.memKiB
        && kdf.timeCost === ARGON2_DEFAULTS.timeCost
        && kdf.lanes === ARGON2_DEFAULTS.lanes;
      if (sameParams && timingSafeEqual(salt, expectedSalt)) return precomputed;
      // Sender chose different parameters; honour them.
      return deriveMaster(passphrase, salt, kdf);
    };

    onEvent({ t: 'status', message: 'Running the post-quantum key exchange...' });
    const [session, established] = await Promise.all([
      runResponderHandshake(signal, deriveMasterFor),
      establishLink(signal, 'answerer', serverConfig.iceServers, (m) => onEvent({ t: 'status', message: m })),
    ]);
    link = established;

    onEvent({ t: 'link', kind: established.kind, detail: established.detail });
    onEvent({ t: 'sas', sas: shortAuthString(session) });

    const channel = await SecureChannel.create(session, 'responder');
    const pump = new MessagePump(established, channel);

    // Only now is this device actually listening on the link. Relay frames that
    // arrive before this point are not buffered anywhere, so the sender must
    // not start until it has seen this.
    signal.sendSignal({ kind: 'receiver-attached' });

    const send = async (type: number, payload?: Uint8Array): Promise<void> => {
      const sealed = await channel.seal(encodeMessage(type as 1, payload), false);
      await established.send(wrapFrame(sealed, false));
    };

    // -- container header and metadata --------------------------------------
    onEvent({ t: 'status', message: 'Waiting for the sender...' });
    const headerMessage = await withTimeout(
      pump.expect(MSG_HEADER),
      2 * 60_000,
      'The sender never sent anything. Ask them to start the transfer again.',
    );
    if (headerMessage.payload.length < HEADER_LEN) throw new Error('Malformed transfer header');
    const fields = decodeHeader(headerMessage.payload);
    const headerBytes = headerMessage.payload.subarray(0, HEADER_LEN);

    const master = await deriveMasterFor(fields.salt, fields.kdf);
    const opener = await ChunkOpener.create(fields, headerBytes, master);

    const metaMessage = await pump.expect(MSG_META);
    const meta = await opener.openMeta(metaMessage.payload);
    onEvent({ t: 'meta', meta });

    // Fail early and clearly rather than after streaming a gigabyte.
    if (fields.compressed && typeof DecompressionStream !== 'function') {
      throw new Error(
        'This transfer is gzip-compressed but this browser cannot decompress it. '
        + 'Open the link in a newer browser, or ask the sender to disable compression.',
      );
    }

    // -- destination ---------------------------------------------------------
    onEvent({ t: 'awaiting-destination', meta });
    sink = await requestDestination(meta);
    throwIfAborted(abort);

    // -- payload -------------------------------------------------------------
    const meter = new RateMeter(meta.size);
    const progress = new ProgressThrottle(onEvent, meter, meta.size);
    let written = 0;

    // Decrypted chunks feed a stream so gzip can sit between cipher and sink.
    // The source pushes back, so a slow destination throttles the whole loop
    // rather than queueing the file in memory.
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
    // Attach a handler now so a failure here is never an unhandled rejection;
    // the awaited `drain` below is what actually surfaces it.
    drain.catch(() => {});

    await send(MSG_READY, encodeCredit(0));
    onEvent({ t: 'status', message: `Receiving over ${established.kind === 'p2p' ? 'the direct connection' : 'the relay'}...` });

    let sinceRefill = 0;
    let sawFinal = false;

    while (!sawFinal) {
      throwIfAborted(abort);
      const message = await pump.next();

      if (message.type === MSG_DATA) {
        // Awaiting the push is what paces the sender: credits are only issued
        // once the destination has actually taken the bytes.
        await source.push(await opener.open(message.payload, message.isFinal));
        if (message.isFinal) { sawFinal = true; break; }
        if (++sinceRefill >= CREDIT_REFILL_AT) {
          await send(MSG_CREDIT, encodeCredit(sinceRefill));
          sinceRefill = 0;
        }
      } else if (message.type === MSG_ABORT) {
        throw new Error(new TextDecoder().decode(message.payload) || 'The sender cancelled');
      }
    }

    source.close();
    await drain;

    // The inner container's own final-chunk flag must also have been seen.
    if (!opener.complete) throw new Error('The transfer ended early and could not be verified');
    opener.destroy();

    progress.report(meta.size, true);
    const { url, blob } = await sink.close(meta.name, meta.type);
    const savedToDisk = sink.kind === 'disk';
    sink = null;

    await send(MSG_DONE);
    channel.destroy();

    onEvent({ t: 'status', message: 'Received and verified.' });
    onEvent({ t: 'done', url, blob, name: meta.name, savedToDisk });
  } catch (err) {
    // Unblock the drain task so it settles instead of hanging on a dead stream.
    source?.fail(err instanceof Error ? err : new Error(String(err)));
    await sink?.abort();
    throw err;
  } finally {
    link?.close();
    signal.close();
  }
}
