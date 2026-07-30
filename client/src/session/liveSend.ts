/**
 * Sending device, live mode.
 *
 * Sequence: host a room, derive the passphrase key, wait for the peer, then run
 * the PQ handshake and the WebRTC negotiation *concurrently* - they are
 * independent, and overlapping them hides the Argon2id cost behind ICE
 * gathering. Once both finish, the file streams through two nested layers of
 * encryption with credit-based flow control.
 */

import { ChunkSealer } from '../crypto/stream.js';
import { SecureChannel } from '../crypto/channel.js';
import { shortAuthString } from '../crypto/sas.js';
import { ARGON2_DEFAULTS, deriveMaster, SALT_LEN } from '../crypto/kdf.js';
import { randomBytes } from '../crypto/env.js';
import { preferredSuite } from '../crypto/aead.js';
import { MAX_FILE_BYTES } from '../crypto/format.js';
import { compress as gzip, compressionAvailable } from '../compress.js';
import { countBytes, rechunk } from '../chunker.js';
import type { TransferSource } from '../source.js';
import { Signal } from '../transport/signal.js';
import { establishLink } from '../transport/link.js';
import { fetchServerConfig } from '../transport/api.js';
import { deferred, throwIfAborted, withTimeout, AbortedError } from '../util/deferred.js';
import { ProgressThrottle, RateMeter, type EventSink } from './events.js';
import { runInitiatorHandshake } from './handshake.js';
import { CreditGate, MessagePump } from './pump.js';
import {
  CREDIT_WINDOW, LIVE_CHUNK_SIZE, MSG_ABORT, MSG_CREDIT, MSG_DATA, MSG_DONE,
  MSG_HEADER, MSG_META, MSG_READY, decodeCredit, encodeMessage, wrapFrame,
} from './protocol.js';

export interface LiveSendOptions {
  source: TransferSource;
  passphrase: string;
  compress: boolean;
  onEvent: EventSink;
  abort?: AbortSignal;
}

export async function liveSend(options: LiveSendOptions): Promise<void> {
  const { source, passphrase, onEvent, abort } = options;
  if (source.size > MAX_FILE_BYTES) {
    throw new Error(
      source.bundled
        ? 'Those files add up to more than the 2 GB limit'
        : 'That file is larger than the 2 GB limit',
    );
  }

  const serverConfig = await fetchServerConfig();
  const signal = await Signal.connect();
  let cleanup: (() => void) | null = null;

  try {
    const code = await signal.host();
    onEvent({ t: 'code', code });

    /**
     * A fresh random salt per session, carried to the receiver in HELLO.
     *
     * It used to be derived from the room code, which made it public and one of
     * only 10^6 possible values - the server knows the code the instant it
     * allocates it, so it could begin grinding candidate passphrases against
     * that exact salt before the file had even moved. Precomputing against a
     * value nobody can predict is not possible, which is the entire job of a
     * salt.
     *
     * The cost is that the receiver can no longer start Argon2id before HELLO
     * arrives, so the derivation no longer hides behind ICE gathering. That is
     * the right trade: it is one wait, once.
     */
    const salt = randomBytes(SALT_LEN);
    onEvent({ t: 'status', message: 'Deriving your key from the passphrase...' });
    const master = await deriveMaster(passphrase, salt, ARGON2_DEFAULTS);

    onEvent({ t: 'status', message: 'Waiting for the other device to join...' });
    await waitForPeer(signal, abort);
    onEvent({ t: 'peer', joined: true });

    const suite = preferredSuite();
    onEvent({ t: 'status', message: 'Running the post-quantum key exchange...' });

    const [session, link] = await Promise.all([
      runInitiatorHandshake(signal, master, salt, ARGON2_DEFAULTS, suite),
      establishLink(signal, 'offerer', serverConfig.iceServers, (m) => onEvent({ t: 'status', message: m })),
    ]);
    cleanup = () => link.close();

    onEvent({ t: 'link', kind: link.kind, detail: link.detail });
    onEvent({ t: 'sas', sas: shortAuthString(session) });

    const channel = await SecureChannel.create(session, 'initiator');
    const pump = new MessagePump(link, channel);

    const send = async (type: number, payload?: Uint8Array, isFinal = false): Promise<void> => {
      const sealed = await channel.seal(encodeMessage(type as 1, payload), isFinal);
      await link.send(wrapFrame(sealed, isFinal));
    };

    const useCompression = options.compress && compressionAvailable();
    const sealer = await ChunkSealer.create({
      master, salt, suite, chunkSize: LIVE_CHUNK_SIZE, compressed: useCompression,
    });

    // Wait until the receiver is attached to the link before putting anything
    // on it. Frames sent earlier would be dropped with no error anywhere.
    onEvent({ t: 'status', message: 'Waiting for the other device to be ready...' });
    await signal.waitFor('receiver-attached', 60_000);

    await send(MSG_HEADER, sealer.headerBytes);
    await send(MSG_META, await sealer.sealMeta({
      name: source.name, size: source.size, type: source.type, lastModified: source.lastModified,
    }));

    // Inbound control loop: credits, the go-ahead, and the final confirmation.
    const gate = new CreditGate();
    const ready = deferred<void>();
    const done = deferred<void>();

    void (async () => {
      try {
        for (;;) {
          const message = await pump.next();
          if (message.type === MSG_READY) {
            gate.grant(CREDIT_WINDOW);
            ready.resolve();
          } else if (message.type === MSG_CREDIT) {
            gate.grant(decodeCredit(message.payload));
          } else if (message.type === MSG_DONE) {
            done.resolve();
            return;
          } else if (message.type === MSG_ABORT) {
            throw new Error(new TextDecoder().decode(message.payload) || 'The receiver cancelled');
          }
        }
      } catch (err) {
        const error = err instanceof Error ? err : new Error(String(err));
        gate.abort(error);
        ready.reject(error);
        done.reject(error);
      }
    })();

    onEvent({ t: 'status', message: 'Waiting for the receiver to accept...' });
    await withTimeout(
      ready.promise,
      10 * 60_000,
      'The receiver never started the transfer. They may need to pick where to save it.',
    );

    onEvent({ t: 'status', message: `Sending over ${link.kind === 'p2p' ? 'the direct connection' : 'the relay'}...` });

    const meter = new RateMeter(source.size);
    const progress = new ProgressThrottle(onEvent, meter, source.size);
    let plaintextRead = 0;

    let bytes$ = countBytes(source.stream(), (n) => { plaintextRead = n; });
    if (useCompression) bytes$ = gzip(bytes$);

    for await (const { bytes, isFinal } of rechunk(bytes$, LIVE_CHUNK_SIZE)) {
      throwIfAborted(abort);
      await gate.take();
      await send(MSG_DATA, await sealer.seal(bytes, isFinal), isFinal);
      progress.report(plaintextRead);
    }
    progress.report(source.size, true);
    sealer.destroy();

    onEvent({ t: 'status', message: 'Waiting for the receiver to verify...' });
    await done.promise;

    channel.destroy();
    onEvent({ t: 'status', message: 'Transfer complete and verified.' });
    onEvent({ t: 'done', name: source.name });
  } finally {
    cleanup?.();
    signal.close();
  }
}

function waitForPeer(signal: Signal, abort?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (fn: () => void) => { if (!settled) { settled = true; fn(); } };

    signal.onPeerJoined(() => finish(resolve));
    signal.onPeerLeft((reason) => finish(() => reject(new Error(reason))));
    abort?.addEventListener('abort', () => finish(() => reject(new AbortedError())), { once: true });
  });
}

