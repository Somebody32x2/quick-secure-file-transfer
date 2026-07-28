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
import { ARGON2_DEFAULTS, deriveMaster, sessionSalt } from '../crypto/kdf.js';
import { preferredSuite } from '../crypto/aead.js';
import { MAX_FILE_BYTES } from '../crypto/format.js';
import { compress as gzip, compressionAvailable } from '../compress.js';
import { countBytes, fileReadable, rechunk } from '../chunker.js';
import { Signal } from '../transport/signal.js';
import { establishLink } from '../transport/link.js';
import { fetchServerConfig } from '../transport/api.js';
import { deferred, throwIfAborted, AbortedError } from '../util/deferred.js';
import { ProgressThrottle, RateMeter, type EventSink } from './events.js';
import { runInitiatorHandshake } from './handshake.js';
import { CreditGate, MessagePump } from './pump.js';
import {
  CREDIT_WINDOW, LIVE_CHUNK_SIZE, MSG_ABORT, MSG_CREDIT, MSG_DATA, MSG_DONE,
  MSG_HEADER, MSG_META, MSG_READY, decodeCredit, encodeMessage, wrapFrame,
} from './protocol.js';

export interface LiveSendOptions {
  file: File;
  passphrase: string;
  compress: boolean;
  onEvent: EventSink;
  abort?: AbortSignal;
}

export async function liveSend(options: LiveSendOptions): Promise<void> {
  const { file, passphrase, onEvent, abort } = options;
  if (file.size > MAX_FILE_BYTES) {
    throw new Error('That file is larger than the 2 GB limit');
  }

  const serverConfig = await fetchServerConfig();
  const signal = await Signal.connect();
  let cleanup: (() => void) | null = null;

  try {
    const code = await signal.host();
    onEvent({ t: 'code', code });

    const salt = sessionSalt(code);
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

    await send(MSG_HEADER, sealer.headerBytes);
    await send(MSG_META, await sealer.sealMeta({
      name: file.name, size: file.size, type: file.type, lastModified: file.lastModified,
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

    onEvent({ t: 'status', message: 'Waiting for the receiver to choose where to save...' });
    await ready.promise;

    onEvent({ t: 'status', message: `Sending over ${link.kind === 'p2p' ? 'the direct connection' : 'the relay'}...` });

    const meter = new RateMeter(file.size);
    const progress = new ProgressThrottle(onEvent, meter, file.size);
    let plaintextRead = 0;

    let source = countBytes(fileReadable(file), (n) => { plaintextRead = n; });
    if (useCompression) source = gzip(source);

    for await (const { bytes, isFinal } of rechunk(source, LIVE_CHUNK_SIZE)) {
      throwIfAborted(abort);
      await gate.take();
      await send(MSG_DATA, await sealer.seal(bytes, isFinal), isFinal);
      progress.report(plaintextRead);
    }
    progress.report(file.size, true);
    sealer.destroy();

    onEvent({ t: 'status', message: 'Waiting for the receiver to verify...' });
    await done.promise;

    channel.destroy();
    onEvent({ t: 'status', message: 'Transfer complete and verified.' });
    onEvent({ t: 'done', name: file.name });
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

