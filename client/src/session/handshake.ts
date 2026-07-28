/**
 * Drives the hybrid PQ handshake over the signalling channel.
 *
 * This runs concurrently with WebRTC negotiation - the two are independent, and
 * doing them in parallel hides the Argon2id cost behind the ICE gathering wait.
 * Handshake messages are multiplexed onto the same signalling channel as SDP
 * and ICE, distinguished by `kind`.
 */

import { Initiator, Responder, type ConfirmMessage, type HelloMessage, type ResponseMessage, type SessionKeys } from '../crypto/kex.js';
import type { KdfParams } from '../crypto/kdf.js';
import type { SuiteId } from '../crypto/aead.js';
import type { Signal } from '../transport/signal.js';

type KexEnvelope =
  | { kind: 'kex'; step: 'hello'; msg: HelloMessage }
  | { kind: 'kex'; step: 'response'; msg: ResponseMessage }
  | { kind: 'kex'; step: 'confirm'; msg: ConfirmMessage };

const HANDSHAKE_TIMEOUT_MS = 60_000;

/** Wait for one handshake step, ignoring the SDP/ICE traffic sharing this channel. */
function awaitStep<T>(signal: Signal, step: KexEnvelope['step'], timeoutMs = HANDSHAKE_TIMEOUT_MS): Promise<T> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error('The other device did not complete the secure handshake in time'));
    }, timeoutMs);

    signal.onSignal((raw) => {
      if (settled) return;
      const env = raw as KexEnvelope;
      if (env?.kind !== 'kex' || env.step !== step) return;
      settled = true;
      clearTimeout(timer);
      resolve(env.msg as T);
    });

    signal.onPeerLeft((reason) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(new Error(`Handshake aborted: ${reason}`));
    });
  });
}

export async function runInitiatorHandshake(
  signal: Signal,
  master: Uint8Array,
  salt: Uint8Array,
  kdf: KdfParams,
  suite: SuiteId,
): Promise<SessionKeys> {
  const initiator = Initiator.start(master, salt, kdf, suite);
  signal.sendSignal({ kind: 'kex', step: 'hello', msg: initiator.hello } satisfies KexEnvelope);

  const response = await awaitStep<ResponseMessage>(signal, 'response');
  const { session, confirm } = initiator.accept(response);
  signal.sendSignal({ kind: 'kex', step: 'confirm', msg: confirm } satisfies KexEnvelope);
  return session;
}

export async function runResponderHandshake(
  signal: Signal,
  deriveMasterFor: (salt: Uint8Array, kdf: KdfParams) => Promise<Uint8Array>,
): Promise<SessionKeys> {
  const hello = await awaitStep<HelloMessage>(signal, 'hello');
  // The sender chooses the salt and cost parameters; derive against those.
  const { salt, kdf } = Responder.parseHello(hello);
  const master = await deriveMasterFor(salt, kdf);

  const responder = Responder.respond(hello, master);
  signal.sendSignal({ kind: 'kex', step: 'response', msg: responder.response } satisfies KexEnvelope);

  const confirm = await awaitStep<ConfirmMessage>(signal, 'confirm');
  responder.verifyConfirm(confirm);
  return responder.session;
}
