/**
 * Drives the hybrid PQ handshake over the signalling channel.
 *
 * This runs concurrently with WebRTC negotiation - the two are independent, and
 * doing them in parallel hides the Argon2id cost behind the ICE gathering wait.
 * Handshake messages are multiplexed onto the same signalling channel as SDP
 * and ICE, distinguished by `kind`.
 */

import { HandshakeError, Initiator, Responder, type ConfirmMessage, type HelloMessage, type ResponseMessage, type SessionKeys } from '../crypto/kex.js';
import type { KdfParams } from '../crypto/kdf.js';
import type { SuiteId } from '../crypto/aead.js';
import type { Signal } from '../transport/signal.js';

type KexStep = 'hello' | 'response' | 'confirm';

type KexEnvelope =
  | { kind: 'kex'; step: 'hello'; msg: HelloMessage }
  | { kind: 'kex'; step: 'response'; msg: ResponseMessage }
  | { kind: 'kex'; step: 'confirm'; msg: ConfirmMessage }
  | { kind: 'kex-abort'; reason: 'auth' };

const HANDSHAKE_TIMEOUT_MS = 60_000;

/**
 * What a peer's abort means, decided here rather than sent over the wire.
 *
 * Only a fixed reason code travels; the wording is ours. The signalling channel
 * is reachable by anyone who guesses the six-digit code, so a free-text reason
 * would be attacker-supplied copy rendered inside our own failure notice - a
 * ready-made place to put "call this number".
 */
const ABORT_MESSAGES: Record<string, string> = {
  auth: 'Handshake authentication failed. Either the passphrases do not match, '
    + 'or someone is intercepting this connection.',
};

/** Wait for one handshake step, ignoring the SDP/ICE traffic sharing this channel. */
function awaitStep<T>(signal: Signal, step: KexStep, timeoutMs = HANDSHAKE_TIMEOUT_MS): Promise<T> {
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
      // The peer gave up and said why. Without this the device that did *not*
      // detect the failure only ever learns that the other one left, which on a
      // passphrase mismatch is reported to the very person who mistyped it.
      if (env?.kind === 'kex-abort') {
        settled = true;
        clearTimeout(timer);
        reject(new HandshakeError(
          ABORT_MESSAGES[env.reason] ?? 'The other device stopped the secure handshake.',
        ));
        return;
      }
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
  const accepted = tellPeerOnAuthFailure(signal, () => initiator.accept(response));
  signal.sendSignal({ kind: 'kex', step: 'confirm', msg: accepted.confirm } satisfies KexEnvelope);
  return accepted.session;
}

/**
 * Run a MAC check and, if it fails, say so to the peer before the socket closes.
 *
 * On a passphrase mismatch it is the *sender* that detects it first - the
 * responder's MAC is the first one checked - and the sender then tears the
 * session down. The receiver, who is the one who just typed the passphrase, was
 * left with "the other device ended the session": true, useless, and pointing at
 * the wrong device. One extra signal costs nothing and puts the explanation in
 * front of the person who can act on it.
 *
 * Only a MAC failure is forwarded. A malformed key or an unknown suite is the
 * peer's own problem to report, and saying "authentication failed" for those
 * would be a lie in the direction that makes people distrust the network.
 */
function tellPeerOnAuthFailure<T>(signal: Signal, run: () => T): T {
  try {
    return run();
  } catch (err) {
    if (err instanceof HandshakeError && err.code === 'auth') {
      signal.sendSignal({ kind: 'kex-abort', reason: 'auth' } satisfies KexEnvelope);
    }
    throw err;
  }
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
  tellPeerOnAuthFailure(signal, () => responder.verifyConfirm(confirm));
  return responder.session;
}
