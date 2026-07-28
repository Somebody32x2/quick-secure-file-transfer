/**
 * The outer encryption layer for live transfers.
 *
 * Live payloads are encrypted twice, and the two layers answer different
 * questions:
 *
 *   inner - ChunkSealer under the passphrase-derived key. Identical to what a
 *           stored transfer produces. Protects the file itself, end to end,
 *           forever, including against the server.
 *   outer - this channel, under the ephemeral hybrid-PQ session key. Gives the
 *           live session forward secrecy and post-quantum protection, and hides
 *           the inner container's header (salt, KDF params, chunk boundaries)
 *           from the relay and from anyone recording the wire.
 *
 * Keys are directional, so a frame sent by the sender can never be replayed
 * back at them. Nonces come from a local counter that is never transmitted:
 * both transports underneath are ordered and reliable, so any desync fails the
 * AEAD rather than silently accepting a reordered frame.
 */

import { createAead, wipe, type AeadContext } from './aead.js';
import { chunkNonce } from './format.js';
import type { SessionKeys } from './kex.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { concat, u32be, utf8 } from '../util/bytes.js';

export type Role = 'initiator' | 'responder';

const NONCE_PREFIX_LEN = 20;
const AAD_LABEL = 'qsft/v1/chan';

function directionKeys(secret: Uint8Array, direction: string): { key: Uint8Array; prefix: Uint8Array } {
  const out = hkdf(sha256, secret, undefined, utf8(`qsft/v1/chan/${direction}`), 32 + NONCE_PREFIX_LEN);
  return { key: out.slice(0, 32), prefix: out.slice(32) };
}

export class ChannelError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ChannelError';
  }
}

export class SecureChannel {
  private sendCounter = 0;
  private recvCounter = 0;
  private closedForSend = false;
  private closedForRecv = false;

  private constructor(
    private sendAead: AeadContext,
    private recvAead: AeadContext,
    private sendPrefix: Uint8Array,
    private recvPrefix: Uint8Array,
    private sendTag: number,
    private recvTag: number,
    private suite: number,
  ) {}

  static async create(session: SessionKeys, role: Role): Promise<SecureChannel> {
    const i2r = directionKeys(session.secret, 'i2r');
    const r2i = directionKeys(session.secret, 'r2i');
    const mine = role === 'initiator' ? i2r : r2i;
    const theirs = role === 'initiator' ? r2i : i2r;

    const sendAead = await createAead(session.suite, mine.key);
    const recvAead = await createAead(session.suite, theirs.key);
    wipe(mine.key);
    wipe(theirs.key);

    return new SecureChannel(
      sendAead, recvAead, mine.prefix, theirs.prefix,
      role === 'initiator' ? 0 : 1,
      role === 'initiator' ? 1 : 0,
      session.suite,
    );
  }

  private aad(direction: number, counter: number, isFinal: boolean): Uint8Array {
    return concat(
      utf8(AAD_LABEL),
      new Uint8Array([direction]),
      u32be(counter),
      new Uint8Array([isFinal ? 1 : 0]),
    );
  }

  /**
   * Encrypt one frame. `isFinal` marks the last frame of the session; the flag
   * is authenticated, so a relay that drops the tail cannot make the receiver
   * believe the transfer completed.
   */
  async seal(plaintext: Uint8Array, isFinal = false): Promise<Uint8Array> {
    if (this.closedForSend) throw new ChannelError('Channel already closed for sending');
    const i = this.sendCounter++;
    const out = await this.sendAead.seal(
      chunkNonce(this.sendPrefix, this.suite, i, isFinal),
      plaintext,
      this.aad(this.sendTag, i, isFinal),
    );
    if (isFinal) this.closedForSend = true;
    return out;
  }

  async open(ciphertext: Uint8Array, isFinal = false): Promise<Uint8Array> {
    if (this.closedForRecv) throw new ChannelError('Channel already closed for receiving');
    const i = this.recvCounter++;
    try {
      const out = await this.recvAead.open(
        chunkNonce(this.recvPrefix, this.suite, i, isFinal),
        ciphertext,
        this.aad(this.recvTag, i, isFinal),
      );
      if (isFinal) this.closedForRecv = true;
      return out;
    } catch {
      throw new ChannelError(
        `Session frame ${i} failed authentication. The connection was tampered with or desynchronised.`,
      );
    }
  }

  destroy(): void {
    this.sendAead.destroy();
    this.recvAead.destroy();
    wipe(this.sendPrefix);
    wipe(this.recvPrefix);
  }
}
