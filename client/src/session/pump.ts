/**
 * Serialises inbound link frames through the secure channel.
 *
 * Frames arrive on a synchronous callback but decryption is async, and the
 * channel's nonce counter means they must be opened strictly in order. So every
 * frame is appended to a promise chain, and consumers pull decrypted messages
 * off a queue.
 */

import type { Link } from '../transport/link.js';
import type { SecureChannel } from '../crypto/channel.js';
import { decodeMessage, unwrapFrame, type MessageType } from './protocol.js';

export interface PumpedMessage {
  type: MessageType;
  payload: Uint8Array;
  isFinal: boolean;
}

export class MessagePump {
  private queue: PumpedMessage[] = [];
  private waiters: { resolve: (m: PumpedMessage) => void; reject: (e: Error) => void }[] = [];
  private failure: Error | null = null;
  /** Set once every frame received before the failure has been dealt with. */
  private drained = false;
  private chain: Promise<void> = Promise.resolve();

  constructor(link: Link, channel: SecureChannel) {
    link.onFrame((frame) => {
      this.chain = this.chain
        .then(async () => {
          const { sealed, isFinal } = unwrapFrame(frame);
          const plaintext = await channel.open(sealed, isFinal);
          const { type, payload } = decodeMessage(plaintext);
          this.push({ type, payload, isFinal });
        })
        .catch((err: unknown) => this.fail(err instanceof Error ? err : new Error(String(err))));
    });

    link.onClose((reason) => this.fail(new Error(reason)));
  }

  private push(message: PumpedMessage): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter.resolve(message);
    else this.queue.push(message);
  }

  /**
   * Record the failure, but let what already arrived be delivered first.
   *
   * Frames are decrypted asynchronously while a close is reported
   * synchronously, so a close can overtake a message that genuinely arrived
   * before it. That is not hypothetical: a receiver that finishes sends its
   * confirmation and immediately tears the connection down, and both reach the
   * sender in that order - but rejecting straight away meant the sender saw the
   * teardown, never the confirmation, and reported that the other device had
   * disconnected when it had actually completed and said so.
   *
   * Draining the chain first costs a tick and makes the two paths agree on
   * ordering. A close with nothing in flight still fails immediately.
   */
  private fail(error: Error): void {
    if (this.failure) return;
    this.failure = error;
    this.chain = this.chain.then(() => {
      this.drained = true;
      for (const w of this.waiters.splice(0)) w.reject(error);
    });
  }

  next(): Promise<PumpedMessage> {
    const queued = this.queue.shift();
    if (queued) return Promise.resolve(queued);
    // Only reject once anything still being decrypted has had its chance; until
    // then, wait - the message we are about to be told we will never get may
    // already be halfway through the door.
    if (this.failure && this.drained) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => this.waiters.push({ resolve, reject }));
  }

  /** Pull until a message of the expected type arrives, tolerating interleaved credits. */
  async expect(type: MessageType, onOther?: (m: PumpedMessage) => void): Promise<PumpedMessage> {
    for (;;) {
      const message = await this.next();
      if (message.type === type) return message;
      onOther?.(message);
    }
  }
}

/**
 * Credit-based send window. The receiver hands out permission to send N more
 * frames; without this the sender would outrun a slow disk or a slow relay and
 * pile the file up in someone else's memory.
 */
export class CreditGate {
  private credits = 0;
  private waiters: (() => void)[] = [];
  private aborted: Error | null = null;

  grant(n: number): void {
    if (n <= 0) return;
    this.credits += n;
    while (this.credits > 0 && this.waiters.length) {
      this.waiters.shift()!();
    }
  }

  abort(error: Error): void {
    this.aborted = error;
    this.waiters.splice(0).forEach((w) => w());
  }

  async take(): Promise<void> {
    if (this.aborted) throw this.aborted;
    while (this.credits <= 0) {
      await new Promise<void>((resolve) => this.waiters.push(resolve));
      if (this.aborted) throw this.aborted;
    }
    this.credits -= 1;
  }
}
