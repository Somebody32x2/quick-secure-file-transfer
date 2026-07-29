/**
 * One ordered, reliable, message-oriented pipe - however we got it.
 *
 * The session layer above this does not care whether bytes are flowing over a
 * direct data channel or bouncing off the server, because the payload is
 * encrypted identically either way. This module's whole job is to hide that
 * difference and to apply backpressure so a fast sender cannot pile up a 2 GB
 * file in anyone's memory.
 */

import type { Signal } from './signal.js';
import { tryDirectConnection, type IceServerConfig } from './p2p.js';

export type LinkKind = 'p2p' | 'relay';

export interface Link {
  readonly kind: LinkKind;
  /** Short human description for the UI, e.g. "direct (local network)". */
  readonly detail: string;
  send(frame: Uint8Array): Promise<void>;
  onFrame(cb: (frame: Uint8Array) => void): void;
  onClose(cb: (reason: string) => void): void;
  close(): void;
}

/** Conservative data-channel write size; every browser handles 16 KiB happily. */
const DC_SLICE = 16 * 1024;
/** Pause writing above this and resume when the channel drains. */
const DC_HIGH_WATER = 1024 * 1024;
/** Refuse to allocate a reassembly buffer larger than this. */
const MAX_FRAME_BYTES = 2 * 1024 * 1024;
/** Relay: stop feeding Socket.IO when its outbound queue is this deep. */
const RELAY_BACKLOG_LIMIT = 24;

export class LinkError extends Error {}

/** Reassembles a u32-length-prefixed frame stream from arbitrary slices. */
class FrameReassembler {
  private buffer: Uint8Array = new Uint8Array(0);
  constructor(private onFrame: (frame: Uint8Array) => void, private onFail: (why: string) => void) {}

  push(bytes: Uint8Array): void {
    this.buffer = this.buffer.length === 0 ? bytes.slice() : concat(this.buffer, bytes);
    for (;;) {
      if (this.buffer.length < 4) return;
      const view = new DataView(this.buffer.buffer, this.buffer.byteOffset, this.buffer.byteLength);
      const length = view.getUint32(0, false);
      if (length > MAX_FRAME_BYTES) {
        this.onFail(`Peer announced an absurd ${length}-byte frame`);
        return;
      }
      if (this.buffer.length < 4 + length) return;
      this.onFrame(this.buffer.slice(4, 4 + length));
      this.buffer = this.buffer.slice(4 + length);
    }
  }
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

class P2pLink implements Link {
  readonly kind = 'p2p';
  private frameHandlers: ((f: Uint8Array) => void)[] = [];
  private closeHandlers: ((r: string) => void)[] = [];
  private closed = false;
  private reassembler: FrameReassembler;

  constructor(private channel: RTCDataChannel, readonly detail: string) {
    this.reassembler = new FrameReassembler(
      (frame) => this.frameHandlers.forEach((h) => h(frame)),
      (why) => this.fail(why),
    );
    channel.bufferedAmountLowThreshold = DC_HIGH_WATER / 2;
    channel.onmessage = (ev: MessageEvent) => {
      const data = ev.data instanceof ArrayBuffer ? new Uint8Array(ev.data) : null;
      if (!data) return;
      this.reassembler.push(data);
    };
    channel.onclose = () => this.fail('the direct connection closed');
    channel.onerror = () => this.fail('the direct connection failed');
  }

  private fail(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.closeHandlers.forEach((h) => h(reason));
  }

  private waitForDrain(): Promise<void> {
    return new Promise((resolve) => {
      const done = () => { this.channel.onbufferedamountlow = null; resolve(); };
      this.channel.onbufferedamountlow = done;
      // Safety net: some engines are unreliable about firing the event.
      setTimeout(() => { if (this.channel.bufferedAmount < DC_HIGH_WATER) done(); }, 250);
    });
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.closed || this.channel.readyState !== 'open') {
      throw new LinkError('The direct connection is no longer open');
    }
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, frame.length, false);
    const message = concat(header, frame);

    for (let off = 0; off < message.length; off += DC_SLICE) {
      while (this.channel.bufferedAmount > DC_HIGH_WATER) {
        await this.waitForDrain();
        if (this.closed || this.channel.readyState !== 'open') {
          throw new LinkError('The direct connection dropped mid-transfer');
        }
      }
      const slice = message.subarray(off, Math.min(off + DC_SLICE, message.length));
      // TS models RTCDataChannel.send as needing an ArrayBuffer-backed view;
      // a subarray is ArrayBufferLike-backed, which is the same thing at runtime.
      this.channel.send(slice as unknown as ArrayBuffer);
    }
  }

  onFrame(cb: (f: Uint8Array) => void): void { this.frameHandlers.push(cb); }
  onClose(cb: (r: string) => void): void { this.closeHandlers.push(cb); }

  close(): void {
    this.closed = true;
    try { this.channel.close(); } catch { /* already closed */ }
  }
}

class RelayLink implements Link {
  readonly kind = 'relay';
  readonly detail = 'relayed through the server (encrypted end-to-end)';
  private frameHandlers: ((f: Uint8Array) => void)[] = [];
  private closeHandlers: ((r: string) => void)[] = [];
  private closed = false;

  constructor(private signal: Signal) {
    signal.onData((frame) => this.frameHandlers.forEach((h) => h(frame)));
    signal.onPeerLeft((reason) => {
      if (this.closed) return;
      this.closed = true;
      this.closeHandlers.forEach((h) => h(reason));
    });
  }

  async send(frame: Uint8Array): Promise<void> {
    if (this.closed) throw new LinkError('The session has ended');
    // Socket.IO gives us no write callback, so throttle on its queue depth.
    // Without this the relay would happily accept a whole file into RAM.
    let waited = 0;
    while (this.signal.outboundBacklog > RELAY_BACKLOG_LIMIT) {
      await new Promise((r) => setTimeout(r, 20));
      waited += 20;
      if (this.closed) throw new LinkError('The session has ended');
      if (waited > 60_000) throw new LinkError('The relay stopped draining');
    }
    this.signal.sendData(frame);
  }

  onFrame(cb: (f: Uint8Array) => void): void { this.frameHandlers.push(cb); }
  onClose(cb: (r: string) => void): void { this.closeHandlers.push(cb); }

  close(): void { this.closed = true; }
}

function describeCandidate(type: string): string {
  switch (type) {
    case 'host': return 'direct (local network)';
    case 'srflx': case 'prflx': return 'direct (through NAT)';
    case 'relay': return 'direct (via TURN)';
    default: return 'direct';
  }
}

/**
 * Try direct first, fall back to the relay - and make sure both devices reach
 * the same answer.
 *
 * Deciding independently is not safe. The two sides run separate WebRTC
 * attempts with separate timeouts, so one can succeed while the other gives up
 * (a phone on cellular and a laptop on wifi will not agree on how long ICE
 * takes). The winner then writes to a data channel while the loser listens on
 * the relay socket, and the transfer deadlocks with no error on either side.
 *
 * So each device reports its own result and waits for the peer's. Direct is
 * used only if *both* got there; otherwise both fall back together.
 */
export async function establishLink(
  signal: Signal,
  role: 'offerer' | 'answerer',
  iceServers: IceServerConfig[],
  onProgress?: (message: string) => void,
): Promise<Link> {
  onProgress?.('Trying a direct connection...');
  const direct = await tryDirectConnection(signal, role, iceServers);

  signal.sendSignal({ kind: 'link', p2p: !!direct });
  onProgress?.(direct
    ? 'Direct connection up - checking the other device agrees...'
    : 'Direct connection unavailable - agreeing on the relay...');

  let peerHasDirect = false;
  try {
    const peer = await signal.waitFor<{ p2p?: boolean }>('link', 45_000);
    peerHasDirect = !!peer.p2p;
  } catch {
    // No word from the peer: the relay is the safe assumption, since it is the
    // one path that cannot have been half-established.
    peerHasDirect = false;
  }

  if (direct && peerHasDirect) {
    const detail = describeCandidate(direct.candidateType);
    onProgress?.(`Connected ${detail}`);
    return new P2pLink(direct.channel, detail);
  }

  if (direct) {
    // We got a channel but the peer did not; tear it down so nothing is written
    // into a pipe the other end is not reading.
    try { direct.channel.close(); direct.pc.close(); } catch { /* already gone */ }
  }

  onProgress?.('Using the encrypted relay');
  return new RelayLink(signal);
}
