/**
 * Socket.IO control channel.
 *
 * Carries two things: WebRTC negotiation for the direct path, and - when direct
 * fails - the encrypted payload frames themselves. In both cases everything the
 * server sees is opaque: handshake messages are public-key material bound to a
 * MAC it cannot forge, and payload frames are sealed under a session key it
 * never had.
 */

import { io, type Socket } from 'socket.io-client';

export type PeerLeftReason = string;

export class SignalError extends Error {}

/** Enough to hold a full SDP exchange plus a burst of ICE candidates. */
const SIGNAL_HISTORY_LIMIT = 256;

export class Signal {
  private socket: Socket;
  private signalHistory: unknown[] = [];
  private peerJoinedSeen = false;
  private handlers = {
    peerJoined: [] as (() => void)[],
    peerLeft: [] as ((reason: PeerLeftReason) => void)[],
    signal: [] as ((payload: unknown) => void)[],
    data: [] as ((frame: Uint8Array) => void)[],
    error: [] as ((message: string) => void)[],
  };

  private constructor(socket: Socket) {
    this.socket = socket;
    socket.on('live:peer-joined', () => {
      this.peerJoinedSeen = true;
      this.handlers.peerJoined.forEach((h) => h());
    });
    socket.on('live:peer-left', (p: { reason?: string }) => {
      this.handlers.peerLeft.forEach((h) => h(p?.reason ?? 'the other device disconnected'));
    });
    socket.on('live:signal', (payload: unknown) => {
      this.signalHistory.push(payload);
      if (this.signalHistory.length > SIGNAL_HISTORY_LIMIT) this.signalHistory.shift();
      this.handlers.signal.forEach((h) => h(payload));
    });
    socket.on('live:data', (payload: ArrayBuffer | Uint8Array) => {
      const frame = payload instanceof Uint8Array ? payload : new Uint8Array(payload);
      this.handlers.data.forEach((h) => h(frame));
    });
    socket.on('live:error', (p: { message?: string }) => {
      this.handlers.error.forEach((h) => h(p?.message ?? 'relay error'));
    });
  }

  static connect(timeoutMs = 15_000): Promise<Signal> {
    return new Promise((resolve, reject) => {
      const socket = io({
        transports: ['websocket', 'polling'],
        reconnection: false,
        timeout: timeoutMs,
      });
      const timer = setTimeout(() => {
        socket.close();
        reject(new SignalError('Could not reach the server'));
      }, timeoutMs);

      socket.on('connect', () => { clearTimeout(timer); resolve(new Signal(socket)); });
      socket.on('connect_error', (err: Error) => {
        clearTimeout(timer);
        socket.close();
        reject(new SignalError(`Could not reach the server: ${err.message}`));
      });
    });
  }

  private emitWithAck<T>(event: string, payload: unknown): Promise<T> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new SignalError('Server did not respond')), 15_000);
      this.socket.emit(event, payload, (response: { error?: string } & T) => {
        clearTimeout(timer);
        if (response?.error) reject(new SignalError(response.error));
        else resolve(response);
      });
    });
  }

  /** Create a live session; resolves to the 6-digit code the receiver types in. */
  async host(): Promise<string> {
    const { code } = await this.emitWithAck<{ code: string }>('live:host', {});
    return code;
  }

  async join(code: string): Promise<void> {
    await this.emitWithAck<{ ok: true }>('live:join', { code });
  }

  sendSignal(payload: unknown): void {
    this.socket.emit('live:signal', payload);
  }

  sendData(frame: Uint8Array): void {
    this.socket.emit('live:data', frame);
  }

  onPeerJoined(cb: () => void): void {
    this.handlers.peerJoined.push(cb);
    if (this.peerJoinedSeen) cb();
  }

  onPeerLeft(cb: (reason: PeerLeftReason) => void): void { this.handlers.peerLeft.push(cb); }

  /**
   * Replays signals received before this handler attached.
   *
   * WebRTC negotiation and the PQ handshake share this channel and attach their
   * handlers at different moments, so an offer or a HELLO can easily land first.
   * Every consumer filters by message kind and ignores what is not theirs, so
   * replaying the whole history to each new handler is safe - and losing a
   * single SDP offer to a race is not.
   */
  onSignal(cb: (payload: unknown) => void): void {
    this.handlers.signal.push(cb);
    for (const past of this.signalHistory) cb(past);
  }
  onData(cb: (frame: Uint8Array) => void): void { this.handlers.data.push(cb); }
  onError(cb: (message: string) => void): void { this.handlers.error.push(cb); }

  /** Socket.IO's own outbound queue depth, used for relay backpressure. */
  get outboundBacklog(): number {
    return (this.socket as any).sendBuffer?.length ?? 0;
  }

  get connected(): boolean { return this.socket.connected; }

  close(): void {
    try { this.socket.emit('live:bye'); } catch { /* socket already gone */ }
    this.socket.close();
  }
}
