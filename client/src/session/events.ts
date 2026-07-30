import type { FileMeta } from '../crypto/format.js';
import type { ShortAuthString } from '../crypto/sas.js';

export type TransferEvent =
  | { t: 'code'; code: string }
  | { t: 'status'; message: string }
  | { t: 'peer'; joined: boolean }
  | { t: 'sas'; sas: ShortAuthString }
  | { t: 'link'; kind: 'p2p' | 'relay'; detail: string }
  | { t: 'meta'; meta: FileMeta }
  | { t: 'awaiting-destination'; meta: FileMeta }
  | { t: 'progress'; bytes: number; total: number; bytesPerSecond: number; etaSeconds: number }
  | { t: 'done'; name?: string; savedToDisk?: boolean; blob?: Blob }
  | { t: 'error'; message: string };

export type EventSink = (event: TransferEvent) => void;

/** Smoothed throughput and ETA for the progress display. */
export class RateMeter {
  private samples: { at: number; bytes: number }[] = [];
  private started = performance.now();

  constructor(private total: number) {}

  update(bytes: number): { bytesPerSecond: number; etaSeconds: number } {
    const now = performance.now();
    this.samples.push({ at: now, bytes });
    // Keep a ~3 second window so the readout reacts but does not jitter.
    while (this.samples.length > 2 && now - this.samples[0].at > 3000) this.samples.shift();

    const first = this.samples[0];
    const span = (now - first.at) / 1000;
    const bytesPerSecond = span > 0.2
      ? (bytes - first.bytes) / span
      : bytes / Math.max(0.001, (now - this.started) / 1000);

    const remaining = Math.max(0, this.total - bytes);
    return {
      bytesPerSecond: Math.max(0, bytesPerSecond),
      etaSeconds: bytesPerSecond > 1 ? remaining / bytesPerSecond : Infinity,
    };
  }
}

/** Emits at most ~12 progress events a second; the DOM cannot use more. */
export class ProgressThrottle {
  private last = 0;
  constructor(private sink: EventSink, private meter: RateMeter, private total: number) {}

  report(bytes: number, force = false): void {
    const now = performance.now();
    if (!force && now - this.last < 80) return;
    this.last = now;
    const { bytesPerSecond, etaSeconds } = this.meter.update(bytes);
    this.sink({ t: 'progress', bytes, total: this.total, bytesPerSecond, etaSeconds });
  }
}
