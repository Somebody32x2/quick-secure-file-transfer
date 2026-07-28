/**
 * Environment capability detection and randomness.
 *
 * QSFT is designed to run on untrusted / non-secure origins (plain http on a
 * LAN IP, a phone hitting 192.168.x.x, a captive dev box). In those contexts
 * browsers withhold `crypto.subtle` entirely, and a few hardened WebViews ship
 * a `crypto` object with a broken or absent `getRandomValues`.
 *
 * Every cryptographic primitive in this app is therefore pure JavaScript
 * (@noble/*) and every random byte flows through `randomBytes()` here. Nothing
 * in the transfer path requires WebCrypto; when WebCrypto *is* present we only
 * use it as an optional accelerator (AES-GCM), never as a correctness
 * dependency.
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';

export interface Capabilities {
  /** window.isSecureContext - false on plain-http LAN addresses. */
  secureContext: boolean;
  /** crypto.subtle present and usable (enables the AES-GCM fast path). */
  subtle: boolean;
  /** A working crypto.getRandomValues was found. */
  nativeRandom: boolean;
  /** True when we had to fall back to the software DRBG. Surfaced in the UI. */
  degradedRandom: boolean;
  /** CompressionStream / DecompressionStream for client-side gzip. */
  compression: boolean;
  /** RTCPeerConnection for the direct P2P path. */
  webrtc: boolean;
  /** showSaveFilePicker - lets us stream large files straight to disk. */
  fileSystemAccess: boolean;
}

// ---------------------------------------------------------------------------
// Randomness
// ---------------------------------------------------------------------------

/**
 * Software DRBG used only when the host provides no usable getRandomValues.
 *
 * Construction is HMAC-DRBG-shaped: state is a 32-byte key, output is
 * HMAC(key, counter) blocks, and the key is ratcheted forward after every
 * request so output is forward-secure. It is seeded from every weak entropy
 * source the page can reach, and continuously reseeded from user input timing.
 *
 * This is a genuine downgrade and the UI says so loudly. It exists so the app
 * degrades to "probably fine" rather than "throws and cannot run at all".
 */
class SoftwareDRBG {
  private key: Uint8Array;
  private counter = 0n;
  private pool: number[] = [];

  constructor() {
    this.key = sha256(this.collectStaticEntropy());
  }

  private collectStaticEntropy(): Uint8Array {
    const bits: string[] = [];
    const g = globalThis as Record<string, any>;
    bits.push(String(Date.now()), String(performance.now()));
    // Timing jitter: the exact loop count reached in a fixed wall-clock window
    // varies with CPU scheduling and is the main real entropy source here.
    for (let round = 0; round < 24; round++) {
      const deadline = performance.now() + 1;
      let spins = 0;
      while (performance.now() < deadline) spins++;
      bits.push(String(spins), performance.now().toFixed(6));
    }
    for (let i = 0; i < 64; i++) bits.push(String(Math.random()));
    try {
      const n = g.navigator ?? {};
      const s = g.screen ?? {};
      bits.push(
        String(n.userAgent), String(n.language), String(n.hardwareConcurrency),
        String(n.deviceMemory), String(s.width), String(s.height),
        String(s.colorDepth), String(new Date().getTimezoneOffset()),
      );
      if (g.performance?.memory) bits.push(JSON.stringify(g.performance.memory));
    } catch { /* property access can throw in locked-down WebViews */ }
    return new TextEncoder().encode(bits.join('|'));
  }

  /** Mix in externally observed entropy (pointer/key timings). */
  addEntropy(...values: number[]): void {
    for (const v of values) this.pool.push(v);
    if (this.pool.length >= 32) this.reseed();
  }

  private reseed(): void {
    const material = new TextEncoder().encode(this.pool.join('|') + performance.now());
    this.pool.length = 0;
    this.key = hmac(sha256, this.key, material);
  }

  bytes(n: number): Uint8Array {
    const out = new Uint8Array(n);
    let off = 0;
    while (off < n) {
      const ctr = new Uint8Array(16);
      new DataView(ctr.buffer).setBigUint64(0, this.counter++, false);
      new DataView(ctr.buffer).setFloat64(8, performance.now(), false);
      const block = hmac(sha256, this.key, ctr);
      const take = Math.min(32, n - off);
      out.set(block.subarray(0, take), off);
      off += take;
    }
    // Ratchet: past output cannot be recovered from the new state.
    this.key = hmac(sha256, this.key, new TextEncoder().encode('qsft-drbg-ratchet'));
    return out;
  }
}

let drbg: SoftwareDRBG | null = null;
let nativeRandomOk = false;

/**
 * Probe getRandomValues for existence and for the "returns all zeros" failure
 * mode seen in some stripped-down WebViews and older polyfills.
 */
function probeNativeRandom(): boolean {
  try {
    const c = globalThis.crypto;
    if (!c || typeof c.getRandomValues !== 'function') return false;
    let allZero = true;
    let identical = true;
    let prev: Uint8Array | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      const buf = new Uint8Array(32);
      c.getRandomValues(buf);
      if (buf.some((b) => b !== 0)) allZero = false;
      if (prev && !buf.every((b, i) => b === prev![i])) identical = false;
      prev = buf;
    }
    return !allZero && !identical;
  } catch {
    return false;
  }
}

nativeRandomOk = probeNativeRandom();
if (!nativeRandomOk) {
  drbg = new SoftwareDRBG();
  // Install a polyfill so any transitive dependency that reaches for
  // crypto.getRandomValues (noble does, internally) still works.
  const target: any = globalThis.crypto ?? {};
  target.getRandomValues = <T extends ArrayBufferView>(arr: T): T => {
    const bytes = drbg!.bytes(arr.byteLength);
    new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength).set(bytes);
    return arr;
  };
  if (!globalThis.crypto) {
    try {
      Object.defineProperty(globalThis, 'crypto', { value: target, configurable: true });
    } catch { /* non-configurable global; the polyfill above still serves us */ }
  }
}

/** The single source of random bytes for the entire application. */
export function randomBytes(n: number): Uint8Array {
  if (nativeRandomOk) {
    const out = new Uint8Array(n);
    // getRandomValues caps at 65536 bytes per call.
    for (let off = 0; off < n; off += 65536) {
      const view = out.subarray(off, Math.min(off + 65536, n));
      globalThis.crypto.getRandomValues(view);
    }
    return out;
  }
  return drbg!.bytes(n);
}

/** Feed observed input timing into the software DRBG (no-op when native RNG works). */
export function stirEntropy(...values: number[]): void {
  drbg?.addEntropy(...values);
}

// ---------------------------------------------------------------------------
// Capability detection
// ---------------------------------------------------------------------------

function detectSubtle(): boolean {
  try {
    const s = globalThis.crypto?.subtle;
    return !!s && typeof s.importKey === 'function' && typeof s.encrypt === 'function';
  } catch {
    return false;
  }
}

export const caps: Capabilities = {
  secureContext: (() => { try { return !!globalThis.isSecureContext; } catch { return false; } })(),
  subtle: detectSubtle(),
  nativeRandom: nativeRandomOk,
  degradedRandom: !nativeRandomOk,
  compression: typeof (globalThis as any).CompressionStream === 'function'
    && typeof (globalThis as any).DecompressionStream === 'function',
  webrtc: typeof (globalThis as any).RTCPeerConnection === 'function',
  fileSystemAccess: typeof (globalThis as any).showSaveFilePicker === 'function',
};

/** Human-readable summary shown in the UI's diagnostics panel. */
export function describeEnvironment(): { label: string; ok: boolean; note: string }[] {
  return [
    {
      label: 'Secure context',
      ok: caps.secureContext,
      note: caps.secureContext
        ? 'HTTPS or localhost'
        : 'Plain HTTP origin - WebCrypto is withheld by the browser; pure-JS crypto in use',
    },
    {
      label: 'Randomness',
      ok: caps.nativeRandom,
      note: caps.nativeRandom
        ? 'crypto.getRandomValues (CSPRNG)'
        : 'DEGRADED: software DRBG seeded from timing jitter. Do not use for high-value secrets.',
    },
    {
      label: 'Cipher',
      ok: true,
      note: caps.subtle
        ? 'AES-256-GCM via WebCrypto (hardware accelerated)'
        : 'XChaCha20-Poly1305 (pure JS)',
    },
    {
      label: 'Compression',
      ok: caps.compression,
      note: caps.compression ? 'gzip via CompressionStream' : 'unavailable - sending uncompressed',
    },
    {
      label: 'Direct P2P',
      ok: caps.webrtc,
      note: caps.webrtc ? 'WebRTC data channel available' : 'unavailable - will use encrypted relay',
    },
    {
      label: 'Streaming save',
      ok: caps.fileSystemAccess,
      note: caps.fileSystemAccess
        ? 'File System Access API - streams straight to disk'
        : 'buffering to a Blob (browser spills to disk; very large files may strain memory)',
    },
  ];
}
