/**
 * Authenticated encryption, abstracted over two interchangeable suites.
 *
 * Suite 1 - XChaCha20-Poly1305, pure JS. Works everywhere including non-secure
 *           origins. ~80 MB/s. This is the universal baseline.
 * Suite 2 - AES-256-GCM. Uses WebCrypto when the host grants it (hardware
 *           accelerated, ~1 GB/s, which is what makes 2 GB files pleasant), and
 *           falls back to a pure-JS implementation for *decryption* so a
 *           receiver on a non-secure origin can still open a blob produced by a
 *           sender that had WebCrypto.
 *
 * The suite id lives in the file header, so any receiver can open any blob
 * regardless of which suite its own host would have chosen.
 */

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { gcm } from '@noble/ciphers/aes.js';
import { caps } from './env.js';

export const SUITE_XCHACHA20_POLY1305 = 1;
export const SUITE_AES_256_GCM = 2;
export type SuiteId = typeof SUITE_XCHACHA20_POLY1305 | typeof SUITE_AES_256_GCM;

export const TAG_LEN = 16;

export interface SuiteSpec {
  id: SuiteId;
  name: string;
  nonceLen: number;
  /** Bytes of the nonce that are random per-file; the rest is counter||lastFlag. */
  noncePrefixLen: number;
}

const SPECS: Record<SuiteId, SuiteSpec> = {
  [SUITE_XCHACHA20_POLY1305]: {
    id: SUITE_XCHACHA20_POLY1305,
    name: 'XChaCha20-Poly1305',
    nonceLen: 24,
    noncePrefixLen: 19,
  },
  [SUITE_AES_256_GCM]: {
    id: SUITE_AES_256_GCM,
    name: 'AES-256-GCM',
    nonceLen: 12,
    noncePrefixLen: 7,
  },
};

export function suiteSpec(id: number): SuiteSpec {
  const spec = SPECS[id as SuiteId];
  if (!spec) throw new Error(`Unsupported cipher suite: ${id}`);
  return spec;
}

/** Pick the fastest suite this host can actually drive. */
export function preferredSuite(): SuiteId {
  return caps.subtle ? SUITE_AES_256_GCM : SUITE_XCHACHA20_POLY1305;
}

export interface AeadContext {
  readonly spec: SuiteSpec;
  seal(nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  open(nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array>;
  destroy(): void;
}

/** Best-effort scrub of key material once a transfer completes. */
export function wipe(buf: Uint8Array | null | undefined): void {
  if (buf) buf.fill(0);
}

class NobleAead implements AeadContext {
  constructor(readonly spec: SuiteSpec, private key: Uint8Array) {}

  private cipher(nonce: Uint8Array, aad: Uint8Array) {
    return this.spec.id === SUITE_XCHACHA20_POLY1305
      ? xchacha20poly1305(this.key, nonce, aad)
      : gcm(this.key, nonce, aad);
  }

  async seal(nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    return this.cipher(nonce, aad).encrypt(plaintext);
  }

  async open(nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    return this.cipher(nonce, aad).decrypt(ciphertext);
  }

  destroy(): void {
    wipe(this.key);
    this.key = new Uint8Array(0);
  }
}

class WebCryptoGcm implements AeadContext {
  readonly spec = SPECS[SUITE_AES_256_GCM];
  constructor(private key: CryptoKey) {}

  async seal(nonce: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const out = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: bufferOf(nonce), additionalData: bufferOf(aad), tagLength: 128 },
      this.key,
      bufferOf(plaintext),
    );
    return new Uint8Array(out);
  }

  async open(nonce: Uint8Array, ciphertext: Uint8Array, aad: Uint8Array): Promise<Uint8Array> {
    const out = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bufferOf(nonce), additionalData: bufferOf(aad), tagLength: 128 },
      this.key,
      bufferOf(ciphertext),
    );
    return new Uint8Array(out);
  }

  destroy(): void { /* CryptoKey material is not reachable from JS */ }
}

/** WebCrypto rejects Uint8Array views with a non-zero offset in some engines. */
function bufferOf(u8: Uint8Array): ArrayBuffer {
  if (u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength) {
    return u8.buffer as ArrayBuffer;
  }
  return u8.slice().buffer as ArrayBuffer;
}

/**
 * Build an AEAD context. `key` must be 32 bytes. The caller owns the key and
 * should `wipe()` it after handing it over.
 */
export async function createAead(suite: number, key: Uint8Array): Promise<AeadContext> {
  const spec = suiteSpec(suite);
  if (key.length !== 32) throw new Error('AEAD key must be 32 bytes');

  if (spec.id === SUITE_AES_256_GCM && caps.subtle) {
    try {
      const cryptoKey = await crypto.subtle.importKey(
        'raw', bufferOf(key), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'],
      );
      return new WebCryptoGcm(cryptoKey);
    } catch {
      // Host advertised subtle but refused the key; use the JS implementation.
    }
  }
  return new NobleAead(spec, key.slice());
}
