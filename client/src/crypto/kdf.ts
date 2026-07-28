/**
 * Passphrase key derivation.
 *
 * Argon2id is used unconditionally and in pure JS. It deliberately does *not*
 * fall back to WebCrypto PBKDF2 when available: sender and receiver must derive
 * byte-identical keys, so the KDF cannot vary with host capabilities. Cost
 * parameters travel in the file header, so they can be raised later without
 * breaking old ciphertexts.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { argon2id } from '@noble/hashes/argon2.js';

export interface KdfParams {
  /** Memory cost in KiB. */
  memKiB: number;
  /** Iterations. */
  timeCost: number;
  /** Lanes / parallelism. */
  lanes: number;
}

/**
 * OWASP's recommended Argon2id floor (19 MiB, t=2, p=1). Measured at ~0.7s on a
 * desktop and ~2-3s on a mid-range phone in pure JS, which is the most we can
 * charge a user on a mobile device without the UI feeling broken.
 */
export const ARGON2_DEFAULTS: KdfParams = { memKiB: 19456, timeCost: 2, lanes: 1 };

export const SALT_LEN = 16;

/**
 * Normalise the passphrase so the same typed characters produce the same key
 * across platforms. iOS and Android keyboards emit different Unicode
 * normalisation forms for accented characters and emoji.
 */
function encodePassphrase(passphrase: string): Uint8Array {
  return new TextEncoder().encode(passphrase.normalize('NFC'));
}

function argon2Sync(passphrase: string, salt: Uint8Array, params: KdfParams): Uint8Array {
  return argon2id(encodePassphrase(passphrase), salt, {
    m: params.memKiB,
    t: params.timeCost,
    p: params.lanes,
    dkLen: 32,
  });
}

// ---------------------------------------------------------------------------
// Worker offload
// ---------------------------------------------------------------------------

let workerFailed = false;

/**
 * Argon2id blocks the thread for seconds. On mobile that reads as a frozen tab,
 * so push it to a worker when one is available and fall back to inline
 * computation (with a yield first, so the UI can paint a spinner) otherwise.
 */
function deriveInWorker(
  passphrase: string,
  salt: Uint8Array,
  params: KdfParams,
): Promise<Uint8Array> {
  return new Promise((resolve, reject) => {
    let worker: Worker;
    try {
      worker = new Worker(new URL('./kdf.worker.ts', import.meta.url), { type: 'module' });
    } catch (err) {
      workerFailed = true;
      reject(err);
      return;
    }
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new Error('Key derivation timed out'));
    }, 120_000);

    worker.onmessage = (ev: MessageEvent) => {
      clearTimeout(timer);
      worker.terminate();
      const data = ev.data as { ok: boolean; key?: ArrayBuffer; error?: string };
      if (data.ok && data.key) resolve(new Uint8Array(data.key));
      else reject(new Error(data.error ?? 'Key derivation failed'));
    };
    worker.onerror = (ev) => {
      clearTimeout(timer);
      worker.terminate();
      workerFailed = true;
      reject(new Error(ev.message || 'Key derivation worker crashed'));
    };
    worker.postMessage({ passphrase, salt, params });
  });
}

/**
 * Derive the 32-byte master secret from the passphrase. Everything else in the
 * protocol is an HKDF label off this value, so the expensive Argon2id pass runs
 * exactly once per transfer.
 */
export async function deriveMaster(
  passphrase: string,
  salt: Uint8Array,
  params: KdfParams = ARGON2_DEFAULTS,
): Promise<Uint8Array> {
  if (salt.length !== SALT_LEN) throw new Error(`salt must be ${SALT_LEN} bytes`);
  if (!passphrase) throw new Error('A passphrase is required');

  if (typeof Worker === 'function' && !workerFailed) {
    try {
      return await deriveInWorker(passphrase, salt, params);
    } catch {
      // fall through to inline
    }
  }
  // Yield once so a spinner can paint before we monopolise the main thread.
  await new Promise((r) => setTimeout(r, 0));
  return argon2Sync(passphrase, salt, params);
}

// ---------------------------------------------------------------------------
// Subkey separation
// ---------------------------------------------------------------------------

export const LABEL_FILE_KEY = 'qsft/v1/file-key';
export const LABEL_SESSION_AUTH = 'qsft/v1/session-auth';
export const LABEL_METADATA = 'qsft/v1/metadata';

/**
 * HKDF-Expand a labelled subkey from the master secret. Distinct labels give
 * cryptographically independent keys, so the live-session authenticator can
 * never be used to attack the file key.
 */
export function subkey(master: Uint8Array, label: string, length = 32): Uint8Array {
  return hkdf(sha256, master, undefined, new TextEncoder().encode(label), length);
}

/** Deterministic salt for live sessions, so both peers derive the same master. */
export function sessionSalt(roomCode: string): Uint8Array {
  return sha256(new TextEncoder().encode(`qsft/v1/session-salt/${roomCode}`)).subarray(0, SALT_LEN);
}
