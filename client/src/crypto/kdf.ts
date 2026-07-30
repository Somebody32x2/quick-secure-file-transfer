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
 * Ceiling on Argon2 parameters a *peer* may impose on us.
 *
 * Both the live handshake and the container header carry these values, and both
 * are consumed before anything has been authenticated - a hostile sender, or a
 * hostile server serving a header, chooses them. Bounding each field on its own
 * is not enough: the cost is the product, and m=1 GiB with t=16 and p=16 sat
 * inside per-field limits while costing minutes of CPU and a gigabyte of RAM.
 * On a phone that is not a slow transfer, it is a dead tab.
 *
 * The allowance is 8x the shipped default's work and 128 MiB of memory, which
 * leaves plenty of room to raise the defaults later without invalidating a
 * single existing container.
 */
export const MAX_KDF_MEM_KIB = 128 * 1024;
export const MAX_KDF_COST =
  8 * (ARGON2_DEFAULTS.memKiB * ARGON2_DEFAULTS.timeCost * ARGON2_DEFAULTS.lanes);

/**
 * Validate peer-supplied cost parameters. Throws with a message naming the
 * offending field; callers wrap it in their own error type.
 */
export function assertKdfParams({ memKiB, timeCost, lanes }: KdfParams): void {
  if (!Number.isInteger(memKiB) || memKiB < 1024 || memKiB > MAX_KDF_MEM_KIB) {
    throw new Error('Rejecting out-of-range Argon2 memory cost');
  }
  if (!Number.isInteger(timeCost) || timeCost < 1 || timeCost > 16) {
    throw new Error('Rejecting out-of-range Argon2 time cost');
  }
  if (!Number.isInteger(lanes) || lanes < 1 || lanes > 16) {
    throw new Error('Rejecting out-of-range Argon2 lanes');
  }
  if (memKiB * timeCost * lanes > MAX_KDF_COST) {
    throw new Error('Rejecting Argon2 parameters that would cost too much to honour');
  }
}

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
 * A timeout means the work itself was too expensive, so retrying it inline would
 * only move the same cost onto the main thread. Tagged so `deriveMaster` can
 * tell it apart from "this host has no usable Worker", which is the only case
 * the inline path exists for.
 */
class KdfTimeoutError extends Error {
  constructor() {
    super('Key derivation timed out. The other device asked for a more expensive '
      + 'key derivation than this one can complete.');
    this.name = 'KdfTimeoutError';
  }
}

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
      reject(new KdfTimeoutError());
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
  // Peer-supplied on both the live and stored paths; never derive against
  // parameters we have not agreed are affordable.
  assertKdfParams(params);

  if (typeof Worker === 'function' && !workerFailed) {
    try {
      return await deriveInWorker(passphrase, salt, params);
    } catch (err) {
      // Only a host that cannot run a worker falls back to the main thread. A
      // timeout means the work was too expensive to finish at all, and running
      // it again inline would freeze the tab for exactly as long as it just
      // spent not finishing in the background.
      if (err instanceof KdfTimeoutError) throw err;
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

/*
 * There was a `sessionSalt(roomCode)` here that derived the live-session salt
 * from the 6-digit room code. It is gone on purpose, and should not come back:
 * it made the salt public, one of only 10^6 values, and known to the server
 * before the transfer began - which is precisely the precomputation a salt
 * exists to prevent. Live senders now draw a random salt and put it in HELLO,
 * the same way stored transfers put one in the container header.
 */
