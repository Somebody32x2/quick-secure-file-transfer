/// <reference lib="webworker" />
/**
 * Argon2id off the main thread. Keeps the UI responsive during the ~1-3s
 * derivation, which matters most on phones.
 */
import { argon2id } from '@noble/hashes/argon2.js';

interface Request {
  passphrase: string;
  salt: Uint8Array;
  params: { memKiB: number; timeCost: number; lanes: number };
}

self.onmessage = (ev: MessageEvent<Request>) => {
  const { passphrase, salt, params } = ev.data;
  try {
    const key = argon2id(new TextEncoder().encode(passphrase.normalize('NFC')), salt, {
      m: params.memKiB,
      t: params.timeCost,
      p: params.lanes,
      dkLen: 32,
    });
    // Transfer rather than copy, then drop our reference.
    const buf = key.buffer as ArrayBuffer;
    (self as unknown as Worker).postMessage({ ok: true, key: buf }, [buf]);
  } catch (err) {
    (self as unknown as Worker).postMessage({
      ok: false,
      error: err instanceof Error ? err.message : String(err),
    });
  }
};
