/**
 * Message framing inside the encrypted session.
 *
 * Each link frame looks like:
 *
 *   [u8 finalFlag][ sealed channel frame ]
 *
 * The final flag rides in the clear but is bound into the AEAD's associated
 * data at *both* layers, so a relay that flips it breaks authentication instead
 * of truncating the transfer silently. The receiver needs the flag before it
 * can decrypt - that is the only reason it is outside the ciphertext.
 *
 * The channel plaintext is then:
 *
 *   [u8 messageType][ payload ]
 */

export const MSG_HEADER = 1; // the inner container's 64-byte header
export const MSG_META = 2;   // the inner sealed metadata chunk
export const MSG_DATA = 3;   // one inner sealed data chunk
export const MSG_READY = 4;  // receiver has a destination and grants initial credit
export const MSG_CREDIT = 5; // receiver grants N more frames
export const MSG_DONE = 6;   // receiver confirms the whole file verified
export const MSG_ABORT = 7;  // either side gives up, with a reason

export type MessageType =
  | typeof MSG_HEADER | typeof MSG_META | typeof MSG_DATA
  | typeof MSG_READY | typeof MSG_CREDIT | typeof MSG_DONE | typeof MSG_ABORT;

export interface Message {
  type: MessageType;
  payload: Uint8Array;
}

export function encodeMessage(type: MessageType, payload: Uint8Array = new Uint8Array(0)): Uint8Array {
  const out = new Uint8Array(1 + payload.length);
  out[0] = type;
  out.set(payload, 1);
  return out;
}

export function decodeMessage(bytes: Uint8Array): Message {
  if (bytes.length < 1) throw new Error('Empty session message');
  return { type: bytes[0] as MessageType, payload: bytes.subarray(1) };
}

export function encodeCredit(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

export function decodeCredit(payload: Uint8Array): number {
  if (payload.length < 4) return 0;
  return new DataView(payload.buffer, payload.byteOffset, payload.byteLength).getUint32(0, false);
}

/** Prepend the authenticated-but-cleartext final flag. */
export function wrapFrame(sealed: Uint8Array, isFinal: boolean): Uint8Array {
  const out = new Uint8Array(1 + sealed.length);
  out[0] = isFinal ? 1 : 0;
  out.set(sealed, 1);
  return out;
}

export function unwrapFrame(frame: Uint8Array): { sealed: Uint8Array; isFinal: boolean } {
  if (frame.length < 1) throw new Error('Empty link frame');
  return { sealed: frame.subarray(1), isFinal: frame[0] === 1 };
}

/**
 * Live chunk size. Small enough that a frame clears every data-channel and
 * relay limit comfortably, large enough that per-chunk AEAD overhead stays
 * negligible (16 bytes on 64 KiB).
 */
export const LIVE_CHUNK_SIZE = 64 * 1024;

/** Frames the sender may have outstanding before it must wait for credit. */
export const CREDIT_WINDOW = 32;
/** Receiver tops the sender back up once this many frames have been consumed. */
export const CREDIT_REFILL_AT = 16;
