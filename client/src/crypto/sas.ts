/**
 * Short Authentication String.
 *
 * Both devices display the same six digits and four glyphs, derived from the
 * completed handshake transcript. If the two screens match, no machine in the
 * middle substituted its own keys - the check is independent of passphrase
 * strength, which is exactly the gap the passphrase-keyed MAC cannot close on
 * its own.
 *
 * Glyphs are included because comparing four pictures across a room is faster
 * and less error-prone than reading digits aloud, especially on a phone.
 */

import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { utf8 } from '../util/bytes.js';
import type { SessionKeys } from './kex.js';

/** 64 visually distinct, widely supported emoji. */
const GLYPHS = [
  '🍎', '🚗', '🌙', '🔑', '🎈', '🐟', '🌵', '⚓',
  '🎸', '🍄', '🦋', '🧊', '🔥', '🌈', '🍀', '🎩',
  '🐘', '🚀', '🎯', '🧲', '🕰️', '🪁', '🦉', '🌻',
  '🍩', '🧭', '🪑', '🎺', '🐍', '🏔️', '💎', '🪂',
  '🦀', '🌰', '🎲', '🪓', '🧦', '🍇', '🐻', '⛺',
  '🪐', '🧅', '🎻', '🦓', '🍋', '🛎️', '🪶', '🧱',
  '🐝', '🌊', '🎪', '🥁', '🦔', '🍒', '🚲', '🗝️',
  '🐙', '🌪️', '🧀', '🪄', '🦜', '🍿', '⚙️', '🌡️',
];

export interface ShortAuthString {
  digits: string;
  glyphs: string[];
}

/**
 * Derived from the session secret under a label distinct from every channel
 * key, so publishing the SAS on screen reveals nothing about the traffic keys.
 */
export function shortAuthString(session: SessionKeys): ShortAuthString {
  const material = hkdf(sha256, session.secret, session.transcript, utf8('qsft/v1/sas'), 8);

  // Six digits from the first 4 bytes.
  const dv = new DataView(material.buffer, material.byteOffset, material.byteLength);
  const digits = String(dv.getUint32(0, false) % 1_000_000).padStart(6, '0');

  // Four glyphs from the next 4 bytes, 6 bits of index each.
  const glyphs = [4, 5, 6, 7].map((i) => GLYPHS[material[i] & 0x3f]);

  return { digits, glyphs };
}
