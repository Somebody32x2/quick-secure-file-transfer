/**
 * One namespace for every 6-digit code.
 *
 * Live sessions and stored blobs both hand out codes. Allocating them from
 * separate maps would let the same code mean two things at once, and would
 * leave the receiver guessing which flow a typed code belongs to. A single
 * registry removes both problems: codes are unique across the server, and one
 * lookup tells the client which path to take.
 */

import { generateCode } from './util.js';

/** @type {Map<string, {kind: 'live'|'stored', ref: string}>} */
const registry = new Map();

/**
 * @param {'live'|'stored'} kind
 * @param {string} ref  room code owner or blob id
 * @returns {string|null} the allocated code, or null if the space is saturated
 */
export function allocate(kind, ref) {
  for (let attempt = 0; attempt < 500; attempt++) {
    const code = generateCode();
    if (registry.has(code)) continue;
    registry.set(code, { kind, ref });
    return code;
  }
  return null;
}

/** Re-register a code loaded from disk at boot. */
export function reserve(code, kind, ref) {
  if (registry.has(code)) return false;
  registry.set(code, { kind, ref });
  return true;
}

export function resolve(code) {
  return registry.get(code) ?? null;
}

export function release(code) {
  registry.delete(code);
}

export function size() {
  return registry.size;
}
