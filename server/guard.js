/**
 * One throttle for every way a 6-digit code can be guessed.
 *
 * There are two surfaces - `GET /api/resolve/:code` and the `live:join` socket
 * event - and they must share a single budget. Two limiters would simply hand an
 * attacker twice the attempts, and the socket path is the cheaper of the two to
 * drive, so it is the one that sets the pace.
 *
 * Refund semantics are unchanged: a lookup that found something real was not a
 * guess, so only misses accumulate. Collecting many genuine transfers in a row
 * must never throttle anyone.
 */

import { config } from './config.js';
import { RateLimiter, httpError } from './util.js';
import * as codes from './codes.js';

const ipLimiter = new RateLimiter(config.codeAttemptsPerIp, config.codeAttemptWindowMs);

/** @type {Map<string, {count: number, last: number}>} */
const codeFailures = new Map();

setInterval(() => {
  ipLimiter.sweep();
  const cutoff = Date.now() - config.codeAttemptWindowMs;
  for (const [code, entry] of codeFailures) {
    if (entry.last < cutoff) codeFailures.delete(code);
  }
}, 60_000).unref();

/**
 * @returns {{allowed: true} | {allowed: false, message: string, retryAfterSeconds?: number}}
 */
export function checkCodeLookup(ip, code) {
  const { allowed, retryAfterMs } = ipLimiter.check(ip);
  if (!allowed) {
    return {
      allowed: false,
      message: 'Too many code attempts. Wait a few minutes and try again.',
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    };
  }

  /**
   * The per-code lock only applies to codes nobody is using.
   *
   * It counts *misses*, and a miss means the code was not allocated - so left
   * unqualified it can only ever punish the transfer that is handed that code
   * later. An attacker sweeping the space would poison every code they missed
   * and lock out the real receivers who were subsequently given them. Skipping
   * the check for allocated codes keeps the speed bump on codes that lead
   * nowhere while making it impossible to lock a live transfer out of its own
   * code. The per-IP limiter above is what actually guards allocated codes.
   */
  const entry = codeFailures.get(code);
  if (entry && entry.count >= config.codeMaxFailuresPerCode && !codes.resolve(code)) {
    return {
      allowed: false,
      message: 'This code has been guessed at too many times and is temporarily locked.',
    };
  }
  return { allowed: true };
}

/** Express flavour: same check, thrown as an HTTP error. */
export function guardCodeLookup(ip, code) {
  const result = checkCodeLookup(ip, code);
  if (result.allowed) return;
  throw httpError(429, result.message, result.retryAfterSeconds
    ? { retryAfterSeconds: result.retryAfterSeconds }
    : {});
}

export function noteFailure(code) {
  const entry = codeFailures.get(code) ?? { count: 0, last: 0 };
  entry.count += 1;
  entry.last = Date.now();
  codeFailures.set(code, entry);
}

/** A lookup that resolved to a real transfer was not a guess; refund it. */
export function noteSuccess(ip, code) {
  ipLimiter.pardon(ip);
  codeFailures.delete(code);
}
