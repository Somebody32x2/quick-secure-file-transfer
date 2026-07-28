import crypto from 'node:crypto';
import { config } from './config.js';

/** Uniform 6-digit code from a CSPRNG - no modulo bias. */
export function generateCode() {
  for (;;) {
    const n = crypto.randomBytes(4).readUInt32BE(0);
    // Largest multiple of 1e6 below 2^32; values above it are rejected.
    if (n < 4_294_000_000) return String(n % 1_000_000).padStart(6, '0');
  }
}

export function generateId() {
  return crypto.randomBytes(16).toString('hex');
}

export function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** Compare secrets without leaking length or position through timing. */
export function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

export function clientIp(req) {
  if (config.trustProxy) {
    const fwd = req.headers['x-forwarded-for'];
    if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  }
  return req.socket?.remoteAddress ?? 'unknown';
}

export function isValidCode(code) {
  return typeof code === 'string' && /^\d{6}$/.test(code);
}

/**
 * Sliding-window counter, in memory. Single-process only; behind multiple
 * instances this needs a shared store (see README).
 */
export class RateLimiter {
  #hits = new Map();

  constructor(limit, windowMs) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** @returns {{allowed: boolean, retryAfterMs: number}} */
  check(key) {
    const now = Date.now();
    const times = (this.#hits.get(key) ?? []).filter((t) => now - t < this.windowMs);
    if (times.length >= this.limit) {
      const retryAfterMs = this.windowMs - (now - times[0]);
      this.#hits.set(key, times);
      return { allowed: false, retryAfterMs };
    }
    times.push(now);
    this.#hits.set(key, times);
    return { allowed: true, retryAfterMs: 0 };
  }

  reset(key) {
    this.#hits.delete(key);
  }

  /**
   * Give back the most recent attempt.
   *
   * The point of this limiter is to make *enumeration* expensive, not to punish
   * someone collecting several files in a row. A lookup that found something
   * real is not a guess, so it is refunded and only failures accumulate.
   */
  pardon(key) {
    const times = this.#hits.get(key);
    if (!times?.length) return;
    times.pop();
    if (times.length === 0) this.#hits.delete(key);
  }

  /** Drop stale keys so the map cannot grow without bound. */
  sweep() {
    const now = Date.now();
    for (const [key, times] of this.#hits) {
      const live = times.filter((t) => now - t < this.windowMs);
      if (live.length === 0) this.#hits.delete(key);
      else this.#hits.set(key, live);
    }
  }
}

export function httpError(status, message, extra = {}) {
  const err = new Error(message);
  err.status = status;
  Object.assign(err, extra);
  return err;
}
