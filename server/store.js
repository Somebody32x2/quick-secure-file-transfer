/**
 * Store-and-forward blob storage.
 *
 * The server is deliberately ignorant here. It appends opaque bytes, hands them
 * back to whoever presents the right code, and deletes them on a deadline. It
 * has no key, no passphrase, and no way to interpret a single byte it holds.
 *
 * Retention is enforced two ways, and whichever fires first wins:
 *   - a wall-clock expiry, capped at 48h and settable lower by the sender
 *   - a read budget, down to a single read ("burn after reading")
 *
 * State lives in memory and is mirrored to a JSON sidecar per blob so a restart
 * does not orphan files. This is single-process by design; see the README for
 * what changes if you run more than one instance.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { config, paths } from './config.js';
import { generateId, generateToken, httpError, safeEqual } from './util.js';
import * as codes from './codes.js';

/** @type {Map<string, Record>} id -> record */
const byId = new Map();
/** @type {Map<string, string>} code -> id */
const byCode = new Map();
/** @type {Map<string, number>} ip -> reservations made but not yet committed */
const uncommittedByIp = new Map();

let bytesOnDisk = 0;

/**
 * @typedef {object} Record
 * @property {string} id
 * @property {string} code
 * @property {string} token       sender's capability to append/commit/revoke
 * @property {number} createdAt
 * @property {number} expiresAt
 * @property {number} maxReads
 * @property {number} reads
 * @property {number} size        bytes written so far
 * @property {number} nextIndex   next expected part index
 * @property {boolean} committed
 * @property {boolean} reading    single-reader lock
 * @property {boolean} deleted
 */

const blobPath = (id) => path.join(paths.blobs, `${id}.bin`);
const metaPath = (id) => path.join(paths.meta, `${id}.json`);

/**
 * The temp name must be unique per *write*, not per record.
 *
 * Two writeMeta calls can overlap on one record with no misbehaving client at
 * all - `beginRead().finish()` fires from a connection-close event and can land
 * on top of an append. Sharing one temp path means the first rename consumes the
 * file and the second gets ENOENT, which surfaces as an uncaught 500. A unique
 * name is also what makes the rename genuinely atomic.
 */
async function writeMeta(record) {
  // `ownerIp` is deliberately not persisted. It exists only to bound concurrent
  // reservations in this process's memory, and writing the uploader's address
  // next to their ciphertext would be exactly the record this app exists to
  // avoid keeping. Restarts therefore forget the association, which is fine:
  // the reservations it bounded are swept within the hour anyway.
  const {
    reading, appendLock, ownerIp, uncommittedCleared, ...persisted
  } = record;
  const tmp = path.join(paths.temp, `${record.id}.${crypto.randomUUID()}.tmp`);
  try {
    await fsp.writeFile(tmp, JSON.stringify(persisted));
    await fsp.rename(tmp, metaPath(record.id));
  } catch (err) {
    await fsp.rm(tmp, { force: true }).catch(() => {});
    throw err;
  }
}

export async function init() {
  for (const dir of [paths.blobs, paths.meta, paths.temp]) {
    await fsp.mkdir(dir, { recursive: true });
  }
  // Clear any half-written temp files from a previous run.
  for (const name of await fsp.readdir(paths.temp)) {
    await fsp.rm(path.join(paths.temp, name), { force: true });
  }

  let restored = 0;
  for (const name of await fsp.readdir(paths.meta)) {
    if (!name.endsWith('.json')) continue;
    try {
      const record = JSON.parse(await fsp.readFile(path.join(paths.meta, name), 'utf8'));
      record.reading = false;
      record.ownerIp = 'restored';
      const stat = await fsp.stat(blobPath(record.id)).catch(() => null);
      if (!stat) { await destroy(record, 'missing blob'); continue; }
      record.size = stat.size;
      if (isExpired(record)) { await destroy(record, 'expired at boot'); continue; }
      if (!codes.reserve(record.code, 'stored', record.id)) {
        // Two sidecars claim the same code; neither can be served unambiguously.
        await destroy(record, 'code collision at boot');
        continue;
      }
      byId.set(record.id, record);
      byCode.set(record.code, record.id);
      bytesOnDisk += record.size;
      restored++;
    } catch {
      await fsp.rm(path.join(paths.meta, name), { force: true });
    }
  }
  return { restored, bytesOnDisk };
}

function isExpired(record) {
  if (record.deleted) return true;
  if (Date.now() >= record.expiresAt) return true;
  if (record.committed && record.reads >= record.maxReads) return true;
  if (!record.committed && Date.now() - record.createdAt > config.incompleteUploadTtlSeconds * 1000) {
    return true;
  }
  return false;
}

async function destroy(record, _reason) {
  clearUncommitted(record);
  record.deleted = true;
  byId.delete(record.id);
  if (byCode.get(record.code) === record.id) {
    byCode.delete(record.code);
    codes.release(record.code);
  }
  bytesOnDisk = Math.max(0, bytesOnDisk - (record.size ?? 0));
  await fsp.rm(blobPath(record.id), { force: true }).catch(() => {});
  await fsp.rm(metaPath(record.id), { force: true }).catch(() => {});
}

function allocateCode(id) {
  const code = codes.allocate('stored', id);
  if (!code) throw httpError(503, 'Could not allocate a free code; try again shortly');
  return code;
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

export async function createUpload({ ttlSeconds, maxReads, declaredSize, ownerIp = 'unknown' }) {
  const ttl = Math.min(
    Math.max(Number(ttlSeconds) || config.defaultTtlSeconds, 60),
    config.maxTtlSeconds,
  );
  const reads = Math.min(Math.max(Number(maxReads) || 1, 1), config.maxReadsLimit);
  const size = Number(declaredSize) || 0;

  if (size > config.maxFileBytes) {
    throw httpError(413, 'That file exceeds the 2 GB limit');
  }
  if (bytesOnDisk + size > config.storageQuotaBytes) {
    throw httpError(507, 'Server storage is full; try a live transfer instead');
  }
  /**
   * A reservation costs the caller nothing and costs the server a code from the
   * shared registry plus two files, held until it commits or is swept an hour
   * later. `declaredSize: 0` skips the quota check above entirely, so without
   * this ceiling the whole 10^6 code space can be held by one unauthenticated
   * caller at a few hundred requests a second - denying every live session and
   * every stored upload at once.
   */
  if ((uncommittedByIp.get(ownerIp) ?? 0) >= config.maxUncommittedPerIp) {
    throw httpError(429, 'Too many uploads in progress from this device. Finish or cancel one first.');
  }

  const id = generateId();
  const record = {
    id,
    code: allocateCode(id),
    token: generateToken(),
    ownerIp,
    createdAt: Date.now(),
    expiresAt: Date.now() + ttl * 1000,
    maxReads: reads,
    reads: 0,
    size: 0,
    nextIndex: 0,
    committed: false,
    reading: false,
    deleted: false,
  };

  try {
    await fsp.writeFile(blobPath(record.id), '');
    await writeMeta(record);
  } catch (err) {
    // Do not leak the code if the record never made it to disk.
    codes.release(record.code);
    throw err;
  }
  byId.set(record.id, record);
  byCode.set(record.code, record.id);
  uncommittedByIp.set(ownerIp, (uncommittedByIp.get(ownerIp) ?? 0) + 1);
  return record;
}

/** Release an in-progress reservation's slot exactly once. */
function clearUncommitted(record) {
  if (record.uncommittedCleared || record.committed) return;
  record.uncommittedCleared = true;
  const held = uncommittedByIp.get(record.ownerIp);
  if (!held) return;
  if (held <= 1) uncommittedByIp.delete(record.ownerIp);
  else uncommittedByIp.set(record.ownerIp, held - 1);
}

/**
 * Resolve and authorise an upload without touching its body. Lets the HTTP layer
 * reject an unauthenticated request *before* it agrees to buffer megabytes for
 * it.
 */
export function assertUploadAuth(id, token) {
  return authorised(id, token);
}

function authorised(id, token) {
  const record = byId.get(id);
  if (!record || record.deleted) throw httpError(404, 'Upload not found or already expired');
  if (!safeEqual(record.token, token)) throw httpError(403, 'Invalid upload token');
  return record;
}

/**
 * Append one part. Parts must arrive in order; re-sending the part just
 * acknowledged is treated as a no-op so a dropped response can be retried
 * safely without duplicating bytes.
 *
 * Serialised per record. The index check and the append that acts on it have to
 * be one indivisible step: validating synchronously and *then* awaiting the
 * write lets two requests carrying the same index both pass the check before
 * either advances `nextIndex`, and both then append. The blob silently gains a
 * duplicate copy of that part, and the receiver meets it much later as an
 * unexplained AEAD failure. Any client that retries a slow PUT without waiting
 * for the first response triggers it.
 */
export async function appendPart(id, token, index, buffer) {
  // Authorise before queueing so a bad token is still rejected immediately
  // rather than waiting behind someone else's upload.
  const record = authorised(id, token);
  const previous = record.appendLock ?? Promise.resolve();
  const mine = previous
    .catch(() => {})
    .then(() => appendPartLocked(record, index, buffer));

  // Keep the chain alive past a rejection so one failed part cannot wedge the
  // upload, and never leave an unhandled rejection behind.
  record.appendLock = mine.catch(() => {});
  return mine;
}

async function appendPartLocked(record, index, buffer) {
  // Re-checked inside the lock: the record may have been revoked or committed
  // while this call was queued.
  if (record.deleted) throw httpError(404, 'Upload not found or already expired');
  if (record.committed) throw httpError(409, 'Upload already committed');

  if (index === record.nextIndex - 1) {
    return { size: record.size, nextIndex: record.nextIndex, duplicate: true };
  }
  if (index !== record.nextIndex) {
    throw httpError(409, `Out-of-order part: expected ${record.nextIndex}, got ${index}`);
  }
  if (record.size + buffer.length > config.maxFileBytes) {
    await destroy(record, 'oversize');
    throw httpError(413, 'Upload exceeds the maximum size');
  }
  if (bytesOnDisk + buffer.length > config.storageQuotaBytes) {
    await destroy(record, 'quota');
    throw httpError(507, 'Server storage is full');
  }

  await fsp.appendFile(blobPath(record.id), buffer);
  record.size += buffer.length;
  record.nextIndex = index + 1;
  bytesOnDisk += buffer.length;
  await writeMeta(record);
  return { size: record.size, nextIndex: record.nextIndex, duplicate: false };
}

export async function commitUpload(id, token) {
  const record = authorised(id, token);
  if (record.size === 0) throw httpError(400, 'Refusing to commit an empty upload');
  // Let any queued append land first, so a commit racing the last part cannot
  // freeze a size the blob has not reached yet.
  await (record.appendLock ?? Promise.resolve());
  if (record.deleted) throw httpError(404, 'Upload not found or already expired');
  clearUncommitted(record);
  record.committed = true;
  await writeMeta(record);
  return record;
}

export async function revoke(id, token) {
  const record = authorised(id, token);
  await destroy(record, 'revoked by sender');
}

// ---------------------------------------------------------------------------
// Download
// ---------------------------------------------------------------------------

export function peek(code) {
  const id = byCode.get(code);
  if (!id) return null;
  const record = byId.get(id);
  if (!record || !record.committed || isExpired(record)) return null;
  return record;
}

/**
 * Begin a download. Only one reader at a time per blob - the requirement is
 * "one client at a time", and it also makes the read-budget decrement safe
 * without a real transaction.
 *
 * The caller must invoke `finish(success)` exactly once. The read is only
 * counted when the whole blob was delivered, so a dropped connection does not
 * silently consume someone's single-read transfer.
 */
export function beginRead(code) {
  const record = peek(code);
  if (!record) return null;
  if (record.reading) throw httpError(409, 'Someone else is downloading this right now; try again in a moment');

  record.reading = true;
  let settled = false;

  return {
    record,
    stream: fs.createReadStream(blobPath(record.id)),
    size: record.size,
    async finish(success) {
      if (settled) return;
      settled = true;
      record.reading = false;
      if (!success) return;
      record.reads += 1;
      if (record.reads >= record.maxReads) {
        await destroy(record, 'read budget exhausted');
      } else {
        await writeMeta(record).catch(() => {});
      }
    },
  };
}

export function describe(record) {
  return {
    size: record.size,
    expiresAt: record.expiresAt,
    readsRemaining: Math.max(0, record.maxReads - record.reads),
    maxReads: record.maxReads,
  };
}

// ---------------------------------------------------------------------------
// Sweeper
// ---------------------------------------------------------------------------

export async function sweep() {
  let removed = 0;
  for (const record of [...byId.values()]) {
    // Never yank a blob out from under an in-flight reader.
    if (record.reading) continue;
    if (isExpired(record)) { await destroy(record, 'swept'); removed++; }
  }
  return removed;
}

export function stats() {
  return { items: byId.size, bytesOnDisk, quotaBytes: config.storageQuotaBytes };
}
