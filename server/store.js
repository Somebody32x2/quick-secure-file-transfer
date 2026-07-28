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

async function writeMeta(record) {
  const { reading, ...persisted } = record;
  const tmp = path.join(paths.temp, `${record.id}.json.tmp`);
  await fsp.writeFile(tmp, JSON.stringify(persisted));
  await fsp.rename(tmp, metaPath(record.id));
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

export async function createUpload({ ttlSeconds, maxReads, declaredSize }) {
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

  const id = generateId();
  const record = {
    id,
    code: allocateCode(id),
    token: generateToken(),
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

  await fsp.writeFile(blobPath(record.id), '');
  await writeMeta(record);
  byId.set(record.id, record);
  byCode.set(record.code, record.id);
  return record;
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
 */
export async function appendPart(id, token, index, buffer) {
  const record = authorised(id, token);
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
