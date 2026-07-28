import express from 'express';
import { config } from './config.js';
import * as store from './store.js';
import * as codes from './codes.js';
import { clientIp, httpError, isValidCode, RateLimiter } from './util.js';

/** Throttles code guessing. A 6-digit code is small; enumeration must not be cheap. */
const ipLimiter = new RateLimiter(config.codeAttemptsPerIp, config.codeAttemptWindowMs);
const codeFailures = new Map();

setInterval(() => {
  ipLimiter.sweep();
  const cutoff = Date.now() - config.codeAttemptWindowMs;
  for (const [code, entry] of codeFailures) {
    if (entry.last < cutoff) codeFailures.delete(code);
  }
}, 60_000).unref();

function guardCodeLookup(req, code) {
  const ip = clientIp(req);
  const { allowed, retryAfterMs } = ipLimiter.check(ip);
  if (!allowed) {
    throw httpError(429, 'Too many code attempts. Wait a few minutes and try again.', {
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
    });
  }
  const entry = codeFailures.get(code);
  if (entry && entry.count >= config.codeMaxFailuresPerCode) {
    throw httpError(429, 'This code has been guessed at too many times and is temporarily locked.');
  }
}

function noteFailure(code) {
  const entry = codeFailures.get(code) ?? { count: 0, last: 0 };
  entry.count += 1;
  entry.last = Date.now();
  codeFailures.set(code, entry);
}

/** A lookup that resolved to a real transfer was not a guess; refund it. */
function noteSuccess(req, code) {
  ipLimiter.pardon(clientIp(req));
  codeFailures.delete(code);
}

export function createRouter() {
  const router = express.Router();
  const json = express.json({ limit: '64kb' });
  const raw = express.raw({ type: '*/*', limit: config.maxPartBytes + 4096 });

  router.get('/health', (_req, res) => {
    res.json({ ok: true, ...store.stats() });
  });

  /** Limits the client needs to know before it starts sealing bytes. */
  router.get('/config', (_req, res) => {
    res.json({
      maxFileBytes: config.maxFileBytes,
      maxPartBytes: config.maxPartBytes,
      maxTtlSeconds: config.maxTtlSeconds,
      defaultTtlSeconds: config.defaultTtlSeconds,
      maxReadsLimit: config.maxReadsLimit,
      iceServers: iceServers(),
    });
  });

  /**
   * Tells the receiver which flow a code belongs to, so the UI can ask for a
   * code and a passphrase and nothing else. Rate limited like any other code
   * lookup - this endpoint would otherwise be the cheapest way to enumerate.
   */
  router.get('/resolve/:code', async (req, res) => {
    const { code } = req.params;
    if (!isValidCode(code)) throw httpError(400, 'Codes are six digits');
    guardCodeLookup(req, code);

    const entry = codes.resolve(code);
    if (!entry) {
      noteFailure(code);
      throw httpError(404, 'Nothing is waiting under that code. Check the digits, or ask the sender to start again.');
    }
    if (entry.kind === 'stored') {
      const record = store.peek(code);
      if (!record) {
        noteFailure(code);
        throw httpError(404, 'That transfer has expired or was already collected.');
      }
      noteSuccess(req, code);
      res.json({ kind: 'stored', ...store.describe(record) });
      return;
    }
    noteSuccess(req, code);
    res.json({ kind: 'live' });
  });

  // -- upload ---------------------------------------------------------------

  router.post('/store/init', json, async (req, res) => {
    const record = await store.createUpload({
      ttlSeconds: req.body?.ttlSeconds,
      maxReads: req.body?.maxReads,
      declaredSize: req.body?.declaredSize,
    });
    res.status(201).json({
      id: record.id,
      code: record.code,
      token: record.token,
      expiresAt: record.expiresAt,
      maxReads: record.maxReads,
      maxPartBytes: config.maxPartBytes,
    });
  });

  router.put('/store/:id/part', raw, async (req, res) => {
    const index = Number.parseInt(req.get('x-part-index') ?? '', 10);
    if (!Number.isInteger(index) || index < 0) throw httpError(400, 'Missing or invalid x-part-index');
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) throw httpError(400, 'Empty part body');

    const result = await store.appendPart(
      req.params.id, req.get('x-upload-token'), index, req.body,
    );
    res.json(result);
  });

  router.post('/store/:id/commit', json, async (req, res) => {
    const record = await store.commitUpload(req.params.id, req.get('x-upload-token'));
    res.json({
      code: record.code,
      expiresAt: record.expiresAt,
      maxReads: record.maxReads,
      size: record.size,
    });
  });

  router.post('/store/:id/revoke', json, async (req, res) => {
    await store.revoke(req.params.id, req.get('x-upload-token'));
    res.json({ ok: true });
  });

  // -- download -------------------------------------------------------------

  router.get('/store/:code/meta', async (req, res) => {
    const { code } = req.params;
    if (!isValidCode(code)) throw httpError(400, 'Codes are six digits');
    guardCodeLookup(req, code);

    const record = store.peek(code);
    if (!record) {
      noteFailure(code);
      throw httpError(404, 'No transfer with that code. It may have expired or already been collected.');
    }
    noteSuccess(req, code);
    res.json(store.describe(record));
  });

  router.get('/store/:code', async (req, res) => {
    const { code } = req.params;
    if (!isValidCode(code)) throw httpError(400, 'Codes are six digits');
    guardCodeLookup(req, code);

    const session = store.beginRead(code);
    if (!session) {
      noteFailure(code);
      throw httpError(404, 'No transfer with that code. It may have expired or already been collected.');
    }
    noteSuccess(req, code);

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(session.size));
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Reads-Remaining', String(Math.max(0, session.record.maxReads - session.record.reads - 1)));

    let bytesSent = 0;
    session.stream.on('data', (chunk) => { bytesSent += chunk.length; });

    const settle = (ok) => {
      // Only a complete delivery consumes a read. A dropped connection must not
      // burn a one-read transfer.
      session.finish(ok && bytesSent === session.size).catch(() => {});
    };

    session.stream.on('error', () => { settle(false); res.destroy(); });
    res.on('close', () => { settle(res.writableFinished); session.stream.destroy(); });
    session.stream.pipe(res);
  });

  return router;
}

function iceServers() {
  if (process.env.ICE_SERVERS) {
    try { return JSON.parse(process.env.ICE_SERVERS); } catch { /* fall through */ }
  }
  // Public STUN only. STUN reveals nothing but IP candidates, and there is no
  // TURN fallback by default: if a NAT blocks direct P2P we fall back to our own
  // encrypted relay rather than trusting a third-party TURN operator.
  return [{ urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478'] }];
}
