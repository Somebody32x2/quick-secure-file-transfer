import express from 'express';
import { config } from './config.js';
import * as store from './store.js';
import * as codes from './codes.js';
import { clientIp, httpError, isValidCode, RateLimiter } from './util.js';
import { guardCodeLookup, noteFailure, noteSuccess } from './guard.js';

/** Bounds how fast one address can mint upload reservations. */
const initLimiter = new RateLimiter(config.storeInitPerIp, config.storeInitWindowMs);
setInterval(() => initLimiter.sweep(), 60_000).unref();

/**
 * Loopback only - the container healthcheck, not the internet.
 *
 * Judged on the *resolved* client address, not the socket peer. A reverse proxy
 * on the same host - nginx or Caddy in front of `127.0.0.1:8080`, which is the
 * ordinary way to deploy this - makes the socket peer loopback for every request
 * that arrives, including ones from the internet. Reading the peer directly
 * therefore handed the detailed readout to everybody on exactly the deployments
 * it was meant to protect.
 *
 * `clientIp` counts proxy hops from the right, so a client cannot reach this by
 * claiming `X-Forwarded-For: 127.0.0.1`: the trusted proxy appends the address
 * it actually saw, and that is the one read. With no proxy configured this is
 * the socket peer, unchanged.
 */
function isLocal(req) {
  const addr = clientIp(req);
  return addr === '127.0.0.1' || addr === '::1' || addr === '::ffff:127.0.0.1';
}

export function createRouter() {
  const router = express.Router();
  const json = express.json({ limit: '64kb' });
  const raw = express.raw({ type: '*/*', limit: config.maxPartBytes + 4096 });

  /**
   * Liveness only from outside. The item count and bytes-on-disk are a public
   * readout of how much traffic a privacy tool is carrying, which is nobody
   * else's business; the Docker healthcheck reaches this over loopback and
   * still gets the detail.
   */
  router.get('/health', (req, res) => {
    res.json(isLocal(req) ? { ok: true, ...store.stats() } : { ok: true });
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
    const ip = clientIp(req);
    guardCodeLookup(ip, code);

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
      noteSuccess(ip, code);
      res.json({ kind: 'stored', ...store.describe(record) });
      return;
    }
    noteSuccess(ip, code);
    res.json({ kind: 'live' });
  });

  // -- upload ---------------------------------------------------------------

  router.post('/store/init', json, async (req, res) => {
    const ip = clientIp(req);
    const { allowed, retryAfterMs } = initLimiter.check(ip);
    if (!allowed) {
      throw httpError(429, 'Too many uploads started from this device. Wait a few minutes.', {
        retryAfterSeconds: Math.ceil(retryAfterMs / 1000),
      });
    }
    const record = await store.createUpload({
      ttlSeconds: req.body?.ttlSeconds,
      maxReads: req.body?.maxReads,
      declaredSize: req.body?.declaredSize,
      ownerIp: ip,
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

  /**
   * Authorise before agreeing to read a body.
   *
   * `express.raw` will happily buffer the full 8 MiB into memory and only then
   * hand it to a handler that rejects it for a bad token. That makes an
   * unauthenticated request an 8 MiB memory allocation, and nothing upstream
   * caps how many of those may be in flight. Checking the token first turns the
   * same request into a 403 on the headers alone.
   */
  const authoriseUpload = (req, _res, next) => {
    const index = Number.parseInt(req.get('x-part-index') ?? '', 10);
    if (!Number.isInteger(index) || index < 0) {
      return next(httpError(400, 'Missing or invalid x-part-index'));
    }
    try {
      store.assertUploadAuth(req.params.id, req.get('x-upload-token'));
    } catch (err) {
      return next(err);
    }
    req.partIndex = index;
    return next();
  };

  router.put('/store/:id/part', authoriseUpload, raw, async (req, res) => {
    if (!Buffer.isBuffer(req.body) || req.body.length === 0) throw httpError(400, 'Empty part body');

    const result = await store.appendPart(
      req.params.id, req.get('x-upload-token'), req.partIndex, req.body,
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
    const ip = clientIp(req);
    guardCodeLookup(ip, code);

    const record = store.peek(code);
    if (!record) {
      noteFailure(code);
      throw httpError(404, 'No transfer with that code. It may have expired or already been collected.');
    }
    noteSuccess(ip, code);
    res.json(store.describe(record));
  });

  router.get('/store/:code', async (req, res) => {
    const { code } = req.params;
    if (!isValidCode(code)) throw httpError(400, 'Codes are six digits');
    const ip = clientIp(req);
    guardCodeLookup(ip, code);

    /**
     * A code that is real but busy is not a guess.
     *
     * `beginRead` throws 409 when another reader holds the blob, and that threw
     * straight past the refund below - so two people collecting a multi-read
     * transfer, or one person retrying after a dropped connection, spent the
     * guess budget on a code they demonstrably already had. Twenty of those and
     * a legitimate receiver is locked out of their own transfer.
     */
    let session;
    try {
      session = store.beginRead(code);
    } catch (err) {
      if (err.status === 409) noteSuccess(ip, code);
      throw err;
    }
    if (!session) {
      noteFailure(code);
      throw httpError(404, 'No transfer with that code. It may have expired or already been collected.');
    }
    noteSuccess(ip, code);

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
