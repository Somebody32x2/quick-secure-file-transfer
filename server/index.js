import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { Server as SocketIOServer } from 'socket.io';

import { config } from './config.js';
import { createRouter } from './routes.js';
import { attachLive, liveStats } from './live.js';
import * as store from './store.js';

const app = express();
app.disable('x-powered-by');
// Numeric hop count or proxy list - never bare `true`, which would take the
// forgeable leftmost X-Forwarded-For value. See config.trustProxy.
if (config.trustProxy) app.set('trust proxy', config.trustProxy);

/**
 * The app must run correctly on a plain-http LAN origin, so these headers are
 * most of the hardening available - no secure cookies, no WebCrypto. Everything
 * security-critical happens in the client's own pure-JS crypto.
 */
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    // 'self' already covers same-origin ws:/wss: in every browser we target.
    // Bare `ws:`/`wss:` scheme sources would match *any* host and leave the
    // policy with no exfiltration ceiling at all. blob: so the receiver can hand
    // a Blob to a download.
    "connect-src 'self' blob:",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; '));
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  // Only where it cannot break the plain-http LAN case: a request that already
  // arrived over TLS has nothing to lose by refusing to be downgraded.
  if (req.secure) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

/**
 * Alias paths redirect to the canonical mount point.
 *
 * Deliberately a redirect rather than a second live mount: serving the same PWA
 * at two paths on one origin would give it two service worker scopes, two
 * caches and two install identities.
 */
for (const alias of config.aliasPaths) {
  const pattern = new RegExp(`^${alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(/.*)?$`);
  app.get(pattern, (req, res) => {
    // Every leading slash, not just one. Stripping a single slash off
    // "//evil.example" leaves "/evil.example", which with an empty basePath
    // reassembles into the protocol-relative "//evil.example" - an off-origin
    // redirect out of a path that is supposed to land on this app.
    const rest = (req.params[0] ?? '').replace(/^\/+/, '');
    res.redirect(301, `${config.basePath}/${rest}`);
  });
}

app.use('/api', createRouter());

if (fs.existsSync(config.publicDir)) {
  app.use(express.static(config.publicDir, {
    index: 'index.html',
    maxAge: config.isProduction ? '1h' : 0,
    setHeaders(res, filePath) {
      // Hashed asset filenames are safe to cache hard; index.html never is.
      if (/\/assets\//.test(filePath)) {
        res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      } else {
        res.setHeader('Cache-Control', 'no-cache');
      }
      // A cached service worker would pin an old version indefinitely, so it
      // must always be revalidated, and it must be scoped to the whole origin.
      if (filePath.endsWith('sw.js')) {
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Service-Worker-Allowed', '/');
      }
    },
  }));
  app.get(/^(?!\/api\/).*/, (_req, res) => {
    res.sendFile(path.join(config.publicDir, 'index.html'));
  });
} else {
  app.get('/', (_req, res) => {
    res.status(503).type('text/plain').send(
      'Client bundle not built yet.\n\n'
      + 'Development:  npm run dev   (Vite on :5173 proxies here)\n'
      + 'Production:   npm run build && npm start\n',
    );
  });
}

// Express 5 forwards rejected async handlers here.
app.use((err, _req, res, _next) => {
  const status = err.status ?? 500;
  if (status >= 500) console.error('[error]', err);
  res.status(status).json({
    error: status >= 500 ? 'Internal server error' : err.message,
    ...(err.retryAfterSeconds ? { retryAfterSeconds: err.retryAfterSeconds } : {}),
  });
});

const server = http.createServer(app);

/**
 * Refuse sockets opened by another origin's page.
 *
 * Socket.IO's `cors` option only governs the polling transport - WebSocket
 * upgrades are not subject to CORS, so without this check any web page could
 * drive this signalling channel from every one of its visitors' browsers. That
 * turns code guessing into a distributed attack with no infrastructure.
 *
 * A missing Origin header is allowed through: non-browser clients do not send
 * one, and there is nothing here that a browser's ambient credentials unlock -
 * the protection needed is against *other pages*, which always send it.
 */
function originAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  if (config.allowedOrigins.length) {
    return config.allowedOrigins.includes(origin.replace(/\/+$/, ''));
  }
  // Same-origin by default, judged against the host we were actually reached on.
  const host = req.headers.host;
  if (!host) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

let refusedOrigins = 0;

const io = new SocketIOServer(server, {
  // One frame plus framing overhead. Caps what a client can push at the relay.
  maxHttpBufferSize: config.relayMaxFrameBytes + 64 * 1024,
  pingTimeout: 30_000,
  pingInterval: 20_000,
  // No `cors` entry: allowRequest below runs for the handshake of *both*
  // transports, so cross-origin sockets are refused outright rather than merely
  // being denied permission to read the reply.
  allowRequest(req, callback) {
    if (originAllowed(req)) return callback(null, true);
    // Loud, because the usual cause is a proxy rewriting Host rather than an
    // attack, and the symptom otherwise is "live transfers just do not work".
    if (refusedOrigins++ < 20) {
      console.warn(
        `[socket] refused origin ${req.headers.origin} (host ${req.headers.host}). `
        + 'If this is your own deployment, set ALLOWED_ORIGINS.',
      );
    }
    return callback('origin not allowed', false);
  },
});
attachLive(io);

/**
 * Serve correctly whether or not the reverse proxy strips the path prefix.
 *
 * Coolify/Traefik path routing may forward "/filetransfer/api/x" intact or
 * strip it to "/api/x", and which one you get depends on the middleware
 * configuration. Rather than betting on it, the prefix is removed here - before
 * Express or Socket.IO see the request - so everything downstream is mounted at
 * the root either way. If the proxy already stripped it, this is a no-op.
 *
 * Registered with prependListener so it runs ahead of both handlers, and it
 * covers 'upgrade' as well so WebSocket connections get the same treatment.
 */
if (config.basePath) {
  const stripPrefix = (req) => {
    if (!req.url) return;
    if (req.url === config.basePath) req.url = '/';
    else if (req.url.startsWith(`${config.basePath}/`)) req.url = req.url.slice(config.basePath.length);
    else if (req.url.startsWith(`${config.basePath}?`)) req.url = `/${req.url.slice(config.basePath.length)}`;
  };
  server.prependListener('request', stripPrefix);
  server.prependListener('upgrade', stripPrefix);
}

const restored = await store.init();

const sweeper = setInterval(() => {
  store.sweep().catch((err) => console.error('[sweep]', err));
}, config.sweepIntervalMs);
sweeper.unref();

server.listen(config.port, config.host, () => {
  const s = store.stats();
  console.log(`QSFT server listening on http://${config.host}:${config.port}`);
  console.log(`  mounted at    ${config.basePath || '/'}`);
  if (config.aliasPaths.length) console.log(`  redirects     ${config.aliasPaths.join(', ')} -> ${config.basePath || '/'}`);
  console.log(`  data dir      ${config.dataDir}`);
  console.log(`  restored      ${restored.restored} stored transfer(s), ${s.bytesOnDisk} bytes`);
  console.log(`  max retention ${config.maxTtlSeconds / 3600}h`);
  if (!fs.existsSync(config.publicDir)) console.log('  client bundle NOT built - run `npm run build`');
});

const shutdown = (signal) => {
  console.log(`\n${signal} received, shutting down`);
  clearInterval(sweeper);
  io.close();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 5000).unref();
};
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

export { app, server, io, liveStats };
