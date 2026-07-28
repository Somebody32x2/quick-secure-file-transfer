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
if (config.trustProxy) app.set('trust proxy', true);

/**
 * The app must run correctly on a plain-http LAN origin, so these headers are
 * the only hardening available - no HSTS, no secure cookies, no WebCrypto.
 * Everything security-critical happens in the client's own pure-JS crypto.
 */
app.use((_req, res, next) => {
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    // ws:/wss: for the relay; blob: so the receiver can hand a Blob to a download.
    "connect-src 'self' ws: wss: blob:",
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
  next();
});

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

const io = new SocketIOServer(server, {
  // One frame plus framing overhead. Caps what a client can push at the relay.
  maxHttpBufferSize: config.relayMaxFrameBytes + 64 * 1024,
  pingTimeout: 30_000,
  pingInterval: 20_000,
  cors: config.isProduction ? undefined : { origin: true, credentials: false },
});
attachLive(io);

const restored = await store.init();

const sweeper = setInterval(() => {
  store.sweep().catch((err) => console.error('[sweep]', err));
}, config.sweepIntervalMs);
sweeper.unref();

server.listen(config.port, config.host, () => {
  const s = store.stats();
  console.log(`QSFT server listening on http://${config.host}:${config.port}`);
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
