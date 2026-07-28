import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '..');

const int = (value, fallback) => {
  const n = Number.parseInt(value ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
};

const GIB = 1024 * 1024 * 1024;

export const config = {
  port: int(process.env.PORT, 8080),
  host: process.env.HOST ?? '0.0.0.0',
  root,
  publicDir: path.join(root, 'dist', 'public'),
  dataDir: process.env.DATA_DIR ?? path.join(root, 'data'),

  /** Product ceiling: 2 GB plaintext, plus room for container overhead. */
  maxFileBytes: int(process.env.MAX_FILE_BYTES, 2 * GIB + 64 * 1024 * 1024),
  /** Largest single upload part the server will accept into memory at once. */
  maxPartBytes: int(process.env.MAX_PART_BYTES, 8 * 1024 * 1024),
  /** Total bytes at rest before new uploads are refused. */
  storageQuotaBytes: int(process.env.STORAGE_QUOTA_BYTES, 20 * GIB),

  /** Hard cap on retention. Senders may choose less, never more. */
  maxTtlSeconds: int(process.env.MAX_TTL_SECONDS, 48 * 60 * 60),
  defaultTtlSeconds: int(process.env.DEFAULT_TTL_SECONDS, 24 * 60 * 60),
  /** Uploads that never commit are swept after this long. */
  incompleteUploadTtlSeconds: int(process.env.INCOMPLETE_UPLOAD_TTL_SECONDS, 60 * 60),
  sweepIntervalMs: int(process.env.SWEEP_INTERVAL_MS, 60_000),

  maxReadsLimit: int(process.env.MAX_READS_LIMIT, 100),

  /**
   * A 6-digit code is only 10^6 wide, so guessing is throttled hard. The code
   * gates access to ciphertext only - the passphrase still stands between an
   * attacker and the plaintext - but there is no reason to make enumeration
   * cheap.
   */
  codeAttemptsPerIp: int(process.env.CODE_ATTEMPTS_PER_IP, 20),
  codeAttemptWindowMs: int(process.env.CODE_ATTEMPT_WINDOW_MS, 10 * 60_000),
  codeMaxFailuresPerCode: int(process.env.CODE_MAX_FAILURES_PER_CODE, 10),

  /** Live relay: bytes in flight the server will pass through per room. */
  relayMaxFrameBytes: int(process.env.RELAY_MAX_FRAME_BYTES, 1024 * 1024),
  liveRoomIdleMs: int(process.env.LIVE_ROOM_IDLE_MS, 15 * 60_000),

  trustProxy: process.env.TRUST_PROXY === '1',
  isProduction: process.env.NODE_ENV === 'production',

  /**
   * Mount point, e.g. "/filetransfer". Must match the BASE_PATH the client was
   * built with. Empty means the origin root.
   */
  basePath: normalisePath(process.env.BASE_PATH),

  /**
   * Extra paths that redirect to the canonical mount point, comma separated.
   * These are redirects rather than second mounts on purpose: two live copies of
   * a PWA on one origin means two service worker scopes, two caches and two
   * install identities for the same app.
   */
  aliasPaths: (process.env.ALIAS_PATHS ?? '')
    .split(',')
    .map((value) => normalisePath(value))
    .filter(Boolean),
};

/** "/filetransfer/" or "filetransfer" -> "/filetransfer"; blank -> "". */
function normalisePath(value) {
  const trimmed = (value ?? '').trim().replace(/\/+$/, '');
  if (!trimmed || trimmed === '/') return '';
  return trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
}

export const paths = {
  blobs: path.join(config.dataDir, 'blobs'),
  meta: path.join(config.dataDir, 'meta'),
  temp: path.join(config.dataDir, 'tmp'),
};
