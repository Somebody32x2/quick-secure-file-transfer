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

  /**
   * Reserving an upload slot is unauthenticated - it has to be, since that call
   * is what mints the credential. So it is bounded two ways: a rate over time,
   * and a ceiling on how many reservations one address may hold un-committed.
   * The second is the one that matters; a reservation occupies a code from the
   * shared registry until it commits or is swept.
   */
  storeInitPerIp: int(process.env.STORE_INIT_PER_IP, 60),
  storeInitWindowMs: int(process.env.STORE_INIT_WINDOW_MS, 10 * 60_000),
  maxUncommittedPerIp: int(process.env.MAX_UNCOMMITTED_PER_IP, 10),

  /** Live relay: bytes in flight the server will pass through per room. */
  relayMaxFrameBytes: int(process.env.RELAY_MAX_FRAME_BYTES, 1024 * 1024),
  liveRoomIdleMs: int(process.env.LIVE_ROOM_IDLE_MS, 15 * 60_000),
  /** Rooms one address may hold open at once, and sockets it may open at all. */
  liveRoomsPerIp: int(process.env.LIVE_ROOMS_PER_IP, 20),
  maxSocketsPerIp: int(process.env.MAX_SOCKETS_PER_IP, 60),

  /**
   * How far to trust `X-Forwarded-For`.
   *
   * A number is a count of proxies between the internet and this process, and
   * the client address is read that many hops from the *right* of the chain -
   * the only part a client cannot forge, since each proxy appends the address it
   * actually saw. A comma-separated list of proxy addresses is also accepted.
   * Empty or "0" means the header is ignored entirely.
   *
   * Taking the leftmost value instead would let any client name its own address
   * and walk straight through every rate limit here.
   */
  trustProxy: trustProxySetting(process.env.TRUST_PROXY),
  isProduction: process.env.NODE_ENV === 'production',

  /**
   * Origins allowed to open a socket, comma separated. Empty means same-origin
   * only, worked out from the request's own Host header. Only enforced when an
   * Origin header is present: native clients and curl do not send one, and the
   * signalling channel carries nothing a browser's credentials would unlock.
   */
  allowedOrigins: (process.env.ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((value) => value.trim().replace(/\/+$/, ''))
    .filter(Boolean),

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

/**
 * "1" -> 1 hop, "2" -> 2 hops, "10.0.0.1,10.0.0.2" -> that proxy list,
 * blank/"0"/"false" -> do not read the header at all.
 *
 * "true" is accepted for compatibility and means one hop, which is what a single
 * reverse proxy in front of this process actually is. It deliberately does not
 * mean "believe whatever the header says".
 */
function trustProxySetting(raw) {
  const value = (raw ?? '').trim();
  if (!value || value === '0' || value.toLowerCase() === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  if (value.toLowerCase() === 'true') return 1;
  const list = value.split(',').map((entry) => entry.trim()).filter(Boolean);
  return list.length ? list : false;
}

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
