/**
 * Where the app is mounted.
 *
 * QSFT can be served from the root of a domain or from a subpath
 * (samuelshuster.com/filetransfer). Vite bakes the mount point in at build time
 * as `import.meta.env.BASE_URL`, and everything that builds a URL - API calls,
 * the Socket.IO endpoint, the service worker registration - goes through here
 * rather than hardcoding a leading slash.
 *
 * BASE_URL always has a trailing slash ("/" at the root, "/filetransfer/"
 * otherwise), so paths are appended without one.
 */

export const BASE: string = import.meta.env.BASE_URL || '/';

/** Absolute path to an API endpoint. `api('config')` -> "/filetransfer/api/config". */
export function api(path: string): string {
  return `${BASE}api/${path}`;
}

/** The Socket.IO endpoint this deployment listens on. */
export function socketPath(): string {
  return `${BASE}socket.io`;
}

/** Absolute path to a file in the public directory. */
export function asset(path: string): string {
  return `${BASE}${path}`;
}
