/**
 * Handing a session to the other device in one scan.
 *
 * The QR code carries a link back to this same deployment with the code and
 * passphrase in the fragment. The fragment is the right half of the URL for
 * this: browsers never put it in a request, so the passphrase does not reach
 * the server even though the link points at it. `Referrer-Policy: no-referrer`
 * covers the other leak, and the app strips the fragment out of the address bar
 * and session history the moment it has read it.
 *
 * The origin is the sender's own, which is exactly the one the receiver needs:
 * they have to reach the same server to collect the file, so a QR that sends
 * them anywhere else would be no use to them.
 */

import { BASE } from '../config.js';

const CODE_PARAM = 'c';
const PASS_PARAM = 'p';

export interface Handoff {
  code: string;
  passphrase: string;
}

/**
 * The URL a QR code encodes.
 *
 * @param origin defaults to this page's, and is a parameter so the URL can be
 *   built outside a browser.
 */
export function handoffUrl(code: string, passphrase: string, origin: string = location.origin): string {
  const fragment = `${CODE_PARAM}=${encodeURIComponent(code)}&${PASS_PARAM}=${encodeURIComponent(passphrase)}`;
  return `${origin}${BASE}#${fragment}`;
}

/** Read a handoff out of a URL fragment. Null if it is not one, or malformed. */
export function parseHandoff(hash: string): Handoff | null {
  const params = new URLSearchParams(hash.replace(/^#/, ''));
  const code = params.get(CODE_PARAM);
  const passphrase = params.get(PASS_PARAM);
  if (code === null || passphrase === null) return null;
  // Held to the same shape the code entry field enforces, so a mangled scan
  // fails here rather than as a confusing lookup error later.
  if (!/^\d{6}$/.test(code) || passphrase.length === 0) return null;
  return { code, passphrase };
}

/**
 * Take the handoff out of the current URL, clearing the fragment either way.
 *
 * Clearing is not tidiness: until it happens the passphrase is sitting in the
 * address bar, in the back/forward entry for this page, and in anything the
 * user might screenshot or screen-share. A fragment that carried our parameters
 * is removed even when it fails to parse, because a malformed one still has the
 * passphrase in it.
 */
export function takeHandoff(): Handoff | null {
  const hash = location.hash;
  if (!hash || (!hash.includes(`${CODE_PARAM}=`) && !hash.includes(`${PASS_PARAM}=`))) return null;

  try {
    history.replaceState(null, '', location.pathname + location.search);
  } catch {
    // Some embedded webviews refuse replaceState. Nothing else to do about the
    // address bar there, and the handoff itself still works.
  }
  return parseHandoff(hash);
}
