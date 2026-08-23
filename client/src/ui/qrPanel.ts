/**
 * The QR handoff panel.
 *
 * A code the other person types is fine; a code *and* a passphrase typed on a
 * phone keyboard is where a transfer gets abandoned. This puts both into one
 * symbol their camera can read.
 *
 * It is hidden until asked for, and torn out of the DOM again when hidden,
 * because unlike the six-digit code this is the whole secret: a passphrase on
 * screen is a passphrase in every shoulder, screenshot, and shared window in
 * the room. Showing it is a deliberate act with a warning attached.
 */

import { clear, el } from './dom.js';
import { encodeQr } from '../util/qr.js';
import { handoffUrl } from '../util/handoff.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * Blank margin around the symbol, in modules. The specification asks for four,
 * and scanners genuinely need it - a symbol that runs to the edge of a dark
 * panel often will not lock on.
 */
const QUIET_ZONE = 4;

/**
 * Render a QR symbol as SVG.
 *
 * SVG rather than a canvas or a data URI so it stays sharp at whatever size the
 * layout gives it, which on a phone screen is the difference between a scan
 * that takes a moment and one that does not happen.
 */
export function qrSvg(text: string, label: string): SVGSVGElement {
  const qr = encodeQr(text);
  const extent = qr.size + QUIET_ZONE * 2;

  // One path of unit squares. A rect element per module would be several
  // thousand nodes for a symbol this size.
  let path = '';
  for (let y = 0; y < qr.size; y++) {
    for (let x = 0; x < qr.size; x++) {
      if (qr.modules[y][x]) path += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h1v1h-1z`;
    }
  }

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${extent} ${extent}`);
  svg.setAttribute('class', 'qr-code');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', label);
  // Sub-pixel module edges are what break a scan on a low-resolution camera.
  svg.setAttribute('shape-rendering', 'crispEdges');

  const background = document.createElementNS(SVG_NS, 'rect');
  background.setAttribute('width', String(extent));
  background.setAttribute('height', String(extent));
  background.setAttribute('fill', '#ffffff');

  const modules = document.createElementNS(SVG_NS, 'path');
  modules.setAttribute('d', path);
  modules.setAttribute('fill', '#000000');

  svg.append(background, modules);
  return svg;
}

/**
 * The reveal button and the symbol it toggles.
 *
 * Colours are fixed rather than themed. Dark mode inverts everything else in
 * the app, and an inverted QR code is one that half the scanners in the world
 * refuse to read.
 */
export function qrHandoff(code: string, passphrase: string): HTMLElement {
  const slot = el('div');

  const hide = () => {
    clear(slot);
    toggle.textContent = 'Show QR code';
    toggle.setAttribute('aria-expanded', 'false');
  };

  const show = () => {
    try {
      slot.append(
        qrSvg(handoffUrl(code, passphrase), 'QR code containing the transfer code and passphrase'),
        el('p', {
          class: 'hint qr-warning',
          text: 'Contains the passphrase as well as the code. Let them scan it off your screen — do not send it as a picture.',
        }),
      );
      toggle.textContent = 'Hide QR code';
      toggle.setAttribute('aria-expanded', 'true');
    } catch {
      // Only reachable with a passphrase thousands of characters long, but a
      // dead button with no explanation is worse than saying so.
      slot.append(el('p', {
        class: 'hint',
        text: 'That passphrase is too long to fit in a QR code. Read the code and passphrase out instead.',
      }));
      toggle.disabled = true;
    }
  };

  const toggle = el('button', {
    type: 'button',
    class: 'button secondary',
    'aria-expanded': false,
    text: 'Show QR code',
    onclick: () => { if (slot.firstChild) hide(); else show(); },
  });

  return el('div', { class: 'qr-handoff' }, toggle, slot);
}
