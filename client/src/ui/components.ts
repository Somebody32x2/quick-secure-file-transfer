/** Reusable panel modules. */

import { el } from './dom.js';
import { caps, describeEnvironment } from '../crypto/env.js';
import { estimateStrength, generatePassphrase } from '../util/passphrase.js';
import { formatBytes, formatDuration } from '../util/bytes.js';
import {
  applyUpdate, canInstall, hasUpdate, isIosSafari, isStandalone, promptInstall,
  serviceWorkerSupported,
} from '../pwa.js';
import type { ShortAuthString } from '../crypto/sas.js';

const SEGMENTS = 28;

/**
 * The carrier meter. A segmented bargraph rather than a smooth bar: this is a
 * transmission instrument, and discrete segments read as signal strength at a
 * glance on a phone held at arm's length. Doubles as the indeterminate
 * indicator during handshake, where a sweep runs across the segments.
 */
export class CarrierMeter {
  readonly root: HTMLElement;
  private segments: HTMLElement[] = [];
  private sweepTimer: number | null = null;
  private sweepPosition = 0;

  constructor() {
    this.root = el('div', {
      class: 'meter',
      role: 'progressbar',
      'aria-valuemin': 0,
      'aria-valuemax': 100,
      'aria-valuenow': 0,
    });
    for (let i = 0; i < SEGMENTS; i++) {
      const segment = el('i');
      this.segments.push(segment);
      this.root.append(segment);
    }
  }

  /** @param fraction 0..1 */
  setProgress(fraction: number): void {
    this.stopSweep();
    this.root.classList.remove('indeterminate', 'error');
    const clamped = Math.max(0, Math.min(1, fraction));
    const lit = Math.round(clamped * SEGMENTS);
    this.segments.forEach((segment, i) => {
      segment.classList.toggle('on', i < lit);
      segment.classList.toggle('tip', i === lit - 1 && lit < SEGMENTS);
    });
    this.root.setAttribute('aria-valuenow', String(Math.round(clamped * 100)));
  }

  /** Running sweep for phases with no measurable progress (handshake, lookup). */
  startSweep(): void {
    if (this.sweepTimer !== null) return;
    this.root.classList.add('indeterminate');
    this.root.classList.remove('error');
    this.root.removeAttribute('aria-valuenow');
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

    const tick = () => {
      this.sweepPosition = (this.sweepPosition + 1) % (SEGMENTS + 6);
      this.segments.forEach((segment, i) => {
        const distance = this.sweepPosition - i;
        segment.classList.toggle('on', distance >= 0 && distance < 4);
        segment.classList.remove('tip');
      });
    };
    if (reduced) {
      // Static half-lit bar rather than motion.
      this.segments.forEach((s, i) => s.classList.toggle('on', i % 2 === 0));
      this.sweepTimer = -1;
      return;
    }
    this.sweepTimer = window.setInterval(tick, 55);
  }

  stopSweep(): void {
    if (this.sweepTimer !== null && this.sweepTimer !== -1) window.clearInterval(this.sweepTimer);
    this.sweepTimer = null;
    this.root.classList.remove('indeterminate');
  }

  setError(): void {
    this.stopSweep();
    this.root.classList.add('error');
    this.segments.forEach((s) => { s.classList.add('on'); s.classList.remove('tip'); });
  }

  destroy(): void { this.stopSweep(); }
}

export function stateBadge(text: string, kind: 'idle' | 'working' | 'ok' | 'error' = 'working'): HTMLElement {
  return el('span', { class: `state ${kind === 'ok' ? '' : kind}`.trim(), text });
}

export function readout(...items: (HTMLElement | string)[]): HTMLElement {
  return el('div', { class: 'readout' }, ...items);
}

export function stat(label: string, value: string): HTMLElement {
  return el('span', {}, `${label} `, el('b', { text: value }));
}

export function progressReadout(bytes: number, total: number, rate: number, eta: number): HTMLElement {
  return readout(
    stat('', `${formatBytes(bytes)} of ${formatBytes(total)}`),
    stat('', `${formatBytes(rate)}/s`),
    stat('left', formatDuration(eta)),
  );
}

/** The six-digit session code, sized to be readable across a room. */
export function codeWell(code: string, caption: string): HTMLElement {
  return el('div', { class: 'code-well' },
    el('p', { class: 'eyebrow', text: 'Code' }),
    el('div', { class: 'code-digits mono', text: code }),
    el('p', { class: 'hint', text: caption }),
  );
}

/**
 * Short authentication string. This is the only check that survives a
 * passphrase an attacker can guess, so it is presented as an instruction to
 * act on rather than as a decorative badge.
 */
export function verifyPanel(sas: ShortAuthString): HTMLElement {
  return el('div', { class: 'verify' },
    el('p', { class: 'eyebrow', text: 'Check these match on both screens' }),
    el('div', { class: 'glyphs', text: sas.glyphs.join(' ') }),
    el('div', { class: 'digits', text: sas.digits }),
  );
}

export function specList(rows: [string, string, 'ok' | 'warn' | 'bad' | ''][]): HTMLElement {
  const list = el('dl', { class: 'spec' });
  for (const [term, value, tone] of rows) {
    list.append(el('dt', { text: term }), el('dd', { class: tone, text: value }));
  }
  return list;
}

export function notice(kind: 'good' | 'warn' | 'bad', title: string, body: string): HTMLElement {
  return el('div', { class: `notice ${kind}` }, el('strong', { text: title }), body);
}

/** Passphrase input with a live strength estimate and a one-tap generator. */
export function passphraseField(options: {
  value: string;
  onChange: (value: string) => void;
  label?: string;
  showGenerator?: boolean;
}): HTMLElement {
  const input = el('input', {
    type: 'password',
    autocomplete: 'off',
    autocapitalize: 'off',
    autocorrect: 'off',
    spellcheck: 'false',
    value: options.value,
    placeholder: 'Both devices must type the same thing',
  });

  const bar = el('div', { class: 'strength' });
  for (let i = 0; i < 4; i++) bar.append(el('i'));
  const advice = el('p', { class: 'hint' });

  const refresh = () => {
    const strength = estimateStrength(input.value);
    bar.className = `strength ${strength.score >= 3 ? 'good' : strength.score <= 1 ? 'weak' : ''}`.trim();
    [...bar.children].forEach((seg, i) => seg.classList.toggle('on', i < strength.score));
    advice.textContent = input.value ? `${strength.label} — ${strength.advice}` : ' ';
    options.onChange(input.value);
  };

  input.addEventListener('input', refresh);

  const reveal = el('button', {
    type: 'button',
    class: 'button secondary',
    text: 'Show',
    onclick: () => {
      const hidden = input.type === 'password';
      input.type = hidden ? 'text' : 'password';
      reveal.textContent = hidden ? 'Hide' : 'Show';
    },
  });

  const generate = el('button', {
    type: 'button',
    class: 'button secondary',
    text: 'Suggest',
    onclick: () => {
      input.value = generatePassphrase();
      input.type = 'text';
      reveal.textContent = 'Hide';
      refresh();
    },
  });

  const wrapper = el('div', {},
    el('label', { class: 'field' },
      el('span', { class: 'field-label' }, 'Passphrase'),
      input,
    ),
    bar,
    advice,
    options.showGenerator !== false
      ? el('div', { class: 'button-row', style: 'margin-top:.6rem' }, generate, reveal)
      : el('div', { class: 'button-row', style: 'margin-top:.6rem' }, reveal),
  );

  refresh();
  return wrapper;
}

/**
 * Install offer and update notice.
 *
 * Only shown when it can actually do something: a real install prompt, iOS's
 * manual route, or a waiting update. Never a dead button.
 */
export function installBanner(onChanged: () => void): HTMLElement | null {
  if (hasUpdate()) {
    return el('div', { class: 'notice good' },
      el('strong', { text: 'A new version is ready' }),
      'Reload to switch to it. Any transfer in progress will be interrupted.',
      el('div', { style: 'margin-top:.6rem' }, el('button', {
        class: 'button secondary',
        text: 'Reload now',
        onclick: () => applyUpdate(),
      })),
    );
  }

  if (isStandalone()) return null;

  if (canInstall()) {
    return el('div', { class: 'notice' },
      el('strong', { text: 'Install QSFT' }),
      'Adds it to your home screen and lets the app open without a network round trip.',
      el('div', { style: 'margin-top:.6rem' }, el('button', {
        class: 'button secondary',
        text: 'Install',
        onclick: async () => { await promptInstall(); onChanged(); },
      })),
    );
  }

  if (isIosSafari()) {
    return el('div', { class: 'notice' },
      el('strong', { text: 'Add QSFT to your home screen' }),
      'Tap the Share button, then "Add to Home Screen".',
    );
  }

  return null;
}

/** Capability panel. Surfaces degraded randomness loudly rather than burying it. */
export function environmentPanel(): HTMLElement {
  const rows = describeEnvironment();
  rows.push({
    label: 'Installable',
    ok: serviceWorkerSupported(),
    note: isStandalone()
      ? 'running as an installed app'
      : serviceWorkerSupported()
        ? 'can be installed and opened offline'
        : 'unavailable - browsers only allow this on HTTPS or localhost',
  });

  const body = el('div', {},
    ...rows.map((row) => el('p', { class: 'hint' },
      el('b', { text: `${row.label}: ` }),
      row.note,
    )),
  );

  return el('details', {},
    el('summary', { text: `Environment${caps.degradedRandom ? ' — degraded' : ''}` }),
    body,
  );
}
