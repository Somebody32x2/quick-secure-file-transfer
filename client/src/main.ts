/**
 * App shell and the two entry screens.
 *
 * The whole surface is three screens: send, receive, and the transfer
 * instrument panel that both feed into.
 */

import './styles.css';

import { el, mount } from './ui/dom.js';
import { environmentPanel, installBanner, notice, passphraseField } from './ui/components.js';
import { initPwa, onPwaChange } from './pwa.js';
import { TransferScreen } from './ui/transferScreen.js';
import { caps } from './crypto/env.js';
import { MAX_FILE_BYTES } from './crypto/format.js';
import { compressionAvailable, looksCompressible } from './compress.js';
import { formatBytes } from './util/bytes.js';
import { AbortedError } from './util/deferred.js';
import { liveSend } from './session/liveSend.js';
import { liveReceive } from './session/liveReceive.js';
import { storedSend, storedReceive } from './session/stored.js';
import { resolveCode } from './transport/api.js';
import type { TransferEvent } from './session/events.js';

const root = document.getElementById('app')!;

type Mode = 'send' | 'receive';
let mode: Mode = 'send';

// -- shell -------------------------------------------------------------------

function masthead(): HTMLElement {
  return el('header', { class: 'masthead' },
    el('div', { class: 'wordmark' }, 'QS', el('span', { text: 'FT' })),
    el('p', { class: 'tagline', text: 'Files are encrypted on this device before anything leaves it.' }),
  );
}

function footer(): HTMLElement {
  return el('footer', { class: 'footer' },
    el('p', {}, 'Your passphrase never leaves this device, and the server only ever holds ciphertext. Send the passphrase to the other person some other way — not alongside the code.'),
    el('div', { style: 'margin-top:.6rem' }, environmentPanel()),
  );
}

function modeSwitch(): HTMLElement {
  const make = (value: Mode, label: string) => el('button', {
    type: 'button',
    'aria-pressed': mode === value,
    text: label,
    onclick: () => { if (mode !== value) { mode = value; render(); } },
  });
  return el('div', { class: 'switch', role: 'group', 'aria-label': 'Send or receive' },
    make('send', 'Send'),
    make('receive', 'Receive'),
  );
}

function shell(...content: (HTMLElement | false | null)[]): void {
  mount(root, masthead(), modeSwitch(), ...content, footer());
}

/** True while a transfer screen is up, so background events cannot re-render over it. */
let inTransfer = false;

function degradedRandomWarning(): HTMLElement | null {
  if (!caps.degradedRandom) return null;
  return notice(
    'bad',
    'This browser has no secure random number generator',
    'QSFT fell back to a software generator seeded from timing noise. It will work, but the keys it produces are weaker than they should be. Use a current browser for anything sensitive.',
  );
}

// -- send --------------------------------------------------------------------

interface SendState {
  file: File | null;
  passphrase: string;
  method: 'live' | 'stored';
  compress: boolean;
  ttlHours: number;
  maxReads: number;
}

const sendState: SendState = {
  file: null,
  passphrase: '',
  method: 'live',
  compress: true,
  ttlHours: 24,
  maxReads: 1,
};

function filePicker(onPick: (file: File) => void): HTMLElement {
  const caption = el('div', {},
    el('p', { class: 'filename', text: sendState.file ? sendState.file.name : 'Choose a file' }),
    el('p', {
      class: 'hint',
      text: sendState.file ? formatBytes(sendState.file.size) : 'Up to 2 GB. Tap to browse, or drop a file here.',
    }),
  );

  const input = el('input', {
    type: 'file',
    onchange: (event: Event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (file) onPick(file);
    },
  });

  const drop = el('label', { class: 'filedrop' }, input, caption);

  drop.addEventListener('dragover', (event) => {
    event.preventDefault();
    drop.classList.add('dragging');
  });
  drop.addEventListener('dragleave', () => drop.classList.remove('dragging'));
  drop.addEventListener('drop', (event: DragEvent) => {
    event.preventDefault();
    drop.classList.remove('dragging');
    const file = event.dataTransfer?.files?.[0];
    if (file) onPick(file);
  });

  return drop;
}

function renderSend(): void {
  const oversize = !!sendState.file && sendState.file.size > MAX_FILE_BYTES;

  const methodSwitch = el('div', { class: 'switch', role: 'group', 'aria-label': 'Transfer method' },
    el('button', {
      type: 'button', 'aria-pressed': sendState.method === 'live', text: 'Live',
      onclick: () => { sendState.method = 'live'; render(); },
    }),
    el('button', {
      type: 'button', 'aria-pressed': sendState.method === 'stored', text: 'Leave on server',
      onclick: () => { sendState.method = 'stored'; render(); },
    }),
  );

  const start = el('button', {
    class: 'button',
    text: sendState.method === 'live' ? 'Get a code and wait' : 'Encrypt and upload',
    disabled: !sendState.file || !sendState.passphrase || oversize,
    onclick: () => startSend(),
  });

  const storedOptions = el('div', {},
    el('div', { class: 'grid-2' },
      el('label', { class: 'field' },
        el('span', { class: 'field-label' }, 'Delete after'),
        el('select', {
          onchange: (e: Event) => { sendState.ttlHours = Number((e.target as HTMLSelectElement).value); },
        },
          ...[[1, '1 hour'], [6, '6 hours'], [24, '24 hours'], [48, '48 hours (max)']].map(([hours, label]) =>
            el('option', { value: String(hours), selected: sendState.ttlHours === hours }, String(label))),
        ),
      ),
      el('label', { class: 'field' },
        el('span', { class: 'field-label' }, 'Or after'),
        el('select', {
          onchange: (e: Event) => { sendState.maxReads = Number((e.target as HTMLSelectElement).value); },
        },
          ...[[1, '1 download'], [2, '2 downloads'], [5, '5 downloads'], [20, '20 downloads']].map(([n, label]) =>
            el('option', { value: String(n), selected: sendState.maxReads === n }, String(label))),
        ),
      ),
    ),
    el('p', { class: 'hint', text: 'Whichever limit is reached first deletes the file. The server never has the key.' }),
  );

  shell(
    degradedRandomWarning(),
    installBanner(render),
    el('div', { class: 'module' },
      el('div', { class: 'module-head' }, el('h2', { text: 'Send a file' })),
      filePicker((file) => { sendState.file = file; sendState.compress = looksCompressible(file.name, file.type); render(); }),
      oversize && notice('bad', 'File is too large', `That file is ${formatBytes(sendState.file!.size)}. The limit is 2 GB.`),
      passphraseField({
        value: sendState.passphrase,
        onChange: (value) => {
          const wasEmpty = !sendState.passphrase;
          sendState.passphrase = value;
          if (wasEmpty !== !value) start.disabled = !sendState.file || !value || oversize;
          start.disabled = !sendState.file || !value || oversize;
        },
      }),
    ),

    el('div', { class: 'module' },
      el('div', { class: 'module-head' }, el('h2', { text: 'How to send it' })),
      methodSwitch,
      el('p', { class: 'hint', text: sendState.method === 'live'
        ? 'Both devices stay open. QSFT tries a direct connection first and falls back to an encrypted relay. Nothing is ever stored.'
        : 'Upload now, collect later. The encrypted file waits on the server until it expires or is collected.' }),
      sendState.method === 'stored' && storedOptions,
      compressionAvailable() && el('label', { class: 'check', style: 'margin-top:.75rem' },
        el('input', {
          type: 'checkbox',
          checked: sendState.compress,
          onchange: (e: Event) => { sendState.compress = (e.target as HTMLInputElement).checked; },
        }),
        el('span', {}, 'Compress before encrypting', el('br'),
          el('span', { class: 'hint', text: 'Faster for documents and text. Skip it for photos, video, and archives.' })),
      ),
      el('div', { style: 'margin-top:1rem' }, start),
    ),
  );
}

// -- receive -----------------------------------------------------------------

const receiveState = { code: '', passphrase: '' };

function renderReceive(): void {
  const codeInput = el('input', {
    type: 'text',
    class: 'code-entry mono',
    inputmode: 'numeric',
    pattern: '[0-9]*',
    autocomplete: 'one-time-code',
    maxlength: '6',
    placeholder: '000000',
    value: receiveState.code,
  });

  const start = el('button', {
    class: 'button',
    text: 'Collect the file',
    disabled: receiveState.code.length !== 6 || !receiveState.passphrase,
    onclick: () => startReceive(),
  });

  const refreshEnabled = () => {
    start.disabled = receiveState.code.length !== 6 || !receiveState.passphrase;
  };

  codeInput.addEventListener('input', () => {
    const digits = codeInput.value.replace(/\D/g, '').slice(0, 6);
    codeInput.value = digits;
    receiveState.code = digits;
    refreshEnabled();
  });

  shell(
    degradedRandomWarning(),
    installBanner(render),
    el('div', { class: 'module' },
      el('div', { class: 'module-head' }, el('h2', { text: 'Receive a file' })),
      el('label', { class: 'field' },
        el('span', { class: 'field-label' }, 'Code from the sender'),
        codeInput,
      ),
      passphraseField({
        value: receiveState.passphrase,
        showGenerator: false,
        onChange: (value) => { receiveState.passphrase = value; refreshEnabled(); },
      }),
      el('p', { class: 'hint', text: 'The passphrase must match exactly what the sender typed. QSFT works out on its own whether someone is waiting live or the file is stored.' }),
      el('div', { style: 'margin-top:1rem' }, start),
    ),
  );
}

// -- transfer ----------------------------------------------------------------

function runTransfer(
  title: string,
  work: (screen: TransferScreen, onEvent: (e: TransferEvent) => void, abort: AbortSignal) => Promise<void>,
): void {
  const controller = new AbortController();
  inTransfer = true;
  const screen = new TransferScreen({
    title,
    onCancel: () => {
      controller.abort();
      screen.showError('Cancelled.');
    },
    onRestart: () => { screen.destroy(); inTransfer = false; render(); },
  });

  shell(screen.root);

  work(screen, (event) => screen.handle(event), controller.signal).catch((err: unknown) => {
    if (err instanceof AbortedError || controller.signal.aborted) return;
    screen.showError(err instanceof Error ? err.message : String(err));
  });
}

function startSend(): void {
  const { file, passphrase, method, compress } = sendState;
  if (!file) return;

  if (method === 'live') {
    runTransfer('Sending live', async (_screen, onEvent, abort) => {
      await liveSend({ file, passphrase, compress, onEvent, abort });
    });
  } else {
    runTransfer('Uploading', async (screen, onEvent, abort) => {
      const result = await storedSend({
        file,
        passphrase,
        compress,
        ttlSeconds: sendState.ttlHours * 3600,
        maxReads: sendState.maxReads,
        onEvent,
        abort,
      });
      screen.showStoredResult(result.code, result.expiresAt, result.maxReads, result.revoke);
    });
  }
}

function startReceive(): void {
  const { code, passphrase } = receiveState;

  runTransfer('Receiving', async (screen, onEvent, abort) => {
    onEvent({ t: 'status', message: 'Looking up the code...' });
    const resolved = await resolveCode(code);

    const requestDestination = (meta: Parameters<typeof screen.askDestination>[0]) =>
      screen.askDestination(meta);

    if (resolved.kind === 'live') {
      await liveReceive({ code, passphrase, onEvent, requestDestination, abort });
    } else {
      await storedReceive({ code, passphrase, onEvent, requestDestination, abort });
    }
  });
}

// -- boot --------------------------------------------------------------------

function render(): void {
  if (inTransfer) return;
  if (mode === 'send') renderSend();
  else renderReceive();
}

initPwa();
// An install offer or a waiting update can arrive at any time; redraw for it,
// unless a transfer is on screen.
onPwaChange(render);

render();
