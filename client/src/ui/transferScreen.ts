/**
 * The live transfer panel: one instrument face that every flow drives through
 * the same event stream, so send and receive, live and stored, all read alike.
 */

import { el, mount, announce } from './dom.js';
import {
  CarrierMeter, codeWell, notice, progressReadout, specList, stateBadge, verifyPanel,
} from './components.js';
import { formatBytes } from '../util/bytes.js';
import { createBlobSink, requestDiskSink, triggerDownload, type FileSink } from '../sink.js';
import { caps } from '../crypto/env.js';
import type { TransferEvent } from '../session/events.js';
import type { FileMeta } from '../crypto/format.js';

export interface TransferScreenOptions {
  title: string;
  onCancel: () => void;
  onRestart: () => void;
}

export class TransferScreen {
  readonly root = el('div');
  private meter = new CarrierMeter();
  private stateSlot = el('div');
  private codeSlot = el('div');
  private verifySlot = el('div');
  private statusLine = el('p', { class: 'hint' });
  private readoutSlot = el('div');
  private specSlot = el('div');
  private extraSlot = el('div');
  private actionSlot = el('div');

  private linkInfo: [string, string, 'ok' | 'warn' | 'bad' | ''] | null = null;
  private cipherInfo: [string, string, 'ok' | 'warn' | 'bad' | ''];
  private finished = false;

  constructor(private options: TransferScreenOptions) {
    this.cipherInfo = ['Cipher', caps.subtle ? 'AES-256-GCM' : 'XChaCha20-Poly1305', ''];
    this.meter.startSweep();

    const module = el('div', { class: 'module' },
      el('div', { class: 'module-head' },
        el('h2', { text: options.title }),
        this.stateSlot,
      ),
      this.meter.root,
      this.statusLine,
      this.readoutSlot,
      this.codeSlot,
      this.verifySlot,
      this.specSlot,
      this.extraSlot,
      this.actionSlot,
    );

    this.setState('Starting', 'working');
    mount(this.root, module);
    this.renderActions();
  }

  private setState(text: string, kind: 'idle' | 'working' | 'ok' | 'error'): void {
    mount(this.stateSlot, stateBadge(text, kind));
  }

  private renderSpec(): void {
    const rows: [string, string, 'ok' | 'warn' | 'bad' | ''][] = [];
    if (this.linkInfo) rows.push(this.linkInfo);
    rows.push(this.cipherInfo);
    rows.push(['Key', 'X25519 + ML-KEM-768', 'ok']);
    mount(this.specSlot, specList(rows));
  }

  private renderActions(): void {
    if (this.finished) {
      mount(this.actionSlot, el('button', {
        class: 'button secondary',
        text: 'Start another transfer',
        onclick: () => this.options.onRestart(),
      }));
    } else {
      mount(this.actionSlot, el('button', {
        class: 'button secondary',
        text: 'Cancel',
        onclick: () => this.options.onCancel(),
      }));
    }
  }

  handle(event: TransferEvent): void {
    switch (event.t) {
      case 'code':
        mount(this.codeSlot, codeWell(event.code, 'Type this on the other device, then the passphrase.'));
        this.setState('Waiting', 'working');
        announce(`Your code is ${event.code.split('').join(' ')}`);
        break;

      case 'status':
        this.statusLine.textContent = event.message;
        break;

      case 'peer':
        this.setState('Linked', 'working');
        break;

      case 'link':
        this.linkInfo = ['Link', event.detail, event.kind === 'p2p' ? 'ok' : 'warn'];
        this.renderSpec();
        break;

      case 'sas':
        mount(this.verifySlot, verifyPanel(event.sas));
        break;

      case 'meta':
        mount(this.extraSlot, el('p', { class: 'hint' },
          el('b', { text: event.meta.name }), ` — ${formatBytes(event.meta.size)}`,
        ));
        break;

      case 'progress': {
        this.setState('Transferring', 'working');
        this.meter.setProgress(event.total > 0 ? event.bytes / event.total : 0);
        mount(this.readoutSlot, progressReadout(
          event.bytes, event.total, event.bytesPerSecond, event.etaSeconds,
        ));
        break;
      }

      case 'awaiting-destination':
        this.setState('Ready', 'working');
        break;

      case 'done':
        this.showDone(event);
        break;

      case 'error':
        this.showError(event.message);
        break;
    }
  }

  /**
   * Asks the user where to put the file. Must run inside the click handler:
   * browsers only open a save dialog during a real user gesture, which is why
   * the protocol waits here rather than picking a destination automatically.
   */
  askDestination(meta: FileMeta): Promise<FileSink> {
    // Checked live rather than from the load-time snapshot, so a host that
    // exposes the picker late (or not at all) is judged on what it can do now.
    const canPickLocation = caps.fileSystemAccess
      && typeof (globalThis as { showSaveFilePicker?: unknown }).showSaveFilePicker === 'function';

    // Without a save picker there is nothing to ask: the browser hands the file
    // over once it is complete and verified. Blocking on a tap here bought
    // nothing on mobile and left both devices sitting in "waiting" states.
    if (!canPickLocation) {
      mount(this.extraSlot,
        el('p', { class: 'hint' },
          el('b', { text: meta.name }), ` — ${formatBytes(meta.size)}`,
        ),
        el('p', { class: 'hint', text: 'Downloads automatically once it arrives and passes its integrity check.' }),
      );
      this.statusLine.textContent = 'Receiving...';
      return Promise.resolve(createBlobSink());
    }

    return new Promise((resolve) => {
      const streamToDisk = canPickLocation;
      const save = el('button', {
        class: 'button',
        text: `Save ${meta.name}`,
        onclick: async () => {
          save.disabled = true;
          const sink = streamToDisk ? await requestDiskSink(meta.name) : null;
          mount(this.extraSlot, el('p', { class: 'hint' },
            el('b', { text: meta.name }), ` — ${formatBytes(meta.size)}`,
          ));
          resolve(sink ?? createBlobSink());
        },
      });

      mount(this.extraSlot,
        el('div', { class: 'notice good' },
          el('strong', { text: 'Ready to receive' }),
          `${meta.name} — ${formatBytes(meta.size)}`,
        ),
        streamToDisk
          ? el('p', { class: 'hint', text: 'You will be asked where to save it. The file is written as it arrives, so size is not limited by memory.' })
          : el('p', { class: 'hint', text: 'The file is assembled in the browser, then downloaded when it finishes and passes its integrity check.' }),
        el('div', { style: 'margin-top:.75rem' }, save),
      );
      this.statusLine.textContent = 'Choose where to save, then the transfer begins.';
    });
  }

  showDone(event: Extract<TransferEvent, { t: 'done' }>): void {
    this.finished = true;
    this.meter.setProgress(1);
    this.setState('Verified', 'ok');

    if (event.url && event.name) {
      // Integrity is already proven at this point, so handing the file over is safe.
      triggerDownload(event.url, event.name);
      mount(this.extraSlot,
        notice('good', 'Received and verified', `${event.name} has been decrypted and its authentication tags checked.`),
        el('div', { style: 'margin-top:.75rem' }, el('button', {
          class: 'button',
          text: 'Save again',
          onclick: () => triggerDownload(event.url!, event.name!),
        })),
      );
    } else if (event.savedToDisk) {
      mount(this.extraSlot, notice('good', 'Saved and verified', `${event.name ?? 'The file'} was written to the location you chose.`));
    } else {
      mount(this.extraSlot, notice('good', 'Sent and verified', 'The other device confirmed it decrypted the whole file.'));
    }

    announce('Transfer complete and verified');
    this.renderActions();
  }

  showError(message: string): void {
    this.finished = true;
    this.meter.setError();
    this.setState('Failed', 'error');
    this.statusLine.textContent = '';
    mount(this.extraSlot, notice('bad', 'Transfer stopped', message));
    announce(`Transfer failed: ${message}`);
    this.renderActions();
  }

  /** Shown after a stored upload commits, since the sender can now walk away. */
  showStoredResult(code: string, expiresAt: number, maxReads: number, onRevoke: () => Promise<void>): void {
    this.finished = true;
    this.meter.setProgress(1);
    this.setState('Stored', 'ok');
    this.statusLine.textContent = '';
    mount(this.verifySlot);

    const expiry = new Date(expiresAt);
    const revoke = el('button', {
      class: 'button danger',
      text: 'Delete from server now',
      onclick: async () => {
        revoke.disabled = true;
        revoke.textContent = 'Deleting...';
        await onRevoke();
        mount(this.extraSlot, notice('good', 'Deleted', 'The encrypted file is no longer on the server.'));
      },
    });

    mount(this.codeSlot, codeWell(code, 'The other device needs this code and the passphrase.'));
    mount(this.extraSlot,
      specList([
        ['Expires', expiry.toLocaleString(), ''],
        ['Reads left', maxReads === 1 ? '1 (deletes after collection)' : String(maxReads), ''],
        ['Server sees', 'ciphertext only', 'ok'],
      ]),
      el('div', { style: 'margin-top:.75rem' }, revoke),
    );
    this.renderActions();
  }

  destroy(): void { this.meter.destroy(); }
}
