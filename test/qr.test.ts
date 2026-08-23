/**
 * The QR encoder and the scanned handoff.
 *
 * A hand-rolled encoder is only worth anything if real scanners read what it
 * produces, and nothing in this repo can scan. So the symbols below were run
 * through an independent decoder (jsQR) once, over payload lengths spanning
 * all forty versions, and the fingerprints recorded here pin that verified
 * output in place. Anything that changes a module now has to change a
 * fingerprint too, which is the point.
 *
 * The rest is read back off the symbol the way a scanner starts: locate the
 * function patterns, decode the format information, and check it says what the
 * encoder claims it says.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { encodeQr, type QrCode } from '../client/src/util/qr.ts';
import { handoffUrl, parseHandoff } from '../client/src/util/handoff.ts';

/** Stable fingerprint of a symbol: its size, then its modules row by row. */
function fingerprint(qr: QrCode): string {
  const rows = qr.modules.map((row) => row.map((cell) => (cell ? '1' : '0')).join(''));
  return createHash('sha256').update(`${qr.size}\n${rows.join('\n')}`).digest('hex').slice(0, 32);
}

function versionOf(qr: QrCode): number {
  return (qr.size - 17) / 4;
}

// -- shape -------------------------------------------------------------------

test('symbol size follows the version', () => {
  for (const [text, version] of [['A', 1], ['x'.repeat(15), 2], ['x'.repeat(123), 8]] as const) {
    const qr = encodeQr(text);
    assert.equal(versionOf(qr), version);
    assert.equal(qr.size, version * 4 + 17);
    assert.equal(qr.modules.length, qr.size);
    for (const row of qr.modules) assert.equal(row.length, qr.size);
  }
});

test('the smallest version that fits is the one used', () => {
  // Level M byte-mode capacities, from the specification's capacity table. The
  // step from 8-bit to 16-bit length fields at version 10 is the interesting
  // one, since it costs a byte of payload on the way across.
  for (const [capacity, version] of [[14, 1], [26, 2], [84, 5], [122, 7], [213, 10], [666, 20], [2331, 40]] as const) {
    assert.equal(versionOf(encodeQr('x'.repeat(capacity))), version, `${capacity} bytes`);
    if (version < 40) {
      assert.equal(versionOf(encodeQr('x'.repeat(capacity + 1))), version + 1, `${capacity + 1} bytes`);
    }
  }
});

test('past the largest symbol it refuses rather than truncating', () => {
  assert.throws(() => encodeQr('x'.repeat(2332)), /Too much data/);
});

test('multi-byte characters are counted as UTF-8 bytes, not characters', () => {
  // 14 characters fit at version 1; the same 14 as three-byte characters do not.
  assert.equal(versionOf(encodeQr('x'.repeat(14))), 1);
  assert.equal(versionOf(encodeQr('✓'.repeat(14))), 3);
});

// -- function patterns -------------------------------------------------------

/** The 7x7 finder, read as concentric rings: dark, light, dark, light, dark. */
function isFinderAt(qr: QrCode, left: number, top: number): boolean {
  for (let dy = 0; dy < 7; dy++) {
    for (let dx = 0; dx < 7; dx++) {
      const ring = Math.max(Math.abs(dx - 3), Math.abs(dy - 3));
      if (qr.modules[top + dy][left + dx] !== (ring !== 2)) return false;
    }
  }
  return true;
}

test('the three finder patterns are where a scanner looks for them', () => {
  const qr = encodeQr('https://example.test/#c=123456&p=hunter2');
  assert.ok(isFinderAt(qr, 0, 0), 'top left');
  assert.ok(isFinderAt(qr, qr.size - 7, 0), 'top right');
  assert.ok(isFinderAt(qr, 0, qr.size - 7), 'bottom left');

  // The fourth corner must not have one - that is how orientation is read.
  assert.ok(!isFinderAt(qr, qr.size - 7, qr.size - 7), 'bottom right stays empty');
});

test('timing patterns alternate across the whole symbol', () => {
  const qr = encodeQr('x'.repeat(200));
  for (let i = 8; i < qr.size - 8; i++) {
    assert.equal(qr.modules[6][i], i % 2 === 0, `row 6 column ${i}`);
    assert.equal(qr.modules[i][6], i % 2 === 0, `column 6 row ${i}`);
  }
});

test('the always-dark module is set', () => {
  const qr = encodeQr('hello');
  assert.equal(qr.modules[qr.size - 8][8], true);
});

// -- format information ------------------------------------------------------

/**
 * Decode the format field the way a scanner does: read the 15 bits, undo the
 * fixed XOR, and check the BCH code before trusting the contents.
 */
function readFormat(qr: QrCode, copy: 'first' | 'second'): { ecLevel: number; mask: number } {
  const bits: boolean[] = [];
  if (copy === 'first') {
    for (let i = 0; i <= 5; i++) bits.push(qr.modules[i][8]);
    bits.push(qr.modules[7][8], qr.modules[8][8], qr.modules[8][7]);
    for (let i = 9; i < 15; i++) bits.push(qr.modules[8][14 - i]);
  } else {
    for (let i = 0; i < 8; i++) bits.push(qr.modules[8][qr.size - 1 - i]);
    for (let i = 8; i < 15; i++) bits.push(qr.modules[qr.size - 15 + i][8]);
  }

  let value = 0;
  for (let i = 0; i < 15; i++) if (bits[i]) value |= 1 << i;
  value ^= 0x5412;

  // Re-run the BCH generator over the top 5 bits; a valid field leaves no
  // remainder against the 10 check bits.
  const data = value >>> 10;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
  assert.equal(((data << 10) | rem) & 0x7fff, value, `${copy} copy fails its BCH check`);

  return { ecLevel: data >>> 3, mask: data & 0b111 };
}

test('format information says level M and both copies agree', () => {
  for (const text of ['A', 'x'.repeat(200), 'x'.repeat(1200)]) {
    const qr = encodeQr(text);
    const first = readFormat(qr, 'first');
    const second = readFormat(qr, 'second');
    assert.deepEqual(first, second, 'the two copies must be identical');
    // 0 is level M in the format field's own numbering, which is not the
    // L/M/Q/H order.
    assert.equal(first.ecLevel, 0, 'error correction level M');
    assert.ok(first.mask >= 0 && first.mask <= 7);
  }
});

test('the mask is chosen by the symbol, not fixed', () => {
  // Different payloads score differently, so a build that quietly stopped
  // evaluating masks would show up as one mask for everything.
  const masks = new Set<number>();
  for (let i = 0; i < 40; i++) masks.add(readFormat(encodeQr(`payload number ${i}`), 'first').mask);
  assert.ok(masks.size > 1, `expected varied masks, got ${[...masks]}`);
});

// -- pinned output -----------------------------------------------------------

test('symbols match the output verified against an independent decoder', () => {
  // Generated once and confirmed to decode back to exactly these strings.
  const vectors: [string, string][] = [
    ['A', '55650a3e668e54d8bbbc272b77ea0ec8'],
    ['https://qsft.example/#c=123456&p=hunter2', '0facf67b68932c7df1e0e25662856553'],
    ['x'.repeat(213), '9be4bea9862935460ffeec1f81f8ffd0'],
    ['x'.repeat(2331), '3d02cba7d04d00a1426d34acb1b2340a'],
  ];
  for (const [text, expected] of vectors) {
    assert.equal(fingerprint(encodeQr(text)), expected, `length ${text.length}`);
  }
});

test('encoding is deterministic', () => {
  const text = 'http://192.168.1.44:8080/#c=482913&p=correct%20horse';
  assert.equal(fingerprint(encodeQr(text)), fingerprint(encodeQr(text)));
});

// -- handoff link ------------------------------------------------------------

test('a handoff URL round-trips code and passphrase', () => {
  const cases = [
    ['123456', 'hunter2'],
    ['000000', 'correct horse battery staple'],
    // The characters that would break a naively built query string.
    ['482913', 'a&b=c#d+e%f?g'],
    ['999999', 'pässphrase with ünicode ✓'],
  ];
  for (const [code, passphrase] of cases) {
    const url = handoffUrl(code, passphrase, 'https://example.test');
    const parsed = parseHandoff(url.slice(url.indexOf('#')));
    assert.deepEqual(parsed, { code, passphrase }, passphrase);
  }
});

test('the passphrase goes in the fragment, never the path or query', () => {
  const url = handoffUrl('123456', 'hunter2', 'https://example.test');
  const [beforeFragment] = url.split('#');
  assert.ok(!beforeFragment.includes('hunter2'));
  assert.ok(!beforeFragment.includes('123456'));
  assert.ok(url.startsWith('https://example.test/'));
});

test('a malformed or unrelated fragment is not treated as a handoff', () => {
  for (const hash of [
    '',
    '#',
    '#section-3',
    '#c=123456',            // no passphrase
    '#p=hunter2',           // no code
    '#c=12345&p=hunter2',   // code too short
    '#c=1234567&p=hunter2', // code too long
    '#c=12345a&p=hunter2',  // not digits
    '#c=123456&p=',         // empty passphrase
  ]) {
    assert.equal(parseHandoff(hash), null, JSON.stringify(hash));
  }
});
