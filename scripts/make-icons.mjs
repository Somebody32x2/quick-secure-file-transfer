#!/usr/bin/env node
/**
 * Generates the PWA icon set.
 *
 * Hand-rolled PNG encoding rather than an image dependency: this project ships
 * cryptography, and every package added to it is another thing to trust. Node's
 * zlib is all that is needed.
 *
 * The mark matches the app's instrument-panel identity - a lit signal segment
 * over a shorter unlit one, on graphite.
 */

import zlib from 'node:zlib';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const outDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..', 'client', 'public', 'icons',
);

// --- minimal PNG encoder ----------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (const byte of buf) c = CRC_TABLE[(c ^ byte) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

/** @param pixels RGBA bytes, width*height*4 */
function encodePng(width, height, pixels) {
  const stride = width * 4;
  // Each scanline is prefixed with its filter byte; 0 = none.
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0;
    pixels.copy(raw, y * (stride + 1) + 1, y * stride, (y + 1) * stride);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8;  // bit depth
  ihdr[9] = 6;  // colour type: RGBA
  ihdr[10] = 0; // deflate
  ihdr[11] = 0; // adaptive filtering
  ihdr[12] = 0; // no interlace

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

// --- drawing ----------------------------------------------------------------

const INK = [0x17, 0x16, 0x14];
const SIGNAL = [0x2f, 0xc4, 0x8b];
const PANEL = [0xde, 0xdc, 0xd5];

function createCanvas(size) {
  return { size, pixels: Buffer.alloc(size * size * 4) };
}

function setPixel(canvas, x, y, [r, g, b], a = 255) {
  const i = (y * canvas.size + x) * 4;
  canvas.pixels[i] = r;
  canvas.pixels[i + 1] = g;
  canvas.pixels[i + 2] = b;
  canvas.pixels[i + 3] = a;
}

/** Rounded rectangle in normalised (0..1) coordinates. */
function fillRoundedRect(canvas, x0, y0, x1, y1, radius, colour) {
  const s = canvas.size;
  const px0 = x0 * s, py0 = y0 * s, px1 = x1 * s, py1 = y1 * s;
  const r = radius * s;

  for (let y = Math.floor(py0); y < Math.ceil(py1); y++) {
    for (let x = Math.floor(px0); x < Math.ceil(px1); x++) {
      if (x < 0 || y < 0 || x >= s || y >= s) continue;
      // Distance outside the inner rect, for corner rounding.
      const dx = Math.max(px0 + r - (x + 0.5), (x + 0.5) - (px1 - r), 0);
      const dy = Math.max(py0 + r - (y + 0.5), (y + 0.5) - (py1 - r), 0);
      const dist = Math.hypot(dx, dy);
      if (dist > r + 0.5) continue;
      // One-pixel feather so the curve does not look jagged.
      const alpha = dist <= r - 0.5 ? 255 : Math.round(255 * (r + 0.5 - dist));
      setPixel(canvas, x, y, colour, alpha);
    }
  }
}

/**
 * @param inset fraction of the canvas kept clear around the mark. Maskable
 *              icons need their content inside the safe zone, because launchers
 *              crop them to arbitrary shapes.
 */
function drawIcon(size, { maskable = false, opaque = false } = {}) {
  const canvas = createCanvas(size);

  if (maskable || opaque) {
    // Full bleed: the launcher (or iOS) supplies the shape.
    fillRoundedRect(canvas, 0, 0, 1, 1, 0, INK);
  } else {
    fillRoundedRect(canvas, 0, 0, 1, 1, 0.18, INK);
  }

  // Content sits inside the safe zone on maskable icons, wider otherwise.
  const scale = maskable ? 0.62 : 0.86;
  const pad = (1 - scale) / 2;
  const at = (v) => pad + v * scale;

  // Lit signal segment, then a shorter unlit one - the carrier meter.
  fillRoundedRect(canvas, at(0.06), at(0.34), at(0.94), at(0.48), 0.02, SIGNAL);
  fillRoundedRect(canvas, at(0.06), at(0.58), at(0.58), at(0.70), 0.02, PANEL);

  return encodePng(size, size, canvas.pixels);
}

// --- output -----------------------------------------------------------------

fs.mkdirSync(outDir, { recursive: true });

const targets = [
  ['icon-192.png', drawIcon(192)],
  ['icon-512.png', drawIcon(512)],
  ['icon-maskable-192.png', drawIcon(192, { maskable: true })],
  ['icon-maskable-512.png', drawIcon(512, { maskable: true })],
  // iOS ignores the manifest and dislikes alpha, so this one is opaque.
  ['apple-touch-icon.png', drawIcon(180, { opaque: true })],
];

for (const [name, buffer] of targets) {
  fs.writeFileSync(path.join(outDir, name), buffer);
  console.log(`${name.padEnd(26)} ${String(buffer.length).padStart(6)} bytes`);
}
