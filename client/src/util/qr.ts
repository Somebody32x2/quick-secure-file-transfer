/**
 * QR encoder — byte mode, error correction level M.
 *
 * Hand-rolled for the same reason the ZIP writer is: the payload here is the
 * passphrase, and a QR library is a dependency that gets to see it. This runs
 * entirely offline on a handful of integer tables, so nothing about the secret
 * leaves the module.
 *
 * Byte mode only, because the payload is a URL and alphanumeric mode cannot
 * carry lowercase. Level M only, because that is the recommended default for
 * screen-to-camera scanning and the payloads here are nowhere near the point
 * where trading correction for capacity would matter — level M still reaches
 * 2331 bytes at version 40.
 *
 * The structure follows ISO/IEC 18004: build a bit stream, split it into
 * blocks, append Reed-Solomon parity, interleave, lay the result into the
 * matrix on a zigzag, then pick the mask that scores best.
 */

/**
 * Reed-Solomon codewords per block, indexed by version (1-40). Index 0 is a
 * placeholder so the tables can be read with the version number directly.
 */
const ECC_CODEWORDS_PER_BLOCK = [
  -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26,
  26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28,
];

/** How many blocks the data is split across, indexed by version (1-40). */
const NUM_ERROR_CORRECTION_BLOCKS = [
  -1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16,
  17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49,
];

/** Format-info bits for level M, and the mask-penalty weights from the spec. */
const FORMAT_BITS_M = 0;
const PENALTY_N1 = 3;
const PENALTY_N2 = 3;
const PENALTY_N3 = 40;
const PENALTY_N4 = 10;

const MIN_VERSION = 1;
const MAX_VERSION = 40;

export interface QrCode {
  /** Width and height in modules, excluding the quiet zone. */
  readonly size: number;
  /** Row-major grid; true is a dark module. */
  readonly modules: readonly boolean[][];
}

/**
 * Encode text as a QR symbol.
 *
 * @throws if the text does not fit in a version 40 symbol at level M.
 */
export function encodeQr(text: string): QrCode {
  const data = new TextEncoder().encode(text);
  const version = chooseVersion(data.length);
  if (version === null) {
    throw new Error('Too much data for a QR code');
  }
  const codewords = addEccAndInterleave(buildCodewords(data, version), version);
  return draw(version, codewords);
}

// -- capacity ----------------------------------------------------------------

/**
 * Total module count available to data and error correction, in bits, before
 * the symbol is divided into codewords.
 *
 * The closed form subtracts the function patterns: finders and format info are
 * a fixed cost, alignment patterns grow with the version, and version 7 and up
 * spend another 36 modules on the version blocks.
 */
function rawDataModules(version: number): number {
  let result = (16 * version + 128) * version + 64;
  if (version >= 2) {
    const alignmentCount = Math.floor(version / 7) + 2;
    result -= (25 * alignmentCount - 10) * alignmentCount - 55;
    if (version >= 7) result -= 36;
  }
  return result;
}

/** Codewords left for the message itself once parity is accounted for. */
function dataCodewords(version: number): number {
  return Math.floor(rawDataModules(version) / 8)
    - ECC_CODEWORDS_PER_BLOCK[version] * NUM_ERROR_CORRECTION_BLOCKS[version];
}

/** Byte mode spends 8 bits on the length below version 10 and 16 above it. */
function lengthBits(version: number): number {
  return version < 10 ? 8 : 16;
}

/** Smallest version that holds `byteCount`, or null if none does. */
function chooseVersion(byteCount: number): number | null {
  for (let version = MIN_VERSION; version <= MAX_VERSION; version++) {
    const capacity = dataCodewords(version) * 8 - 4 - lengthBits(version);
    if (byteCount * 8 <= capacity) return version;
  }
  return null;
}

// -- bit stream --------------------------------------------------------------

/**
 * Mode indicator, length, payload, terminator, and padding, as whole codewords.
 *
 * The pad bytes alternate 0xEC / 0x11 by specification — they are not
 * arbitrary filler, and a scanner will reject a symbol padded with zeroes.
 */
function buildCodewords(data: Uint8Array, version: number): Uint8Array {
  const bits: number[] = [];
  const append = (value: number, count: number) => {
    for (let i = count - 1; i >= 0; i--) bits.push((value >>> i) & 1);
  };

  append(0b0100, 4);
  append(data.length, lengthBits(version));
  for (const byte of data) append(byte, 8);

  const capacityBits = dataCodewords(version) * 8;
  append(0, Math.min(4, capacityBits - bits.length));
  append(0, (8 - (bits.length % 8)) % 8);

  const out = new Uint8Array(dataCodewords(version));
  for (let i = 0; i < bits.length; i++) out[i >>> 3] |= bits[i] << (7 - (i & 7));
  for (let i = bits.length / 8, pad = 0xec; i < out.length; i++, pad ^= 0xec ^ 0x11) {
    out[i] = pad;
  }
  return out;
}

// -- error correction --------------------------------------------------------

/** Multiply in GF(2^8) modulo x^8 + x^4 + x^3 + x^2 + 1, the QR field. */
function fieldMultiply(x: number, y: number): number {
  let z = 0;
  for (let i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11d);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

/** Coefficients of the generator polynomial of the given degree. */
function rsDivisor(degree: number): Uint8Array {
  const result = new Uint8Array(degree);
  result[degree - 1] = 1;
  let root = 1;
  for (let i = 0; i < degree; i++) {
    for (let j = 0; j < degree; j++) {
      result[j] = fieldMultiply(result[j], root);
      if (j + 1 < degree) result[j] ^= result[j + 1];
    }
    root = fieldMultiply(root, 0x02);
  }
  return result;
}

/** Polynomial division remainder — the parity codewords for one block. */
function rsRemainder(data: Uint8Array, divisor: Uint8Array): Uint8Array {
  const result = new Uint8Array(divisor.length);
  for (const byte of data) {
    const factor = byte ^ result[0];
    result.copyWithin(0, 1);
    result[result.length - 1] = 0;
    for (let i = 0; i < divisor.length; i++) {
      result[i] ^= fieldMultiply(divisor[i], factor);
    }
  }
  return result;
}

/**
 * Split into blocks, add parity, and interleave.
 *
 * Interleaving is what makes the correction worth having: a scratch or a thumb
 * across the symbol damages a contiguous run of modules, and spreading each
 * block's codewords across the whole symbol turns that burst into a few
 * recoverable errors per block rather than one unrecoverable block.
 *
 * Blocks come in two lengths. Short blocks carry a placeholder byte so every
 * block is the same length while interleaving, and that byte is skipped on the
 * way out.
 */
function addEccAndInterleave(data: Uint8Array, version: number): Uint8Array {
  const blockCount = NUM_ERROR_CORRECTION_BLOCKS[version];
  const eccLen = ECC_CODEWORDS_PER_BLOCK[version];
  const rawCodewords = Math.floor(rawDataModules(version) / 8);
  const shortBlockCount = blockCount - (rawCodewords % blockCount);
  const shortBlockLen = Math.floor(rawCodewords / blockCount);

  const divisor = rsDivisor(eccLen);
  const blocks: Uint8Array[] = [];
  for (let i = 0, offset = 0; i < blockCount; i++) {
    const datLen = shortBlockLen - eccLen + (i < shortBlockCount ? 0 : 1);
    const dat = data.subarray(offset, offset + datLen);
    offset += datLen;
    const block = new Uint8Array(shortBlockLen + 1);
    block.set(dat);
    // The placeholder in a short block sits where the extra data codeword of a
    // long block would be, so parity lands at the same index in both.
    block.set(rsRemainder(dat, divisor), block.length - eccLen);
    blocks.push(block);
  }

  const result = new Uint8Array(rawCodewords);
  for (let i = 0, k = 0; i < blocks[0].length; i++) {
    for (let j = 0; j < blocks.length; j++) {
      if (i === shortBlockLen - eccLen && j < shortBlockCount) continue;
      result[k++] = blocks[j][i];
    }
  }
  return result;
}

// -- matrix ------------------------------------------------------------------

class Matrix {
  readonly size: number;
  readonly modules: boolean[][];
  /** Function patterns are fixed: data skips them and masking leaves them alone. */
  private readonly reserved: boolean[][];

  constructor(readonly version: number) {
    this.size = version * 4 + 17;
    this.modules = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
    this.reserved = Array.from({ length: this.size }, () => new Array<boolean>(this.size).fill(false));
  }

  private set(x: number, y: number, dark: boolean): void {
    this.modules[y][x] = dark;
    this.reserved[y][x] = true;
  }

  isReserved(x: number, y: number): boolean { return this.reserved[y][x]; }

  drawFunctionPatterns(): void {
    // Timing patterns: the alternating row and column scanners use to work out
    // the module pitch.
    for (let i = 0; i < this.size; i++) {
      this.set(6, i, i % 2 === 0);
      this.set(i, 6, i % 2 === 0);
    }

    this.drawFinder(3, 3);
    this.drawFinder(this.size - 4, 3);
    this.drawFinder(3, this.size - 4);

    const positions = alignmentPositions(this.version);
    for (let i = 0; i < positions.length; i++) {
      for (let j = 0; j < positions.length; j++) {
        // The three corners already hold finder patterns.
        const corner = (i === 0 && j === 0)
          || (i === 0 && j === positions.length - 1)
          || (i === positions.length - 1 && j === 0);
        if (!corner) this.drawAlignment(positions[i], positions[j]);
      }
    }

    // Reserve the format area with a placeholder; the real bits go in once the
    // mask is chosen.
    this.drawFormatBits(0);
    this.drawVersionBits();
  }

  private drawFinder(x: number, y: number): void {
    for (let dy = -4; dy <= 4; dy++) {
      for (let dx = -4; dx <= 4; dx++) {
        const distance = Math.max(Math.abs(dx), Math.abs(dy));
        const xx = x + dx;
        const yy = y + dy;
        if (xx >= 0 && xx < this.size && yy >= 0 && yy < this.size) {
          this.set(xx, yy, distance !== 2 && distance !== 4);
        }
      }
    }
  }

  private drawAlignment(x: number, y: number): void {
    for (let dy = -2; dy <= 2; dy++) {
      for (let dx = -2; dx <= 2; dx++) {
        this.set(x + dx, y + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
      }
    }
  }

  /** Format info: error correction level and mask, BCH-protected and twice over. */
  drawFormatBits(mask: number): void {
    const data = (FORMAT_BITS_M << 3) | mask;
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    // The XOR mask stops an all-zero format field from looking like blank space.
    const bits = ((data << 10) | rem) ^ 0x5412;
    const bit = (i: number) => ((bits >>> i) & 1) !== 0;

    for (let i = 0; i <= 5; i++) this.set(8, i, bit(i));
    this.set(8, 7, bit(6));
    this.set(8, 8, bit(7));
    this.set(7, 8, bit(8));
    for (let i = 9; i < 15; i++) this.set(14 - i, 8, bit(i));

    for (let i = 0; i < 8; i++) this.set(this.size - 1 - i, 8, bit(i));
    for (let i = 8; i < 15; i++) this.set(8, this.size - 15 + i, bit(i));
    this.set(8, this.size - 8, true);
  }

  /** Version 7 and up state their version in two 18-bit blocks. */
  private drawVersionBits(): void {
    if (this.version < 7) return;
    let rem = this.version;
    for (let i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >>> 11) * 0x1f25);
    const bits = (this.version << 12) | rem;

    for (let i = 0; i < 18; i++) {
      const dark = ((bits >>> i) & 1) !== 0;
      const a = this.size - 11 + (i % 3);
      const b = Math.floor(i / 3);
      this.set(a, b, dark);
      this.set(b, a, dark);
    }
  }

  /**
   * Lay codewords in on the zigzag: two-module columns walked right to left,
   * alternating upward and downward, skipping function patterns. Column 6 is
   * the vertical timing pattern and is stepped over entirely.
   */
  drawCodewords(codewords: Uint8Array): void {
    let i = 0;
    for (let right = this.size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (let vert = 0; vert < this.size; vert++) {
        for (let j = 0; j < 2; j++) {
          const x = right - j;
          const upward = ((right + 1) & 2) === 0;
          const y = upward ? this.size - 1 - vert : vert;
          if (!this.reserved[y][x] && i < codewords.length * 8) {
            this.modules[y][x] = ((codewords[i >>> 3] >>> (7 - (i & 7))) & 1) !== 0;
            i++;
          }
        }
      }
    }
  }

  applyMask(mask: number): void {
    for (let y = 0; y < this.size; y++) {
      for (let x = 0; x < this.size; x++) {
        if (this.reserved[y][x]) continue;
        if (maskAt(mask, x, y)) this.modules[y][x] = !this.modules[y][x];
      }
    }
  }
}

/** Centres of the alignment patterns, which the version fixes. */
function alignmentPositions(version: number): number[] {
  if (version === 1) return [];
  const count = Math.floor(version / 7) + 2;
  // Version 32 is the one case the general formula gets wrong.
  const step = version === 32 ? 26 : Math.ceil((version * 4 + 4) / (count * 2 - 2)) * 2;
  const result = [6];
  for (let pos = version * 4 + 10; result.length < count; pos -= step) result.splice(1, 0, pos);
  return result;
}

/** The eight mask patterns. Whether module (x, y) is flipped. */
function maskAt(mask: number, x: number, y: number): boolean {
  switch (mask) {
    case 0: return (x + y) % 2 === 0;
    case 1: return y % 2 === 0;
    case 2: return x % 3 === 0;
    case 3: return (x + y) % 3 === 0;
    case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
    case 5: return ((x * y) % 2) + ((x * y) % 3) === 0;
    case 6: return (((x * y) % 2) + ((x * y) % 3)) % 2 === 0;
    default: return ((((x + y) % 2) + ((x * y) % 3)) % 2) === 0;
  }
}

/**
 * Build the symbol, trying every mask and keeping the one that scores best.
 *
 * Masking is not cosmetic: an unmasked symbol can produce large blank areas or
 * runs that imitate a finder pattern, either of which a scanner reads wrong.
 * The penalty function is the spec's proxy for how hard the result is to read.
 */
function draw(version: number, codewords: Uint8Array): QrCode {
  const matrix = new Matrix(version);
  matrix.drawFunctionPatterns();
  matrix.drawCodewords(codewords);

  let bestMask = 0;
  let bestPenalty = Infinity;
  for (let mask = 0; mask < 8; mask++) {
    matrix.applyMask(mask);
    matrix.drawFormatBits(mask);
    const penalty = penaltyScore(matrix);
    if (penalty < bestPenalty) {
      bestPenalty = penalty;
      bestMask = mask;
    }
    // Masking is its own inverse, so undo it before trying the next one.
    matrix.applyMask(mask);
  }

  matrix.applyMask(bestMask);
  matrix.drawFormatBits(bestMask);
  return { size: matrix.size, modules: matrix.modules };
}

// -- mask selection ----------------------------------------------------------

function penaltyScore(matrix: Matrix): number {
  const { size, modules } = matrix;
  let result = 0;

  // Long same-colour runs, and runs shaped like a finder pattern, in both
  // directions.
  for (let y = 0; y < size; y++) {
    let runColor = false;
    let runLength = 0;
    const history = [0, 0, 0, 0, 0, 0, 0];
    for (let x = 0; x < size; x++) {
      if (modules[y][x] === runColor) {
        runLength++;
        if (runLength === 5) result += PENALTY_N1;
        else if (runLength > 5) result++;
      } else {
        addRunToHistory(runLength, history, size);
        if (!runColor) result += countFinderLookalikes(history) * PENALTY_N3;
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    result += terminateRun(runColor, runLength, history, size) * PENALTY_N3;
  }
  for (let x = 0; x < size; x++) {
    let runColor = false;
    let runLength = 0;
    const history = [0, 0, 0, 0, 0, 0, 0];
    for (let y = 0; y < size; y++) {
      if (modules[y][x] === runColor) {
        runLength++;
        if (runLength === 5) result += PENALTY_N1;
        else if (runLength > 5) result++;
      } else {
        addRunToHistory(runLength, history, size);
        if (!runColor) result += countFinderLookalikes(history) * PENALTY_N3;
        runColor = modules[y][x];
        runLength = 1;
      }
    }
    result += terminateRun(runColor, runLength, history, size) * PENALTY_N3;
  }

  // Solid 2x2 blocks.
  for (let y = 0; y < size - 1; y++) {
    for (let x = 0; x < size - 1; x++) {
      const color = modules[y][x];
      if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) {
        result += PENALTY_N2;
      }
    }
  }

  // Imbalance between dark and light.
  let dark = 0;
  for (const row of modules) for (const cell of row) if (cell) dark++;
  const total = size * size;
  const k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
  return result + k * PENALTY_N4;
}

/** Push a finished run, treating the symbol's edge as light space. */
function addRunToHistory(runLength: number, history: number[], size: number): void {
  if (history[0] === 0) runLength += size;
  history.pop();
  history.unshift(runLength);
}

function terminateRun(runColor: boolean, runLength: number, history: number[], size: number): number {
  if (runColor) {
    addRunToHistory(runLength, history, size);
    runLength = 0;
  }
  addRunToHistory(runLength + size, history, size);
  return countFinderLookalikes(history);
}

/** The 1:1:3:1:1 ratio a scanner reads as a finder, with quiet space one side. */
function countFinderLookalikes(history: number[]): number {
  const n = history[1];
  const core = n > 0 && history[2] === n && history[3] === n * 3 && history[4] === n && history[5] === n;
  return (core && history[0] >= n * 4 && history[6] >= n ? 1 : 0)
    + (core && history[6] >= n * 4 && history[0] >= n ? 1 : 0);
}
