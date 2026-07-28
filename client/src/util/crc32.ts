/** CRC-32 (IEEE), incremental. Required by the ZIP container format. */

const TABLE = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return table;
})();

/** Feed chunks in order; seed the next call with the previous return value. */
export function crc32Update(bytes: Uint8Array, seed = 0): number {
  let c = ~seed;
  for (let i = 0; i < bytes.length; i++) c = TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

export function crc32(bytes: Uint8Array): number {
  return crc32Update(bytes, 0);
}
