/**
 * The STREAM sealer/opener pair - the layer that actually encrypts file bytes.
 *
 * Both live transfers and stored transfers use this identical container, so a
 * blob captured off the wire and a blob sitting on the server are the same
 * thing and are opened by the same code path.
 */

import {
  createAead, preferredSuite, wipe, TAG_LEN,
  type AeadContext, type SuiteId,
} from './aead.js';
import {
  chunkAad, chunkNonce, decodeMeta, encodeHeader, encodeMeta,
  DEFAULT_CHUNK_SIZE, FORMAT_VERSION, HEADER_LEN, KDF_ARGON2ID, META_BLOCK_LEN,
  NONCE_PREFIX_FIELD_LEN,
  type FileMeta, type Header,
} from './format.js';
import { ARGON2_DEFAULTS, deriveMaster, LABEL_FILE_KEY, SALT_LEN, subkey, type KdfParams } from './kdf.js';
import { randomBytes } from './env.js';

/** u32 counter space; at 1 MiB chunks that is 4 PiB, far beyond our 2 GB cap. */
const MAX_COUNTER = 0xffffffff;

export interface SealerOptions {
  /** Pre-derived master secret. Supply this to reuse a KDF pass. */
  master?: Uint8Array;
  /** Or a passphrase, and we derive. */
  passphrase?: string;
  suite?: SuiteId;
  chunkSize?: number;
  compressed?: boolean;
  kdfParams?: KdfParams;
  /** Fixed salt (live sessions derive it from the room code). */
  salt?: Uint8Array;
}

export class ChunkSealer {
  private counter = 0;
  private finished = false;

  private constructor(
    readonly headerBytes: Uint8Array,
    readonly fields: Header,
    private aead: AeadContext,
    readonly master: Uint8Array,
  ) {}

  static async create(opts: SealerOptions): Promise<ChunkSealer> {
    const suite = opts.suite ?? preferredSuite();
    const chunkSize = opts.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const kdf = opts.kdfParams ?? ARGON2_DEFAULTS;
    const salt = opts.salt ?? randomBytes(SALT_LEN);

    let master = opts.master;
    if (!master) {
      if (!opts.passphrase) throw new Error('Sealer needs a passphrase or a master key');
      master = await deriveMaster(opts.passphrase, salt, kdf);
    }

    const fields: Header = {
      version: FORMAT_VERSION,
      suite,
      kdfId: KDF_ARGON2ID,
      compressed: !!opts.compressed,
      kdf,
      salt,
      noncePrefix: randomBytes(NONCE_PREFIX_FIELD_LEN),
      chunkSize,
    };
    const headerBytes = encodeHeader(fields);

    const fileKey = subkey(master, LABEL_FILE_KEY);
    const aead = await createAead(suite, fileKey);
    wipe(fileKey);

    return new ChunkSealer(headerBytes, fields, aead, master);
  }

  /** Seal chunk 0, the encrypted metadata. Must be called first. */
  async sealMeta(meta: FileMeta): Promise<Uint8Array> {
    if (this.counter !== 0) throw new Error('Metadata must be the first sealed chunk');
    return this.seal(encodeMeta(meta), false);
  }

  async seal(plaintext: Uint8Array, isFinal: boolean): Promise<Uint8Array> {
    if (this.finished) throw new Error('Sealer already finalised');
    if (this.counter > MAX_COUNTER) throw new Error('Chunk counter exhausted');
    if (plaintext.length > this.fields.chunkSize) {
      throw new Error('Chunk exceeds the declared chunk size');
    }
    const i = this.counter++;
    const out = await this.aead.seal(
      chunkNonce(this.fields.noncePrefix, this.fields.suite, i, isFinal),
      plaintext,
      chunkAad(this.headerBytes, i, isFinal),
    );
    if (isFinal) this.finished = true;
    return out;
  }

  destroy(): void {
    this.aead.destroy();
    wipe(this.master);
  }
}

export class ChunkOpener {
  private counter = 0;
  private finished = false;

  private constructor(
    readonly fields: Header,
    private headerBytes: Uint8Array,
    private aead: AeadContext,
    readonly master: Uint8Array,
  ) {}

  static async create(
    fields: Header,
    headerBytes: Uint8Array,
    master: Uint8Array,
  ): Promise<ChunkOpener> {
    const fileKey = subkey(master, LABEL_FILE_KEY);
    const aead = await createAead(fields.suite, fileKey);
    wipe(fileKey);
    return new ChunkOpener(fields, headerBytes.slice(0, HEADER_LEN), aead, master);
  }

  /**
   * Open the next chunk. A wrong passphrase, a tampered chunk, a reordered
   * chunk or a truncated stream all surface here as an AEAD failure - there is
   * no separate "wrong password" check to get wrong.
   */
  async open(ciphertext: Uint8Array, isFinal: boolean): Promise<Uint8Array> {
    if (this.finished) throw new Error('Stream already ended');
    if (ciphertext.length < TAG_LEN) throw new Error('Chunk shorter than its authentication tag');
    const i = this.counter++;
    let out: Uint8Array;
    try {
      out = await this.aead.open(
        chunkNonce(this.fields.noncePrefix, this.fields.suite, i, isFinal),
        ciphertext,
        chunkAad(this.headerBytes, i, isFinal),
      );
    } catch {
      throw new DecryptionError(i);
    }
    if (isFinal) this.finished = true;
    return out;
  }

  async openMeta(ciphertext: Uint8Array): Promise<FileMeta> {
    if (this.counter !== 0) throw new Error('Metadata must be the first chunk opened');
    return decodeMeta(await this.open(ciphertext, false));
  }

  /** True once the chunk flagged final has been opened. */
  get complete(): boolean { return this.finished; }

  destroy(): void {
    this.aead.destroy();
    wipe(this.master);
  }
}

/**
 * Authentication failure. Chunk 0 failing almost always means a wrong
 * passphrase; a later chunk failing means corruption or tampering, and the
 * message says so, because the two call for very different user reactions.
 */
export class DecryptionError extends Error {
  constructor(readonly chunkIndex: number) {
    super(
      chunkIndex === 0
        ? 'Could not decrypt. The passphrase is wrong, or this transfer was altered.'
        : `Authentication failed on chunk ${chunkIndex}. The data was corrupted or tampered with in transit.`,
    );
    this.name = 'DecryptionError';
  }
}

/**
 * Exact serialized length for an uncompressed payload. Used to declare the
 * upload size up front; with compression enabled the length is unknowable in
 * advance and the caller declares the plaintext size as a hint instead.
 */
export function sealedTotalLength(plaintextLength: number, chunkSize: number): number {
  const fullChunks = Math.floor(plaintextLength / chunkSize);
  const remainder = plaintextLength - fullChunks * chunkSize;
  // rechunk always emits a final chunk, even an empty one for a zero-byte file.
  const hasShortFinal = remainder > 0 || plaintextLength === 0;
  const dataBytes = fullChunks * (chunkSize + TAG_LEN) + (hasShortFinal ? remainder + TAG_LEN : 0);
  return HEADER_LEN + (META_BLOCK_LEN + TAG_LEN) + dataBytes;
}
