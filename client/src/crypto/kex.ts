/**
 * Hybrid post-quantum key exchange for live transfers.
 *
 * Shape: X25519 + ML-KEM-768 (FIPS 203), concatenated into one HKDF, in the
 * same spirit as TLS's X25519MLKEM768. The classical half keeps the exchange at
 * least as strong as X25519 if a flaw is found in the lattice scheme; the
 * ML-KEM half defends against harvest-now-decrypt-later. An attacker must break
 * *both* to recover the session key.
 *
 * Authentication: an unauthenticated KEM exchange over a server-brokered
 * channel is trivially MITM-able by that server, so the transcript is
 * authenticated with an HMAC keyed by the Argon2id-derived passphrase secret
 * that both peers already share. The server never learns the passphrase and
 * cannot forge the tag.
 *
 *   HELLO     I->R  ecPubI, kemPubI, salt, kdf params, suite
 *   RESPONSE  R->I  ecPubR, kemCt, macR
 *   CONFIRM   I->R  macI
 *
 *   transcript    = SHA-256(label || suite || salt || kdf || ecPubI || kemPubI || ecPubR || kemCt)
 *   sessionSecret = HKDF(ikm = ssEC || ssPQ, salt = transcript, info = "qsft/v1/session")
 *   macR/macI     = HMAC(authKey, role-label || transcript)
 *
 * Residual risk, stated plainly: because the authenticator is keyed by a
 * human-chosen passphrase, an active MITM who completes a handshake can take
 * the captured MAC offline and grind candidate passphrases against it. Argon2id
 * makes each guess expensive rather than impossible. This is inherent to
 * authenticating with a low-entropy shared secret and no PAKE. The short
 * authentication string below closes the gap for anyone who compares it out of
 * band, and the payload underneath stays independently encrypted regardless.
 */

import { x25519 } from '@noble/curves/ed25519.js';
import { ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import { hkdf } from '@noble/hashes/hkdf.js';

import { randomBytes } from './env.js';
import { wipe, preferredSuite, suiteSpec, type SuiteId } from './aead.js';
import { assertKdfParams, LABEL_SESSION_AUTH, subkey, type KdfParams } from './kdf.js';
import {
  concat, fromBase64Exact, lengthPrefixed, timingSafeEqual, toBase64, u32be, utf8,
} from '../util/bytes.js';

export const KEX_VERSION = 1;

const EC_PUB_LEN = 32;
const EC_PRIV_LEN = 32;
const KEM_PUB_LEN = 1184;
const KEM_CT_LEN = 1088;
const KEM_SEED_LEN = 64;
const KEM_ENCAP_SEED_LEN = 32;

const LABEL_TRANSCRIPT = 'qsft/v1/kex';
const LABEL_SESSION = 'qsft/v1/session';
const LABEL_MAC_RESPONDER = 'qsft/v1/kex/responder';
const LABEL_MAC_INITIATOR = 'qsft/v1/kex/initiator';

export interface HelloMessage {
  v: number;
  suite: number;
  salt: string;
  kdf: { m: number; t: number; p: number };
  ecPub: string;
  kemPub: string;
}

export interface ResponseMessage {
  v: number;
  ecPub: string;
  kemCt: string;
  mac: string;
}

export interface ConfirmMessage {
  v: number;
  mac: string;
}

/** Everything a live transfer needs once the handshake completes. */
export interface SessionKeys {
  /** 32-byte session secret; channel keys are HKDF labels off this. */
  secret: Uint8Array;
  transcript: Uint8Array;
  suite: SuiteId;
}

export class HandshakeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'HandshakeError';
  }
}

function buildTranscript(
  suite: number,
  salt: Uint8Array,
  kdf: KdfParams,
  ecPubI: Uint8Array,
  kemPubI: Uint8Array,
  ecPubR: Uint8Array,
  kemCt: Uint8Array,
): Uint8Array {
  return sha256(concat(
    utf8(LABEL_TRANSCRIPT),
    new Uint8Array([KEX_VERSION, suite]),
    lengthPrefixed(salt),
    u32be(kdf.memKiB),
    new Uint8Array([kdf.timeCost, kdf.lanes]),
    lengthPrefixed(ecPubI),
    lengthPrefixed(kemPubI),
    lengthPrefixed(ecPubR),
    lengthPrefixed(kemCt),
  ));
}

/**
 * Combine the classical and post-quantum shared secrets. Concatenating both
 * into the HKDF input keying material is what makes this a true hybrid: the
 * output is secure as long as at least one half held.
 */
function deriveSession(ssEc: Uint8Array, ssPq: Uint8Array, transcript: Uint8Array): Uint8Array {
  const ikm = concat(ssEc, ssPq);
  const secret = hkdf(sha256, ikm, transcript, utf8(LABEL_SESSION), 32);
  wipe(ikm);
  wipe(ssEc);
  wipe(ssPq);
  return secret;
}

function macFor(authKey: Uint8Array, label: string, transcript: Uint8Array): Uint8Array {
  return hmac(sha256, authKey, concat(utf8(label), transcript));
}

function ecdh(privateKey: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privateKey, peerPublic);
  } catch {
    throw new HandshakeError('Peer sent an invalid X25519 public key');
  }
  // Reject the all-zero shared secret produced by small-order points.
  if (shared.every((b) => b === 0)) {
    throw new HandshakeError('Peer sent a degenerate X25519 public key');
  }
  return shared;
}

/**
 * HELLO is unauthenticated when we read it - the MAC that proves the sender
 * holds the passphrase can only be checked *after* we have derived a key with
 * these very parameters. So they are peer-controlled input to an expensive
 * operation, and the bound has to hold before we spend anything on them.
 */
function parseKdf(raw: unknown): KdfParams {
  const k = raw as { m?: unknown; t?: unknown; p?: unknown } | undefined;
  const params = { memKiB: Number(k?.m), timeCost: Number(k?.t), lanes: Number(k?.p) };
  try {
    assertKdfParams(params);
  } catch (err) {
    throw new HandshakeError(`Peer proposed unusable Argon2 parameters: ${(err as Error).message}`);
  }
  return params;
}

// ---------------------------------------------------------------------------
// Initiator (the sending device)
// ---------------------------------------------------------------------------

export class Initiator {
  private ecPriv: Uint8Array;
  private kemPriv: Uint8Array;
  private constructor(
    readonly hello: HelloMessage,
    private ecPub: Uint8Array,
    private kemPub: Uint8Array,
    ecPriv: Uint8Array,
    kemPriv: Uint8Array,
    private salt: Uint8Array,
    private kdf: KdfParams,
    private suite: SuiteId,
    private authKey: Uint8Array,
  ) {
    this.ecPriv = ecPriv;
    this.kemPriv = kemPriv;
  }

  /**
   * @param master Argon2id output for (passphrase, salt) - already derived so
   *               the expensive pass runs once per transfer.
   */
  static start(master: Uint8Array, salt: Uint8Array, kdf: KdfParams, suite: SuiteId = preferredSuite()): Initiator {
    suiteSpec(suite);
    const ecPriv = randomBytes(EC_PRIV_LEN);
    const ecPub = x25519.getPublicKey(ecPriv);
    const kem = ml_kem768.keygen(randomBytes(KEM_SEED_LEN));

    const hello: HelloMessage = {
      v: KEX_VERSION,
      suite,
      salt: toBase64(salt),
      kdf: { m: kdf.memKiB, t: kdf.timeCost, p: kdf.lanes },
      ecPub: toBase64(ecPub),
      kemPub: toBase64(kem.publicKey),
    };

    return new Initiator(
      hello, ecPub, kem.publicKey, ecPriv, kem.secretKey,
      salt, kdf, suite, subkey(master, LABEL_SESSION_AUTH),
    );
  }

  /** Verify the responder's MAC, derive the session, and produce our CONFIRM. */
  accept(response: ResponseMessage): { session: SessionKeys; confirm: ConfirmMessage } {
    if (response?.v !== KEX_VERSION) throw new HandshakeError('Peer speaks a different handshake version');
    const ecPubR = fromBase64Exact(response.ecPub, EC_PUB_LEN, 'ecPub');
    const kemCt = fromBase64Exact(response.kemCt, KEM_CT_LEN, 'kemCt');
    const macR = fromBase64Exact(response.mac, 32, 'mac');

    const transcript = buildTranscript(
      this.suite, this.salt, this.kdf, this.ecPub, this.kemPub, ecPubR, kemCt,
    );

    const expected = macFor(this.authKey, LABEL_MAC_RESPONDER, transcript);
    if (!timingSafeEqual(expected, macR)) {
      throw new HandshakeError(
        'Handshake authentication failed. Either the passphrases do not match, '
        + 'or someone is intercepting this connection.',
      );
    }

    const ssEc = ecdh(this.ecPriv, ecPubR);
    let ssPq: Uint8Array;
    try {
      ssPq = ml_kem768.decapsulate(kemCt, this.kemPriv);
    } catch {
      throw new HandshakeError('ML-KEM decapsulation failed');
    }

    const secret = deriveSession(ssEc, ssPq, transcript);
    const confirm: ConfirmMessage = {
      v: KEX_VERSION,
      mac: toBase64(macFor(this.authKey, LABEL_MAC_INITIATOR, transcript)),
    };
    this.destroy();
    return { session: { secret, transcript, suite: this.suite }, confirm };
  }

  destroy(): void {
    wipe(this.ecPriv);
    wipe(this.kemPriv);
    wipe(this.authKey);
  }
}

// ---------------------------------------------------------------------------
// Responder (the receiving device)
// ---------------------------------------------------------------------------

export class Responder {
  private constructor(
    readonly response: ResponseMessage,
    readonly session: SessionKeys,
    private expectedInitiatorMac: Uint8Array,
    private authKey: Uint8Array,
  ) {}

  /** Parse HELLO enough to learn the salt and KDF params before deriving the master. */
  static parseHello(hello: HelloMessage): { salt: Uint8Array; kdf: KdfParams; suite: SuiteId } {
    if (hello?.v !== KEX_VERSION) throw new HandshakeError('Peer speaks a different handshake version');
    const suite = hello.suite as SuiteId;
    suiteSpec(suite);
    return {
      salt: fromBase64Exact(hello.salt, 16, 'salt'),
      kdf: parseKdf(hello.kdf),
      suite,
    };
  }

  static respond(hello: HelloMessage, master: Uint8Array): Responder {
    const { salt, kdf, suite } = Responder.parseHello(hello);
    const ecPubI = fromBase64Exact(hello.ecPub, EC_PUB_LEN, 'ecPub');
    const kemPubI = fromBase64Exact(hello.kemPub, KEM_PUB_LEN, 'kemPub');

    const ecPriv = randomBytes(EC_PRIV_LEN);
    const ecPubR = x25519.getPublicKey(ecPriv);

    let encap: { cipherText: Uint8Array; sharedSecret: Uint8Array };
    try {
      encap = ml_kem768.encapsulate(kemPubI, randomBytes(KEM_ENCAP_SEED_LEN));
    } catch {
      throw new HandshakeError('Peer sent an invalid ML-KEM public key');
    }

    const transcript = buildTranscript(suite, salt, kdf, ecPubI, kemPubI, ecPubR, encap.cipherText);
    const ssEc = ecdh(ecPriv, ecPubI);
    wipe(ecPriv);

    const secret = deriveSession(ssEc, encap.sharedSecret, transcript);
    const authKey = subkey(master, LABEL_SESSION_AUTH);

    const response: ResponseMessage = {
      v: KEX_VERSION,
      ecPub: toBase64(ecPubR),
      kemCt: toBase64(encap.cipherText),
      mac: toBase64(macFor(authKey, LABEL_MAC_RESPONDER, transcript)),
    };

    return new Responder(
      response,
      { secret, transcript, suite },
      macFor(authKey, LABEL_MAC_INITIATOR, transcript),
      authKey,
    );
  }

  /**
   * Verify CONFIRM. Until this passes we know the peer holds the passphrase
   * only if they could produce it - so no payload is accepted before it.
   */
  verifyConfirm(confirm: ConfirmMessage): void {
    if (confirm?.v !== KEX_VERSION) throw new HandshakeError('Peer speaks a different handshake version');
    const mac = fromBase64Exact(confirm.mac, 32, 'mac');
    if (!timingSafeEqual(this.expectedInitiatorMac, mac)) {
      throw new HandshakeError(
        'Sender failed authentication. Either the passphrases do not match, '
        + 'or someone is intercepting this connection.',
      );
    }
    wipe(this.authKey);
  }
}
