/**
 * Passphrase generation and strength estimation.
 *
 * The passphrase is the single security parameter the user controls: every
 * other defence in this app is downstream of it. An eavesdropper who captures a
 * transfer can grind candidate passphrases offline, so the UI has an obligation
 * to say plainly when one is too weak and to make a strong one one tap away.
 *
 * Generated passphrases are words rather than random characters because they
 * have to be typed on a second device, usually a phone, often from memory
 * across a room.
 */

import { randomBytes } from '../crypto/env.js';

/** 256 short, unambiguous, easily typed words. 8 bits of entropy each. */
const WORDS = `
able acid aged also arch arms army atom aunt aware axis bake
bald band bank barn base bath bead beam bean bear beat beef
bell belt bend best bike bind bird bite blue boat bold bolt
bond bone book boot born boss both bowl bulk bull burn bush
busy cafe cage cake calm camp cane cape card care cart case
cash cast cave cell chef chin chip city clay clip club coal
coat code coil coin cold colt comb cook cool copy cord core
cork corn cost cove crab crew crop crow cube cure curl dark
dart dash data dawn deal dear debt deck deep deer dent desk
dial dice dime dine dish dive dock does dome door dose dove
down drag draw drew drop drum dual duck dusk dust duty each
earn ease east easy echo edge exit face fact fade fair fall
fame farm fast fate fawn fear feed feel fern feud file fill
film find fine fire firm fish fist five flag flat flax fled
flew flip flow foam foil fold folk font food foot ford fork
form fort four fowl free frog fuel full fund fuse gain gala
game gate gave gear gene gift girl give glad glow goal goat
gold golf gone good gown grab gray grew grid grim grip grow
gulf gust hair half hall halt hand hang harm harp haul have
hawk haze head heal heap hear heat heir held helm herb herd
hero hide high hill hint hire hive hold hole holy home hood
hoof hook hope horn
`
  .trim()
  .split(/\s+/);

/** ~8 bits per word; 6 words is 48 bits, on top of Argon2id. */
const DEFAULT_WORD_COUNT = 6;

/** Exactly 256 words means one random byte selects one word with no bias. */
export const WORD_LIST_SIZE = 256;
if (WORDS.length !== WORD_LIST_SIZE) {
  throw new Error(`word list must hold exactly ${WORD_LIST_SIZE} entries, found ${WORDS.length}`);
}

/** Membership test for the strength estimator; see estimateStrength. */
const WORD_SET = new Set(WORDS);

export function generatePassphrase(words = DEFAULT_WORD_COUNT): string {
  return Array.from(randomBytes(words), (byte) => WORDS[byte]!).join('-');
}

export interface Strength {
  /** 0-4, for the segmented bar. */
  score: number;
  bits: number;
  label: string;
  advice: string;
}

/**
 * A deliberately conservative entropy estimate. It is not a password cracker,
 * and it errs toward calling things weak, because the failure mode of
 * over-praising a passphrase here is somebody's file being decrypted.
 */
export function estimateStrength(passphrase: string): Strength {
  if (!passphrase) {
    return { score: 0, bits: 0, label: 'Empty', advice: 'A passphrase is required.' };
  }

  /**
   * "Generated" means *our* format, which is only true if every token is
   * actually one of our words.
   *
   * Shape alone is not evidence of entropy. Matching any hyphenated lowercase
   * string and paying 8 bits a token credited "a-a-a-a-a-a" with 48 bits, and a
   * ten-token string of repeats with 80 - reported to the user as "Strong". For
   * the one control this whole app rests on, over-praising is the failure that
   * matters, so an unrecognised token drops the passphrase to the conservative
   * character-based estimate below.
   */
  const tokens = passphrase.split('-');
  const generated = tokens.length >= 4 && tokens.every((token) => WORD_SET.has(token));
  let bits: number;

  if (generated) {
    // Our own format: count words at 8 bits each.
    bits = tokens.length * 8;
  } else {
    let alphabet = 0;
    if (/[a-z]/.test(passphrase)) alphabet += 26;
    if (/[A-Z]/.test(passphrase)) alphabet += 26;
    if (/[0-9]/.test(passphrase)) alphabet += 10;
    if (/[^a-zA-Z0-9]/.test(passphrase)) alphabet += 32;

    // Repeated characters carry far less entropy than their count suggests.
    const unique = new Set(passphrase).size;
    const effectiveLength = passphrase.length * Math.min(1, (unique / passphrase.length) * 1.4);
    bits = Math.log2(Math.max(alphabet, 2)) * effectiveLength;

    // Common shapes a wordlist attack finds immediately.
    if (/^[a-zA-Z]+[0-9]{0,4}[!?.]?$/.test(passphrase) && passphrase.length < 14) bits *= 0.55;
    if (/(.)\1{2,}/.test(passphrase)) bits *= 0.8;
    if (/^(19|20)\d{2}$/.test(passphrase)) bits = 8;
  }

  bits = Math.round(bits);

  if (bits < 32) {
    return {
      score: 1, bits, label: 'Too weak',
      advice: 'Someone who captures this transfer could crack it. Use the suggested passphrase.',
    };
  }
  if (bits < 50) {
    return {
      score: 2, bits, label: 'Weak',
      advice: 'Workable for low-stakes files. Add more words for anything sensitive.',
    };
  }
  if (bits < 70) {
    return { score: 3, bits, label: 'Good', advice: 'Strong enough for most things.' };
  }
  return { score: 4, bits, label: 'Strong', advice: 'Strong. Send it over a different channel than the code.' };
}
