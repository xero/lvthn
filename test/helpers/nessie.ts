///////////////////////////////////////////////////////////////////////////////
// NESSIE vector preprocessing helper for Serpent-256
//
// The NESSIE official test vectors use a standard big-endian byte convention.
// leviathan's Serpent uses the AES submission byte convention, which reverses the
// byte array before packing into 32-bit words. As a result, the NESSIE and
// AES submission formats are byte-order mirrors of each other:
//
//   NESSIE byte order: standard big-endian (byte 0 = MSB)
//   leviathan byte order: AES submission / reversed (byte 0 feeds the low-order
//                      position of the most-significant word)
//
// The correct leviathan-specific preprocessing is simply to REVERSE ALL BYTES of
// the key and of the plaintext before calling leviathan, and to REVERSE ALL BYTES
// of leviathan's output to obtain the NESSIE ciphertext.
//
// NOTE: The original developer's note at the NESSIE vector page describes
// "reverse word order + byte-swap each key word" plus "byte-swap each PT word"
// as preprocessing for a DIFFERENT reference C implementation (not leviathan).
// That note's key preprocessing (word-reversal + per-word byte-swap) is
// mathematically equivalent to a full byte reversal for 32-byte keys, which
// is correct. However, the note's PT preprocessing ("byte-swap each word")
// is WRONG for leviathan — leviathan requires a full byte reversal of the plaintext,
// not just a per-word byte-swap. Verified empirically against multiple NESSIE
// vector sets (Sets 1–4 and 8).
//
// This helper is intentionally self-contained — it has no dependency on the
// AES submission parsers or any other test helper.
///////////////////////////////////////////////////////////////////////////////

// ---------------------------------------------------------------------------
// Low-level utilities
// ---------------------------------------------------------------------------

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/\s/g, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < h.length; i += 2) {
    out[i >>> 1] = parseInt(h.slice(i, i + 2), 16);
  }
  return out;
}

/** Reverse all bytes in a buffer. This is the core transform for all NESSIE↔leviathan conversion. */
function reverseAll(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = bytes[bytes.length - 1 - i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Public preprocessing API
// ---------------------------------------------------------------------------

/**
 * Prepare a 256-bit NESSIE key for use with leviathan's Serpent.
 *
 * NESSIE keys are in standard big-endian notation. leviathan's Serpent init()
 * reverses input bytes before packing into 32-bit LE words (AES submission
 * convention). To convert from NESSIE to leviathan format, simply reverse the
 * entire 32-byte key array.
 *
 * This is mathematically equivalent to the original developer's note
 * ("reverse word order, then byte-swap each word"), which when applied to a
 * 32-byte sequence also produces a full byte reversal.
 *
 * @param hexKey 64 hex characters (two key lines from the file, concatenated)
 */
export const prepareNessieKey = (hexKey: string): Uint8Array => {
  return reverseAll(hexToBytes(hexKey));
};

/**
 * Prepare a NESSIE 128-bit plaintext for use with leviathan's Serpent.
 *
 * NESSIE plaintexts are in standard big-endian notation. leviathan expects
 * bytes in AES submission order (reversed). Reverse the entire 16-byte array.
 *
 * Note: the original developer's note says to "byte-swap each word in place",
 * but that instruction applies to a different reference implementation. For
 * leviathan, a full byte reversal is required (empirically verified).
 *
 * @param hexPT 32 hex characters
 */
export const prepareNessiePlaintext = (hexPT: string): Uint8Array => {
  return reverseAll(hexToBytes(hexPT));
};

/**
 * Convert leviathan's Serpent ciphertext output to NESSIE byte order for
 * comparison, or convert a NESSIE ciphertext to leviathan input for decryption.
 *
 * Same transformation as plaintext: reverse all bytes. Since reversal is its
 * own inverse, this function handles both directions.
 *
 * @param hexCT 32 hex characters
 */
export const prepareNessieCiphertext = (hexCT: string): Uint8Array => {
  return reverseAll(hexToBytes(hexCT));
};

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

export interface NessieVector {
  /** Set label from the file, e.g. "Set 1" */
  set: string;
  /** Vector number within the set */
  num: number;
  /** 256-bit key as 64 uppercase hex chars (both lines concatenated) */
  key: string;
  /** 128-bit plaintext as 32 uppercase hex chars */
  plain: string;
  /** 128-bit ciphertext as 32 uppercase hex chars */
  cipher: string;
  /**
   * Round-trip confirmation value as 32 uppercase hex chars.
   * - If `hasEncryptedField` is true: encrypt(plain) == cipher == this value.
   * - If `hasEncryptedField` is false: decrypt(cipher) == plain == this value.
   */
  roundTrip: string;
  /** True for sets using `encrypted=`; false for sets using `decrypted=`. */
  hasEncryptedField: boolean;
}

/**
 * Parse all vectors from a NESSIE Serpent-256 test vector file.
 *
 * Handles both the `decrypted=` fields (Sets 1–4) and `encrypted=` fields
 * (Sets 5–8). Sanity-checks that each vector's round-trip confirmation is
 * consistent and throws if any vector fails.
 */
export function parseNessieVectors(text: string): NessieVector[] {
  const vectors: NessieVector[] = [];
  const lines = text.split(/\r?\n/);

  let current: Partial<NessieVector> | null = null;
  let keyPart1: string | null = null;
  let awaitingKeyLine2 = false;

  const finalize = () => {
    if (current && current.key && current.plain && current.cipher && current.roundTrip !== undefined) {
      vectors.push(current as NessieVector);
    }
    current = null;
    keyPart1 = null;
    awaitingKeyLine2 = false;
  };

  for (const line of lines) {
    const trimmed = line.trim();

    // "Set N, vector# M:" — note: some entries have no space before the number
    // e.g. "Set 3, vector#254:" vs "Set 1, vector#  0:"
    const setMatch = trimmed.match(/^(Set \d+), vector#\s*(\d+):$/);
    if (setMatch) {
      finalize();
      current = {
        set: setMatch[1],
        num: parseInt(setMatch[2], 10),
        hasEncryptedField: false,
      };
      continue;
    }

    if (!current) continue;

    if (trimmed.startsWith('key=')) {
      keyPart1 = trimmed.slice(4).replace(/\s/g, '').toUpperCase();
      awaitingKeyLine2 = true;
      continue;
    }

    // Second line of the two-line key (pure hex after leading whitespace).
    // If the next line is NOT pure hex, the key was complete on one line
    // (e.g., 128-bit key = 32 hex chars). Fall through to process the
    // current line as a regular field in that case.
    if (awaitingKeyLine2) {
      if (trimmed.length > 0 && /^[0-9A-Fa-f]+$/.test(trimmed)) {
        current.key = keyPart1! + trimmed.toUpperCase();
        awaitingKeyLine2 = false;
        continue;
      } else {
        // Single-line key (128- or 192-bit key)
        current.key = keyPart1!;
        awaitingKeyLine2 = false;
        // Fall through to parse this line as a normal field
      }
    }

    if (trimmed.startsWith('plain=')) {
      current.plain = trimmed.slice(6).toUpperCase();
      continue;
    }
    if (trimmed.startsWith('cipher=')) {
      current.cipher = trimmed.slice(7).toUpperCase();
      continue;
    }
    if (trimmed.startsWith('decrypted=')) {
      current.roundTrip = trimmed.slice(10).toUpperCase();
      current.hasEncryptedField = false;
      continue;
    }
    if (trimmed.startsWith('encrypted=')) {
      current.roundTrip = trimmed.slice(10).toUpperCase();
      current.hasEncryptedField = true;
      continue;
    }
    // Ignore "Iterated N times=..." lines and blank lines
  }

  finalize();

  // Sanity check: round-trip confirmation must be consistent
  for (const v of vectors) {
    const label = `${v.set}, vector# ${v.num}`;
    if (v.hasEncryptedField) {
      // Sets 5–8: encrypted = encrypt(plain) = cipher
      if (v.roundTrip !== v.cipher) {
        throw new Error(`Parser sanity check failed at ${label}: encrypted (${v.roundTrip}) !== cipher (${v.cipher})`);
      }
    } else {
      // Sets 1–4: decrypted = decrypt(cipher) = plain
      if (v.roundTrip !== v.plain) {
        throw new Error(`Parser sanity check failed at ${label}: decrypted (${v.roundTrip}) !== plain (${v.plain})`);
      }
    }
  }

  return vectors;
}
