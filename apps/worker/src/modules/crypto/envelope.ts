import { base64ToBytes } from "@/lib";
import { decryptGCMBytes, encryptGCMBytes } from "./aes";

const KEY_SIZE = 32;

/**
 * Generates a new random 32-byte data-encryption key.
 *
 * @returns Cryptographically secure DEK bytes.
 */
export function generateDEK(): Uint8Array {
  const crypto = globalThis.crypto;
  return crypto.getRandomValues(new Uint8Array(KEY_SIZE));
}

/**
 * Wraps a DEK with the worker KEK.
 *
 * @param dek - Plain DEK bytes.
 * @param kek - 32-byte KEK bytes.
 * @returns Encrypted DEK blob.
 */
export async function wrapKey(dek: Uint8Array, kek: Uint8Array): Promise<Uint8Array> {
  return encryptGCMBytes(dek, kek);
}

/**
 * Unwraps a previously wrapped DEK with the worker KEK.
 *
 * @param wrappedKey - Encrypted DEK blob.
 * @param kek - 32-byte KEK bytes.
 * @returns Plain DEK bytes.
 */
export async function unwrapKey(wrappedKey: Uint8Array, kek: Uint8Array): Promise<Uint8Array> {
  const decrypted = await decryptGCMBytes(wrappedKey, kek);
  if (decrypted.length === KEY_SIZE) {
    const dek = decrypted.slice();
    decrypted.fill(0);
    return dek;
  }

  try {
    const legacyText = new TextDecoder().decode(decrypted);
    return base64ToBytes(legacyText);
  } finally {
    decrypted.fill(0);
  }
}