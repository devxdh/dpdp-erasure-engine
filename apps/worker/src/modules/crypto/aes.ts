import { fail } from "@/errors";


const IV_LENGTH = 12; // 96-bit IV is the industry standard for GCM.
const KEY_LENGTH = 32; // 256-bit key for AES-256.
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function assertAesKeyLength(rawKey: Uint8Array) {
  if (rawKey.length !== KEY_LENGTH) {
    fail({
      code: "CRYPTO_INVALID_KEY_LENGTH",
      title: "Invalid AES key length",
      detail: `Invalid key length. Expected ${KEY_LENGTH} bytes for AES-256, got ${rawKey.length} bytes.`,
      category: "crypto",
      retryable: false,
    });
  }
}

function toOwnedArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

async function importAesKey(rawKey: Uint8Array, usages: readonly ("encrypt" | "decrypt")[]): Promise<CryptoKey> {
  assertAesKeyLength(rawKey);

  const keyBytes = rawKey.slice();
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      toOwnedArrayBuffer(keyBytes),
      "AES-GCM",
      false,
      [...usages]
    );
  } finally {
    keyBytes.fill(0);
  }
}

/**
 * Encrypts raw bytes using AES-256-GCM.
 *
 * This overload exists for sensitive call sites that need direct control over plaintext buffer
 * lifecycle so the caller can explicitly wipe the source bytes after encryption.
 *
 * @param plaintext - Raw plaintext bytes to encrypt.
 * @param rawKey - 32-byte symmetric key.
 * @returns Combined buffer in `IV || ciphertext+tag` format.
 * @throws {WorkerError} When key length is invalid.
 */
export async function encryptGCMBytes(plaintext: Uint8Array, rawKey: Uint8Array): Promise<Uint8Array> {
  const key = await importAesKey(rawKey, ["encrypt"]);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const ciphertextBuffer = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    toOwnedArrayBuffer(plaintext)
  );

  const combined = new Uint8Array(iv.length + ciphertextBuffer.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(ciphertextBuffer), iv.length);

  return combined;
}

/**
 * Encrypts UTF-8 plaintext using AES-256-GCM.
 *
 * @param plaintext - Text payload to encrypt.
 * @param rawKey - 32-byte symmetric key.
 * @returns Combined buffer in `IV || ciphertext+tag` format.
 * @throws {WorkerError} When key length is invalid.
 */
export async function encryptGCM(plaintext: string, rawKey: Uint8Array): Promise<Uint8Array> {
  const plaintextBytes = textEncoder.encode(plaintext);
  try {
    return await encryptGCMBytes(plaintextBytes, rawKey);
  } finally {
    plaintextBytes.fill(0);
  }
}

/**
 * Decrypts a buffer in `IV || ciphertext+tag` format.
 *
 * Returns raw bytes so high-sensitivity callers can zero the decrypted buffer immediately after
 * parsing, instead of leaving plaintext in immutable JS string storage.
 *
 * @param combined - Combined encrypted payload produced by `encryptGCM`.
 * @param rawKey - 32-byte symmetric key.
 * @returns Decrypted plaintext bytes.
 * @throws {WorkerError} When key/ciphertext is invalid or integrity verification fails.
 */
export async function decryptGCMBytes(combined: Uint8Array, rawKey: Uint8Array): Promise<Uint8Array> {
  assertAesKeyLength(rawKey);

  if (combined.length < IV_LENGTH + 16) {
    fail({
      code: "CRYPTO_INVALID_CIPHERTEXT",
      title: "Invalid ciphertext",
      detail: "Invalid ciphertext. Too short to be a valid AES-GCM payload.",
      category: "crypto",
      retryable: false,
    });
  }

  const crypto = globalThis.crypto;

  const iv = combined.slice(0, IV_LENGTH);
  const ciphertext = combined.slice(IV_LENGTH);

  const key = await importAesKey(rawKey, ["decrypt"]);

  let decryptBuffer: ArrayBuffer;
  try {
    decryptBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      toOwnedArrayBuffer(ciphertext)
    );
  } catch (error) {
    fail({
      code: "CRYPTO_INTEGRITY_FAILURE",
      title: "AES-GCM integrity verification failed",
      detail: "Decryption failed because the ciphertext or auth tag was corrupted.",
      category: "crypto",
      retryable: false,
      cause: error,
    });
  }

  return new Uint8Array(decryptBuffer);
}

/**
 * Decrypts a buffer in `IV || ciphertext+tag` format` and decodes it as UTF-8 text.
 *
 * Prefer `decryptGCMBytes` when handling raw PII so the caller can explicitly wipe the plaintext
 * buffer after use.
 *
 * @param combined - Combined encrypted payload produced by `encryptGCM`.
 * @param rawKey - 32-byte symmetric key.
 * @returns Decrypted UTF-8 plaintext.
 * @throws {WorkerError} When key/ciphertext is invalid or integrity verification fails.
 */
export async function decryptGCM(combined: Uint8Array, rawKey: Uint8Array): Promise<string> {
  const decryptedBytes = await decryptGCMBytes(combined, rawKey);
  try {
    return textDecoder.decode(decryptedBytes);
  } finally {
    decryptedBytes.fill(0);
  }
}