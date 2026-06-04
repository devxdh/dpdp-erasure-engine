import { fail, CODE } from "@/errors";
import { base64ToBytes, bytesToHex, copyBytes, hexToBytes } from "@/lib";

const KEY_LENGTH = 32;
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function ensureKeyLength(bytes: Uint8Array, keyName: string): Uint8Array {
  if (bytes.length === KEY_LENGTH) {
    return new Uint8Array(bytes);
  }

  fail({
    code: CODE.SECRET_ENV_INVALID,
    data: { keyName, KEY_LENGTH },
    context: { keyName },
  })
}

export function normalizeBase64(value: string): string {
  return value.trim().replace(/-/g, "+").replace(/_/g, "/");
}

/**
 * Decodes configured key material from raw bytes or textual hex/base64.
 *
 * @param rawValue - Runtime key value returned by env, file, KMS, Secret Manager, or Vault.
 * @param keyName - Human-readable key label used in fail-closed error details.
 * @returns A defensive copy of the 32-byte key.
 * @throws {WorkerError} If the value cannot be decoded into a 256-bit key.
 */
export function decodeKeyMaterial(rawValue: string | Uint8Array, keyName: string): Uint8Array {
  if (rawValue instanceof Uint8Array) {
    if (rawValue.length === KEY_LENGTH) {
      return new Uint8Array(rawValue);
    }
    rawValue = textDecoder.decode(rawValue);
  }

  const value = rawValue.trim();
  if (value.length === 0) {
    fail({
      code: CODE.SECRET_ENV_MISSING,
      data: { keyName },
      context: { keyName }
    })
  }

  const normalizedHex = value.startsWith("hex:") ? value.slice(4) : value;
  if (/^[0-9a-fA-F]+$/.test(normalizedHex) && normalizedHex.length === KEY_LENGTH * 2) {
    return hexToBytes(normalizedHex);
  }

  const normalizedBase64 = value.startsWith("base64:") ? value.slice(7) : value;
  try {
    return ensureKeyLength(base64ToBytes(normalizeBase64(normalizedBase64)), keyName)
  } catch (error) {
    fail({
      code: CODE.SECRET_ENV_INVALID,
      data: { keyName, KEY_LENGTH },
      context: { keyName }
    })
  }
}

export async function sha256Hex(value: string): Promise<string> {
  const bytes = textEncoder.encode(value);
  // Ensure we pass a regular ArrayBuffer, as SharedArrayBuffer is not allowed for crypto.
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer as ArrayBuffer);
  return bytesToHex(new Uint8Array(digest));
}

export function seedSecret(secretAccessKey: string): Uint8Array {
  return copyBytes(textEncoder.encode(`AWS4${secretAccessKey}`));
}

export async function hmacSha256(key: Uint8Array, value: string | Uint8Array): Promise<Uint8Array> {
  const keyBytes = key.slice();
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = typeof value === "string" ? textEncoder.encode(value).slice() : value.slice();
  const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, data.buffer as ArrayBuffer);
  return new Uint8Array(signature);
}