import { bytesToHex } from "@/lib";

const textEncoder = new TextEncoder();

function copyToOwnedBytes(bytes: Uint8Array): Uint8Array {
  const owned = new Uint8Array(bytes.byteLength);
  owned.set(bytes);
  return owned;
}

/**
 * Imports HMAC-SHA256 key material once for repeated pseudonymization operations.
 *
 * @param keyMaterial - Raw key bytes or a legacy string secret.
 * @returns Web Crypto HMAC key suitable for repeated `sign` calls.
 */
export async function importHmacKey(keyMaterial: Uint8Array | string): Promise<CryptoKey> {
  const rawKey = typeof keyMaterial === "string"
    ? copyToOwnedBytes(textEncoder.encode(keyMaterial))
    : copyToOwnedBytes(keyMaterial);
  const keyBuffer = rawKey.buffer.slice(rawKey.byteOffset, rawKey.byteOffset + rawKey.byteLength) as ArrayBuffer;
  return globalThis.crypto.subtle.importKey(
    "raw",
    keyBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

/**
 * Computes deterministic HMAC-SHA256 with a pre-imported Web Crypto key.
 *
 * @param input - Plain input string to sign.
 * @param key - Pre-imported HMAC-SHA256 key.
 * @returns Lowercase hex digest.
 */
export async function generateHMACWithKey(input: string, key: CryptoKey): Promise<string> {
  const signature = await globalThis.crypto.subtle.sign(
    "HMAC",
    key,
    textEncoder.encode(input)
  );

  return bytesToHex(new Uint8Array(signature));
}

/**
 * Computes deterministic HMAC-SHA256 for worker pseudonymization and lookup keys.
 *
 * Prefer `importHmacKey` + `generateHMACWithKey` when signing many values in one request.
 *
 * @param input - Plain input string to sign.
 * @param salt - HMAC key material (salt/secret).
 * @returns Lowercase hex digest.
 */
export async function generateHMAC(input: string, salt: string): Promise<string> {
  const key = await importHmacKey(salt);
  return generateHMACWithKey(input, key);
}