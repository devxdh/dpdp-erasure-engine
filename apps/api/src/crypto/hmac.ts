import { bytesToHex } from "@/utils";

const textEncoder = new TextEncoder();
const hmacKeyCache = new Map<string, Promise<CryptoKey>>();
const MAX_HMAC_KEY_CACHE_ENTRIES = 1024;

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

function hexToBytes(value: string): Uint8Array | null {
  const normalized = value.trim().replace(/^sha256=/i, "");
  if (!/^[0-9a-f]{64}$/i.test(normalized)) {
    return null;
  }

  const bytes = new Uint8Array(32);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const cached = hmacKeyCache.get(secret);
  if (cached) {
    return cached;
  }

  if (hmacKeyCache.size >= MAX_HMAC_KEY_CACHE_ENTRIES) {
    hmacKeyCache.delete(hmacKeyCache.keys().next().value as string);
  }

  const imported = globalThis.crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  hmacKeyCache.set(secret, imported);
  return imported;
}

export function clearHmacKeyCache(): void {
  hmacKeyCache.clear();
}

async function getHmacKey(secret: string): Promise<CryptoKey> {
  return importHmacKey(secret);
}

async function importLegacyHmacKey(secret: string, usages: Array<"sign" | "verify">): Promise<CryptoKey> {
  return globalThis.crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    usages
  );
}

/**
 * Computes a lowercase HMAC-SHA256 hex digest with Web Crypto.
 *
 * @param secret - Shared HMAC secret.
 * @param value - Exact message bytes represented as UTF-8 text.
 * @returns Lowercase hex digest.
 */
export async function computeHmacSha256Hex(secret: string, value: string): Promise<string> {
  const key = await getHmacKey(secret);
  const signature = await globalThis.crypto.subtle.sign("HMAC", key, textEncoder.encode(value));
  return bytesToHex(new Uint8Array(signature));
}

/**
 * Verifies a hex HMAC-SHA256 digest through Web Crypto's native verification path.
 *
 * Invalid encodings are rejected before verification; valid-length digests are compared by
 * `crypto.subtle.verify`, avoiding application-level byte loops.
 *
 * @param secret - Shared HMAC secret.
 * @param value - Exact message bytes represented as UTF-8 text.
 * @param signatureHex - Hex digest, optionally prefixed with `sha256=`.
 * @returns `true` only when the signature is authentic.
 */
export async function verifyHmacSha256Hex(
  secret: string,
  value: string,
  signatureHex: string | null | undefined
): Promise<boolean> {
  if (!signatureHex) {
    return false;
  }

  const signature = hexToBytes(signatureHex);
  if (!signature) {
    return false;
  }

  let key = await getHmacKey(secret);
  if (!key.usages.includes("verify")) {
    key = await importLegacyHmacKey(secret, ["verify"]);
  }
  return globalThis.crypto.subtle.verify(
    "HMAC",
    key,
    copyToArrayBuffer(signature),
    textEncoder.encode(value)
  );
}
