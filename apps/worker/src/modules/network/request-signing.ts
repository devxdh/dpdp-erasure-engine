const textEncoder = new TextEncoder();
const signingKeyCache = new Map<string, Promise<CryptoKey>>();
const MAX_SIGNING_KEY_CACHE_ENTRIES = 128;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function importSigningKey(secret: string): Promise<CryptoKey> {
  const cached = signingKeyCache.get(secret);
  if (cached) {
    return cached;
  }

  if (signingKeyCache.size >= MAX_SIGNING_KEY_CACHE_ENTRIES) {
    signingKeyCache.delete(signingKeyCache.keys().next().value as string);
  }

  const imported = globalThis.crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
  signingKeyCache.set(secret, imported);
  return imported;
}

/**
 * Computes the canonical worker/API HMAC request signature.
 *
 * @param secret - Shared HMAC secret.
 * @param method - HTTP method.
 * @param path - URL pathname.
 * @param clientId - Worker client identifier.
 * @param timestamp - Unix epoch milliseconds string.
 * @param nonce - Optional per-request nonce used to prevent same-millisecond multi-worker collisions.
 * @param bodyText - Exact request body text.
 * @returns Lowercase hex digest.
 */
export async function computeRequestSignature(
  secret: string,
  method: string,
  path: string,
  clientId: string,
  timestamp: string,
  bodyText: string,
  nonce: string = ""
): Promise<string> {
  const key = await importSigningKey(secret);
  const parts = nonce
    ? [method.toUpperCase(), path, clientId, timestamp, nonce, bodyText]
    : [method.toUpperCase(), path, clientId, timestamp, bodyText];
  const payload = textEncoder.encode(parts.join("\n"));
  const signature = await globalThis.crypto.subtle.sign("HMAC", key, payload);
  return bytesToHex(new Uint8Array(signature));
}
