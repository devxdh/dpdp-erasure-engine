type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

function toHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) {
    return value.map((item) => sortJson(item));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort((left, right) => left.localeCompare(right))
        .map((key) => [key, sortJson((value as Record<string, JsonValue>)[key]!)])
    );
  }

  return value;
}

export function canonicalJsonStringify(value: unknown): string {
  const firstPass = JSON.stringify(value);
  if (firstPass === undefined) {
    throw new TypeError("Value is not JSON-serializable.");
  }

  const parsed = JSON.parse(firstPass) as JsonValue;
  return JSON.stringify(sortJson(parsed));
}

/**
 * Computes a SHA-256 hex digest for deterministic non-secret identifiers.
 *
 * @param value - UTF-8 text to hash.
 * @returns Lowercase SHA-256 hex digest.
 */
export async function computeSha256Hex(value: string): Promise<string> {
  const data = new TextEncoder().encode(value);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

/**
 * Computes a SHA-256 hex digest for the WORM audit chain.
 *
 * @param previousHash - Prior chain hash or `GENESIS`.
 * @param payload - Event payload body.
 * @param idempotencyKey - Event idempotency key.
 * @returns Chain hash for the current event.
 */
export async function computeWormHash(previousHash: string, payload: unknown, idempotencyKey: string): Promise<string> {
  const data = new TextEncoder().encode(`${previousHash}${canonicalJsonStringify(payload)}${idempotencyKey}`);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}

/**
 * Computes a SHA-256 hex digest for worker API token storage.
 *
 * @param token - Raw worker bearer token.
 * @returns SHA-256 token digest in hex format.
 */
export async function computeTokenHash(token: string): Promise<string> {
  const data = new TextEncoder().encode(token);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return toHex(digest);
}
