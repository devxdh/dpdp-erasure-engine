import { fail } from "@/errors";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const hmacKeyCache = new Map<string, Promise<CryptoKey>>();
const MAX_HMAC_KEY_CACHE_ENTRIES = 1024;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

function decodeBase64(value: string): Uint8Array | null {
  try {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
  } catch {
    return null;
  }
}

function parseSignatureBytes(value: string): Uint8Array | null {
  const normalized = value.trim().replace(/^sha256=/i, "");
  if (/^[0-9a-f]{64}$/i.test(normalized)) {
    const bytes = new Uint8Array(32);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  }

  return decodeBase64(normalized);
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

/**
 * Verifies an HMAC-SHA256 signature using Web Crypto's constant-time verification path.
 *
 * @param secret - Provider/client webhook signing secret.
 * @param rawBody - Exact request body bytes represented as UTF-8 text.
 * @param signatureHeader - Hex, `sha256=<hex>`, or base64 signature header.
 * @returns `true` only when the signature matches.
 */
export async function verifyHmacSha256(
  secret: string,
  rawBody: string,
  signatureHeader: string | undefined
): Promise<boolean> {
  if (!signatureHeader) {
    return false;
  }

  const signature = parseSignatureBytes(signatureHeader);
  if (!signature) {
    return false;
  }

  const key = await importHmacKey(secret);
  return globalThis.crypto.subtle.verify(
    "HMAC",
    key,
    toArrayBuffer(signature),
    textEncoder.encode(rawBody)
  );
}

/**
 * Computes a SHA-256 digest for deterministic opaque identifiers.
 *
 * @param value - UTF-8 text to hash.
 * @returns Lowercase SHA-256 hex digest.
 */
export async function sha256Hex(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", textEncoder.encode(value));
  return toHex(new Uint8Array(digest));
}

function uuidBytes(value: string): Uint8Array {
  const normalized = value.replace(/-/g, "");
  if (!/^[0-9a-f]{32}$/i.test(normalized)) {
    fail({
      code: "API_WEBHOOK_NAMESPACE_INVALID",
      title: "Invalid webhook UUID namespace",
      detail: "Webhook UUID namespace must be a valid UUID.",
      status: 500,
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  const bytes = new Uint8Array(16);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Generates an RFC-4122 UUIDv5 using Web Crypto SHA-1.
 *
 * @param namespace - UUID namespace.
 * @param name - Deterministic idempotency source string.
 * @returns UUIDv5 string.
 */
export async function uuidV5(namespace: string, name: string): Promise<string> {
  const namespaceBytes = uuidBytes(namespace);
  const nameBytes = textEncoder.encode(name);
  const payload = new Uint8Array(namespaceBytes.length + nameBytes.length);
  payload.set(namespaceBytes);
  payload.set(nameBytes, namespaceBytes.length);

  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-1", payload));
  const bytes = digest.slice(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = toHex(bytes);

  payload.fill(0);
  nameBytes.fill(0);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

/**
 * Reads a request body with a hard byte cap so webhook ingestion cannot allocate unbounded memory.
 *
 * @param request - Incoming Fetch request.
 * @param maxBytes - Maximum accepted body size.
 * @returns Raw UTF-8 request body.
 * @throws {ApiError} When the body exceeds the configured cap.
 */
export async function readBoundedTextBody(request: Request, maxBytes: number): Promise<string> {
  const contentLength = request.headers.get("content-length");
  if (contentLength && Number(contentLength) > maxBytes) {
    fail({
      code: "API_WEBHOOK_PAYLOAD_TOO_LARGE",
      title: "Webhook payload too large",
      detail: `Webhook body exceeds ${maxBytes} bytes.`,
      status: 413,
      category: "validation",
      retryable: false,
    });
  }

  const reader = request.body?.getReader();
  if (!reader) {
    return "";
  }

  const chunks: Uint8Array[] = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }

    received += value.byteLength;
    if (received > maxBytes) {
      value.fill(0);
      for (const chunk of chunks) {
        chunk.fill(0);
      }
      fail({
        code: "API_WEBHOOK_PAYLOAD_TOO_LARGE",
        title: "Webhook payload too large",
        detail: `Webhook body exceeds ${maxBytes} bytes.`,
        status: 413,
        category: "validation",
        retryable: false,
      });
    }

    chunks.push(value);
  }

  const body = new Uint8Array(received);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
    chunk.fill(0);
  }

  try {
    return textDecoder.decode(body);
  } finally {
    body.fill(0);
  }
}
