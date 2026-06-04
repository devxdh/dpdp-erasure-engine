import { fail } from "@/errors";

const textEncoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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