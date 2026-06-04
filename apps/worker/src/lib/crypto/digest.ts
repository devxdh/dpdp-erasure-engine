const textEncoder = new TextEncoder();

/**
 * Converts binary data into lowercase hexadecimal representation.
 * @param buffer - Input bytes.
 * @returns Hex string.
 */
export function hexEncode(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Computes SHA-256 digest for UTF-8 text and returns lowercase hex.
 * 
 * @param input - Text payload to hash.
 * @returns SHA-256 digest encoded as hex.
 */
export async function sha256HexDigest(input: string): Promise<string> {
  const data = textEncoder.encode(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", data);
  return hexEncode(digest);
}