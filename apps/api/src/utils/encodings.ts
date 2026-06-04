/**
 * Web-native encoding helpers for Bun/Web Crypto code paths.
 */

function bytesToBinary(bytes: Uint8Array): string {
  let output = "";
  const chunkSize = 0x8000;

  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    output += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }

  return output;
}

/**
 * Encodes bytes as base64.
 *
 * @param input - Binary payload.
 * @returns Base64 string.
 */
export function bytesToBase64(input: Uint8Array | ArrayBuffer): string {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  return btoa(bytesToBinary(bytes));
}

/**
 * Decodes base64 text into raw bytes.
 *
 * @param value - Base64 payload.
 * @returns Decoded bytes.
 * @throws {TypeError} When the input is not valid base64.
 */
export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

/**
 * Encodes bytes as lowercase hexadecimal text.
 *
 * @param input - Binary payload.
 * @returns Lowercase hex string.
 */
export function bytesToHex(input: Uint8Array): string {
  return Array.from(input, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
