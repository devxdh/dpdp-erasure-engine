/**
 * Web-native byte encoding helpers for Bun/Web Crypto code paths.
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
 * Encodes raw bytes as base64.
 *
 * @param bytes - Binary payload.
 * @returns Base64 string.
 */
export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes));
}

/**
 * Decodes Base64 into raw bytes.
 * 
 * @param value - Base64 payload.
 * @returns Decoded bytes.
 * @throws {TypeError} when value is not valid Base64.
 */
export function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

/**
 * Encodes raw bytes as lowercase hexadecimal.
 *
 * @param bytes - Binary payload.
 * @returns Lowercase hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Decodes hexadecimal text into raw bytes
 * 
 * @param value - Hex payload
 * @returns Decoded Bytes
 * @throws {TypeError} When the input is not valid even-length hex.
 */
export function hexToBytes(value: string): Uint8Array {
  if (value.length % 2 !== 0 || /[^0-9a-f]/i.test(value)) {
    throw new TypeError("Invalid hexadecimal string.");
  }

  const bytes = new Uint8Array(value.length / 2)
  for (let i = 0; i < value.length; i += 2) {
    bytes[i / 2] = Number.parseInt(value.slice(i, i + 2), 16);
  }

  return bytes;
}

export function copyBytes(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy as Uint8Array;
}