import { fail } from "@/errors";
import { base64ToBytes, bytesToBase64 } from "@/utils";

const textEncoder = new TextEncoder();

type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };

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

function canonicalJsonStringify(value: unknown): string {
  const firstPass = JSON.stringify(value);
  if (firstPass === undefined) {
    throw new TypeError("Value is not JSON-serializable.");
  }

  const parsed = JSON.parse(firstPass) as JsonValue;
  return JSON.stringify(sortJson(parsed));
}

export interface CoeSignature {
  algorithm: "Ed25519";
  keyId: string;
  signatureBase64: string;
  publicKeySpkiBase64: string;
}

/**
 * Certificate signer abstraction used when minting Certificates of Erasure.
 */
export interface CoeSigner {
  sign(payload: unknown): Promise<CoeSignature>;
}

function encodePayload(payload: unknown): ArrayBuffer {
  const source = textEncoder.encode(canonicalJsonStringify(payload));
  const copied = new Uint8Array(source.length);
  copied.set(source);
  return copied.buffer as ArrayBuffer;
}

function toBase64(input: ArrayBuffer | Uint8Array): string {
  return bytesToBase64(input);
}

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

/**
 * Creates an Ed25519 certificate signer using Web Crypto APIs.
 *
 * If private/public key material is not provided, an ephemeral keypair is generated.
 *
 * @param keyId - Stable key identifier embedded in signatures.
 * @param options - Optional PKCS8 private key + SPKI public key (base64).
 * @returns Signer capable of producing CoE signatures.
 * @throws {ApiError} When private key is provided without corresponding public key.
 */
export async function createEd25519Signer(
  keyId: string,
  options: { privateKeyPkcs8Base64?: string; publicKeySpkiBase64?: string } = {}
): Promise<CoeSigner> {
  let privateKey: CryptoKey;
  let publicKeySpkiBase64: string;

  if (options.privateKeyPkcs8Base64) {
    if (!options.publicKeySpkiBase64) {
      fail({
        code: "API_COE_PUBLIC_KEY_MISSING",
        title: "Public key is required",
        detail: "publicKeySpkiBase64 is required when privateKeyPkcs8Base64 is provided.",
        status: 500,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    privateKey = await globalThis.crypto.subtle.importKey(
      "pkcs8",
      toArrayBuffer(base64ToBytes(options.privateKeyPkcs8Base64)),
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    publicKeySpkiBase64 = options.publicKeySpkiBase64;
  } else {
    const pair = (await globalThis.crypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"]
    )) as unknown as CryptoKeyPair;
    privateKey = pair.privateKey;
    const spki = await globalThis.crypto.subtle.exportKey("spki", pair.publicKey);
    publicKeySpkiBase64 = toBase64(spki);
  }

  return {
    async sign(payload: unknown): Promise<CoeSignature> {
      const signature = await globalThis.crypto.subtle.sign("Ed25519", privateKey, encodePayload(payload));

      return {
        algorithm: "Ed25519",
        keyId,
        signatureBase64: toBase64(signature),
        publicKeySpkiBase64,
      };
    },
  };
}

/**
 * Verifies an Ed25519 signature for a JSON payload.
 *
 * @param publicKeySpkiBase64 - Public key in base64-encoded SPKI format.
 * @param signatureBase64 - Signature in base64 format.
 * @param payload - Canonical JSON payload that was signed.
 * @returns `true` when signature verification succeeds.
 */
export async function verifyEd25519Signature(
  publicKeySpkiBase64: string,
  signatureBase64: string,
  payload: unknown
): Promise<boolean> {
  const publicKey = await globalThis.crypto.subtle.importKey(
    "spki",
    toArrayBuffer(base64ToBytes(publicKeySpkiBase64)),
    { name: "Ed25519" },
    false,
    ["verify"]
  );

  return globalThis.crypto.subtle.verify(
    "Ed25519",
    publicKey,
    toArrayBuffer(base64ToBytes(signatureBase64)),
    encodePayload(payload)
  );
}
