import { bytesToHex } from "@/lib";
import type { S3AwsCredentials } from "./type";

const textEncoder = new TextEncoder();
const signingKeyCache = new Map<string, Promise<CryptoKey>>();
const MAX_SIGNING_KEY_CACHE_ENTRIES = 256;


export interface AwsSignedRequestInput {
  method: string;
  url: URL;
  region: string;
  service: string;
  headers: Headers;
  body?: Uint8Array | string;
  credentials: S3AwsCredentials;
  now?: Date;
}

function copyBytes(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length);
  copy.set(bytes);
  return copy;
}

function encodeBody(body: Uint8Array | string | undefined): Uint8Array {
  if (body === undefined) {
    return new Uint8Array(0);
  }

  return typeof body === "string" ? copyBytes(textEncoder.encode(body)) : copyBytes(body);
}

async function sha256Hex(input: Uint8Array | string): Promise<string> {
  const bytes = typeof input === "string" ? textEncoder.encode(input) : input;
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer as ArrayBuffer);
  return bytesToHex(new Uint8Array(digest));
}

async function hmacSha256(key: Uint8Array, value: string): Promise<Uint8Array> {
  const keyBytes = key.slice();
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes.buffer as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = textEncoder.encode(value).slice();
  const signature = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, data.buffer as ArrayBuffer);
  return new Uint8Array(signature);
}

async function hmacSha256WithKey(key: CryptoKey, value: string): Promise<Uint8Array> {
  const data = textEncoder.encode(value);
  const signature = await globalThis.crypto.subtle.sign("HMAC", key, data);
  return new Uint8Array(signature);
}

function signingCacheKey(input: AwsSignedRequestInput, dateStamp: string): string {
  return [
    input.credentials.accessKeyId,
    input.credentials.sessionToken ?? "",
    input.credentials.expiration?.getTime() ?? "",
    dateStamp,
    input.region,
    input.service,
  ].join("|");
}

async function importSigningKey(bytes: Uint8Array): Promise<CryptoKey> {
  const keyBytes = bytes.slice();
  try {
    return await globalThis.crypto.subtle.importKey(
      "raw",
      keyBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
  } finally {
    keyBytes.fill(0);
  }
}

async function deriveSigningKey(input: AwsSignedRequestInput, dateStamp: string): Promise<CryptoKey> {
  const cacheKey = signingCacheKey(input, dateStamp);
  const cached = signingKeyCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  if (signingKeyCache.size >= MAX_SIGNING_KEY_CACHE_ENTRIES) {
    signingKeyCache.delete(signingKeyCache.keys().next().value as string);
  }

  const derived = (async () => {
    const secretSeed = textEncoder.encode(`AWS4${input.credentials.secretAccessKey}`);
    let dateKey: Uint8Array = new Uint8Array(0);
    let regionKey: Uint8Array = new Uint8Array(0);
    let serviceKey: Uint8Array = new Uint8Array(0);
    let signingKey: Uint8Array = new Uint8Array(0);
    try {
      dateKey = await hmacSha256(secretSeed, dateStamp);
      regionKey = await hmacSha256(dateKey, input.region);
      serviceKey = await hmacSha256(regionKey, input.service);
      signingKey = await hmacSha256(serviceKey, "aws4_request");
      return importSigningKey(signingKey);
    } finally {
      secretSeed.fill(0);
      dateKey.fill(0);
      regionKey.fill(0);
      serviceKey.fill(0);
      signingKey.fill(0);
    }
  })();
  signingKeyCache.set(cacheKey, derived);
  return derived;
}

function buildCanonicalQuery(searchParams: URLSearchParams): string {
  return Array.from(searchParams.entries())
    .sort(([leftName, leftValue], [rightName, rightValue]) => {
      const byName = leftName.localeCompare(rightName);
      return byName === 0 ? leftValue.localeCompare(rightValue) : byName;
    })
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join("&");
}

function normalizeAmzDate(now: Date): { amzDate: string; dateStamp: string } {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return { amzDate, dateStamp: amzDate.slice(0, 8) };
}

/**
 * Signs an AWS REST request with Signature Version 4 using Web Crypto HMAC-SHA256.
 *
 * @param input - Request method, URL, headers, body, service, region, and credentials.
 * @returns Headers containing SigV4 authorization fields.
 */
export async function signAwsRequest(input: AwsSignedRequestInput): Promise<Headers> {
  const bodyBytes = encodeBody(input.body);
  const payloadHash = await sha256Hex(bodyBytes);
  const { amzDate, dateStamp } = normalizeAmzDate(input.now ?? new Date());
  const headers = new Headers(input.headers);

  headers.set("host", input.url.host);
  headers.set("x-amz-content-sha256", payloadHash);
  headers.set("x-amz-date", amzDate);
  if (input.credentials.sessionToken) {
    headers.set("x-amz-security-token", input.credentials.sessionToken);
  }

  const sortedHeaders = Array.from(headers.entries())
    .map(([name, value]) => [name.toLowerCase(), value.trim().replace(/\s+/g, " ")] as const)
    .sort(([left], [right]) => left.localeCompare(right));
  const canonicalHeaders = sortedHeaders.map(([name, value]) => `${name}:${value}\n`).join("");
  const signedHeaders = sortedHeaders.map(([name]) => name).join(";");
  const canonicalRequest = [
    input.method.toUpperCase(),
    input.url.pathname || "/",
    buildCanonicalQuery(input.url.searchParams),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${input.region}/${input.service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  let signatureBytes: Uint8Array = new Uint8Array(0);

  try {
    const signingKey = await deriveSigningKey(input, dateStamp);
    signatureBytes = await hmacSha256WithKey(signingKey, stringToSign);
    headers.set(
      "authorization",
      `AWS4-HMAC-SHA256 Credential=${input.credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${bytesToHex(signatureBytes)}`
    );
    return headers;
  } finally {
    signatureBytes.fill(0);
  }
}
