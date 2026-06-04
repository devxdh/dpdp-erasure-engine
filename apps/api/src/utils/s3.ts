import { bytesToHex } from "./encodings";

const textEncoder = new TextEncoder();

export interface S3Credentials {
  accessKeyId: string;
  secretAccessKey: string;
}

export interface S3PutObjectOptions {
  bucket: string;
  key: string;
  region: string;
  body: Uint8Array;
  contentType: string;
  credentials: S3Credentials;
  endpointOverride?: string;
  objectLockMode?: "COMPLIANCE" | "GOVERNANCE";
  retainUntilDate?: Date;
}

export interface S3PutObjectReceipt {
  eTag: string | null;
  versionId: string | null;
}

async function sha256Hex(input: Uint8Array): Promise<string> {
  const bytes = new Uint8Array(input);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
  return bytesToHex(new Uint8Array(digest));
}

async function hmacSha256(key: Uint8Array, value: string | Uint8Array): Promise<Uint8Array> {
  const keyBytes = new Uint8Array(key);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const data = typeof value === "string" ? textEncoder.encode(value) : new Uint8Array(value);
  return new Uint8Array(await globalThis.crypto.subtle.sign("HMAC", cryptoKey, data));
}

function buildS3Url(bucket: string, key: string, region: string, endpointOverride?: string): URL {
  if (endpointOverride) {
    const url = new URL(endpointOverride);
    // Support both path-style and virtual-hosted if needed, but path-style is easier for mocks
    url.pathname = `/${bucket}/${key}`;
    return url;
  }
  return new URL(`https://${bucket}.s3.${region}.amazonaws.com/${key}`);
}

/**
 * Signs and executes an S3 PutObject request using SigV4.
 * Includes support for WORM Object Lock headers.
 */
export async function s3PutObject(options: S3PutObjectOptions): Promise<S3PutObjectReceipt> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const url = buildS3Url(options.bucket, options.key, options.region, options.endpointOverride);
  const payloadHash = await sha256Hex(options.body);

  const headers = new Headers({
    "content-type": options.contentType,
    "content-length": String(options.body.length),
    host: url.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
  });

  if (options.objectLockMode) {
    headers.set("x-amz-object-lock-mode", options.objectLockMode);
  }
  if (options.retainUntilDate) {
    headers.set("x-amz-object-lock-retain-until-date", options.retainUntilDate.toISOString());
  }

  // Canonical Request
  const canonicalHeaders = Array.from(headers.entries())
    .map(([name, value]) => `${name.toLowerCase()}:${value.trim()}\n`)
    .sort()
    .join("");

  const signedHeaders = Array.from(headers.keys())
    .map((name) => name.toLowerCase())
    .sort()
    .join(";");

  const canonicalRequest = [
    "PUT",
    url.pathname,
    "", // Query string
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${options.region}/s3/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(textEncoder.encode(canonicalRequest)),
  ].join("\n");

  // Signing Key
  const kDate = await hmacSha256(textEncoder.encode(`AWS4${options.credentials.secretAccessKey}`), dateStamp);
  const kRegion = await hmacSha256(kDate, options.region);
  const kService = await hmacSha256(kRegion, "s3");
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = bytesToHex(await hmacSha256(kSigning, stringToSign));

  headers.set(
    "authorization",
    `AWS4-HMAC-SHA256 Credential=${options.credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
  );

  const response = await fetch(url, {
    method: "PUT",
    headers,
    body: options.body,
  });

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`S3 PutObject failed [${response.status}]: ${error}`);
  }

  return {
    eTag: response.headers.get("etag"),
    versionId: response.headers.get("x-amz-version-id"),
  };
}
