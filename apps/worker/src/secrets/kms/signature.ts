import { bytesToHex } from "@/lib";
import { hmacSha256, seedSecret, sha256Hex } from "../repository"

export interface KMSAwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export async function signAwsKmsRequest(
  endpoint: URL,
  region: string,
  body: string,
  credentials: KMSAwsCredentials,
  now: Date = new Date()
): Promise<Headers> {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = await sha256Hex(body);
  const headers = new Headers({
    "content-type": "application/x-amz-json-1.1",
    host: endpoint.host,
    "x-amz-content-sha256": payloadHash,
    "x-amz-date": amzDate,
    "x-amz-target": "TrentService.Decrypt",
  });

  if (credentials.sessionToken) {
    headers.set("x-amz-security-token", credentials.sessionToken);
  }

  const sortedHeaders = Array.from(headers.entries()).sort(([left], [right]) => left.localeCompare(right));
  const canonicalHeaders = sortedHeaders
    .map(([name, value]) => `${name.toLowerCase()}:${value.trim().replace(/\s+/g, " ")}\n`)
    .join("");
  const signedHeaders = sortedHeaders.map(([name]) => name.toLowerCase()).join(";");
  const canonicalRequest = [
    "POST",
    endpoint.pathname || "/",
    endpoint.search.length > 1 ? endpoint.search.slice(1) : "",
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");
  const credentialScope = `${dateStamp}/${region}/kms/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const secretSeed = seedSecret(credentials.secretAccessKey)
  let dateKey: Uint8Array = new Uint8Array(0);
  let regionKey: Uint8Array = new Uint8Array(0);
  let serviceKey: Uint8Array = new Uint8Array(0);
  let signingKey: Uint8Array = new Uint8Array(0);
  let signatureBytes: Uint8Array = new Uint8Array(0);

  try {
    dateKey = await hmacSha256(secretSeed, dateStamp);
    regionKey = await hmacSha256(dateKey, region);
    serviceKey = await hmacSha256(regionKey, "kms");
    signingKey = await hmacSha256(serviceKey, "aws4_request");
    signatureBytes = await hmacSha256(signingKey, stringToSign);
    const signature = bytesToHex(signatureBytes);

    headers.set(
      "authorization",
      `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`
    );
  } finally {
    secretSeed.fill(0);
    dateKey.fill(0);
    regionKey.fill(0);
    serviceKey.fill(0);
    signingKey.fill(0);
    signatureBytes.fill(0);
  }

  return headers;
}