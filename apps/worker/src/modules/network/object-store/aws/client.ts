import type { Override } from "@/types";
import { CODE, fail } from "@/errors";
import { bytesToBase64 } from "@/lib";
import type { S3AwsCredentials } from "./type";
import { resolveAwsCredentials } from "./credentials";
import { signAwsRequest } from "./sigv4";

const textEncoder = new TextEncoder();

export interface S3ObjectPointer {
  bucket: string;
  key: string;
  versionId?: string;
}

export interface S3ObjectHead extends Override<S3ObjectPointer, { versionId: string | null; }> {
  eTag: string | null;
};

interface KeyAndVersion {
  key: string;
  versionId: string;
}

export interface S3ObjectVersion extends KeyAndVersion {
  eTag: string | null;
  isDeleteMarker: boolean;
}

export interface S3DeleteReceipt {
  key: string;
  versionId: string | null;
  deleteMarker: boolean;
  status: number;
}

export interface S3PutReceipt extends Omit<S3ObjectHead, "bucket"> {
  status: number;
};

export interface S3RequestOptions extends S3ObjectPointer {
  region: string;
  expectedBucketOwner?: string;
}

export interface S3ClientOptions {
  env?: Record<string, string | undefined>;
  fetchFn?: typeof fetch;
  credentials?: S3AwsCredentials;
  endpointOverride?: string;
  timeoutMs?: number;
}

export interface S3Client {
  headObject(options: S3RequestOptions): Promise<S3ObjectHead>;
  putObjectLegalHold(options: S3RequestOptions & { status: "ON" | "OFF" }): Promise<void>;
  listObjectVersions(options: Omit<S3RequestOptions, "versionId">): Promise<S3ObjectVersion[]>;
  deleteObjectVersion(options: S3RequestOptions & { bypassGovernanceRetention?: boolean }): Promise<S3DeleteReceipt>;
  putObject(options: Omit<S3RequestOptions, "versionId"> & { body: Uint8Array; contentType: string }): Promise<S3PutReceipt>;
}

function encodeS3KeyPath(key: string): string {
  return `/${key.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
}

function stripQuotedHeader(value: string | null): string | null {
  return value ? value.replace(/^"|"$/g, "") : null;
}

function buildS3Url(bucket: string, key: string | null, region: string, endpointOverride?: string): URL {
  const host = endpointOverride
    ? new URL(endpointOverride).host
    : `${bucket}.s3.${region}.amazonaws.com`;
  const protocol = endpointOverride ? new URL(endpointOverride).protocol : "https:";
  const path = key ? encodeS3KeyPath(key) : "/";
  return new URL(`${protocol}//${host}${path}`);
}

function appendExpectedBucketOwner(headers: Headers, expectedBucketOwner?: string): void {
  if (expectedBucketOwner) {
    headers.set("x-amz-expected-bucket-owner", expectedBucketOwner);
  }
}

async function sha256Base64(bytes: Uint8Array): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes.slice().buffer as ArrayBuffer);
  return bytesToBase64(new Uint8Array(digest));
}

function decodeXml(value: string): string {
  return value
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'");
}

function readXmlTag(block: string, tag: string): string | null {
  const escapedTag = tag.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`<${escapedTag}>([\\s\\S]*?)</${escapedTag}>`).exec(block);
  return match ? decodeXml(match[1] ?? "") : null;
}

function parseBooleanXml(value: string | null): boolean {
  return value?.trim().toLowerCase() === "true";
}

function parseListObjectVersionsXml(xml: string, requestedKey: string): {
  versions: S3ObjectVersion[];
  isTruncated: boolean;
  nextKeyMarker: string | null;
  nextVersionIdMarker: string | null;
} {
  const versions: S3ObjectVersion[] = [];
  for (const match of xml.matchAll(/<(Version|DeleteMarker)>([\s\S]*?)<\/\1>/g)) {
    const type = match[1];
    const block = match[2] ?? "";
    const key = readXmlTag(block, "Key");
    const versionId = readXmlTag(block, "VersionId");
    if (!key || !versionId || key !== requestedKey) {
      continue;
    }

    versions.push({
      key,
      versionId,
      eTag: stripQuotedHeader(readXmlTag(block, "ETag")),
      isDeleteMarker: type === "DeleteMarker",
    });
  }

  return {
    versions,
    isTruncated: parseBooleanXml(readXmlTag(xml, "IsTruncated")),
    nextKeyMarker: readXmlTag(xml, "NextKeyMarker"),
    nextVersionIdMarker: readXmlTag(xml, "NextVersionIdMarker"),
  };
}

/**
 * Parses supported S3 URL forms into bucket, key, and optional version id.
 *
 * @param value - `s3://bucket/key`, virtual-hosted S3 HTTPS URL, or path-style S3 URL.
 * @returns Parsed object pointer.
 * @throws {WorkerError} When the URL is absent, malformed, or not an S3 URL.
 */
export function parseS3ObjectUrl(value: string): S3ObjectPointer {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    fail({
      code: CODE.BLOB_URL_INVALID,
      detail: "Blob target value must be a valid s3:// or https:// S3 URL.",
    });
  }

  if (url.protocol === "s3:") {
    const key = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    if (!url.hostname || !key) {
      fail({
        code: CODE.BLOB_URL_INVALID,
        detail: "s3:// blob URL must contain a bucket and object key.",
      });
    }

    return {
      bucket: url.hostname,
      key,
      versionId: url.searchParams.get("versionId") ?? undefined,
    };
  }

  if (url.protocol !== "https:") {
    fail({
      code: CODE.BLOB_URL_UNSUPPORTED,
      title: "Unsupported blob URL protocol",
      detail: "S3 blob targets must use s3:// or https:// URLs.",
    });
  }

  const hostParts = url.hostname.split(".");
  const s3Index = hostParts.findIndex((part) => part === "s3" || part.startsWith("s3-"));
  if (s3Index <= 0 && !url.hostname.startsWith("s3.")) {
    fail({
      code: CODE.BLOB_URL_UNSUPPORTED,
      title: "Unsupported S3 URL host",
      detail: "HTTPS blob URL must use an Amazon S3 virtual-hosted or path-style hostname.",
    });
  }

  if (s3Index > 0) {
    const key = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    if (!key) {
      fail({
        code: CODE.BLOB_URL_INVALID,
        detail: "Virtual-hosted S3 URL must contain an object key.",
      });
    }

    return {
      bucket: hostParts.slice(0, s3Index).join("."),
      key,
      versionId: url.searchParams.get("versionId") ?? undefined,
    };
  }

  const [bucket, ...keyParts] = url.pathname.replace(/^\/+/, "").split("/");
  if (!bucket || keyParts.length === 0) {
    fail({
      code: CODE.BLOB_URL_INVALID,
      title: "Invalid S3 path-style URL",
      detail: "Path-style S3 URL must contain bucket and key path segments.",
    });
  }

  return {
    bucket,
    key: decodeURIComponent(keyParts.join("/")),
    versionId: url.searchParams.get("versionId") ?? undefined,
  };
}

/**
 * Creates a minimal AWS S3 REST client using SigV4 and native fetch.
 *
 * @param options - Credential, fetch, endpoint, and timeout overrides.
 * @returns S3 client used by vaulting and shredding blob workflows.
 */
export function createS3Client(options: S3ClientOptions = {}): S3Client {
  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  let cachedCredentials: S3AwsCredentials | null = options.credentials ?? null;

  async function credentials(): Promise<S3AwsCredentials> {
    if (
      cachedCredentials &&
      (!cachedCredentials.expiration || cachedCredentials.expiration.getTime() - Date.now() > 60_000)
    ) {
      return cachedCredentials;
    }

    cachedCredentials = await resolveAwsCredentials({
      env: options.env,
      fetchFn,
      timeoutMs: Math.min(timeoutMs, 2_000),
    });
    return cachedCredentials;
  }

  async function signedFetch(
    method: string,
    requestUrl: URL,
    region: string,
    headers: Headers,
    body?: Uint8Array | string
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const signedHeaders = await signAwsRequest({
        method,
        url: requestUrl,
        region,
        service: "s3",
        headers,
        body,
        credentials: await credentials(),
      });
      try {
        return await fetchFn(requestUrl, {
          method,
          headers: signedHeaders,
          body,
          signal: controller.signal,
          redirect: "error",
        });
      } catch (error) {
        fail({
          code: "S3_OPERATION_RETRYABLE",
          title: "S3 operation failed",
          detail: error instanceof Error ? error.message : "S3 request could not be completed.",
          category: "network",
          retryable: true,
          fatal: false,
          context: {
            method,
            host: requestUrl.host,
          },
        });
      }
    } finally {
      clearTimeout(timer);
    }
  }

  async function assertS3Response(response: Response, operation: string): Promise<void> {
    if (response.ok) {
      return;
    }

    fail({
      code: response.status >= 500 || response.status === 429
        ? "S3_OPERATION_RETRYABLE"
        : "S3_OPERATION_REJECTED",
      title: "S3 operation failed",
      detail: `${operation} returned HTTP ${response.status}.`,
      category: response.status >= 500 || response.status === 429 ? "network" : "external",
      retryable: response.status >= 500 || response.status === 429,
      fatal: response.status === 401 || response.status === 403,
      context: {
        operation,
        status: response.status,
      },
    });
  }

  return {
    async headObject(input) {
      const url = buildS3Url(input.bucket, input.key, input.region, options.endpointOverride);
      if (input.versionId) {
        url.searchParams.set("versionId", input.versionId);
      }
      const headers = new Headers();
      appendExpectedBucketOwner(headers, input.expectedBucketOwner);
      const response = await signedFetch("HEAD", url, input.region, headers);
      await assertS3Response(response, "HeadObject");

      return {
        bucket: input.bucket,
        key: input.key,
        versionId: response.headers.get("x-amz-version-id"),
        eTag: stripQuotedHeader(response.headers.get("etag")),
      };
    },

    async putObjectLegalHold(input) {
      const url = buildS3Url(input.bucket, input.key, input.region, options.endpointOverride);
      url.searchParams.set("legal-hold", "");
      if (input.versionId) {
        url.searchParams.set("versionId", input.versionId);
      }

      const body = `<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${input.status}</Status></LegalHold>`;
      const headers = new Headers({
        "content-type": "application/xml",
        "x-amz-checksum-sha256": await sha256Base64(textEncoder.encode(body)),
      });
      appendExpectedBucketOwner(headers, input.expectedBucketOwner);
      const response = await signedFetch("PUT", url, input.region, headers, body);
      await assertS3Response(response, "PutObjectLegalHold");
    },

    async listObjectVersions(input) {
      const versions: S3ObjectVersion[] = [];
      let keyMarker: string | null = null;
      let versionIdMarker: string | null = null;

      while (true) {
        const url = buildS3Url(input.bucket, null, input.region, options.endpointOverride);
        url.searchParams.set("versions", "");
        url.searchParams.set("prefix", input.key);
        url.searchParams.set("max-keys", "1000");
        if (keyMarker) {
          url.searchParams.set("key-marker", keyMarker);
        }
        if (versionIdMarker) {
          url.searchParams.set("version-id-marker", versionIdMarker);
        }

        const headers = new Headers();
        appendExpectedBucketOwner(headers, input.expectedBucketOwner);
        const response = await signedFetch("GET", url, input.region, headers);
        await assertS3Response(response, "ListObjectVersions");
        const parsed = parseListObjectVersionsXml(await response.text(), input.key);
        versions.push(...parsed.versions);

        if (!parsed.isTruncated) {
          break;
        }

        keyMarker = parsed.nextKeyMarker;
        versionIdMarker = parsed.nextVersionIdMarker;
        if (!keyMarker || !versionIdMarker) {
          fail({
            code: "S3_VERSION_PAGINATION_INVALID",
            title: "S3 version pagination invalid",
            detail: "ListObjectVersions returned truncated=true without next markers.",
            category: "external",
            retryable: true,
          });
        }
      }

      return versions;
    },

    async deleteObjectVersion(input) {
      const url = buildS3Url(input.bucket, input.key, input.region, options.endpointOverride);
      if (input.versionId) {
        url.searchParams.set("versionId", input.versionId);
      }
      const headers = new Headers();
      appendExpectedBucketOwner(headers, input.expectedBucketOwner);
      if (input.bypassGovernanceRetention) {
        headers.set("x-amz-bypass-governance-retention", "true");
      }

      const response = await signedFetch("DELETE", url, input.region, headers);
      await assertS3Response(response, "DeleteObject");

      return {
        key: input.key,
        versionId: response.headers.get("x-amz-version-id") ?? input.versionId ?? null,
        deleteMarker: response.headers.get("x-amz-delete-marker") === "true",
        status: response.status,
      };
    },

    async putObject(input) {
      const url = buildS3Url(input.bucket, input.key, input.region, options.endpointOverride);
      const headers = new Headers({
        "content-type": input.contentType,
        "content-length": String(input.body.length),
        "x-amz-checksum-sha256": bytesToBase64(
          new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input.body.slice().buffer as ArrayBuffer))
        ),
      });
      appendExpectedBucketOwner(headers, input.expectedBucketOwner);
      const response = await signedFetch("PUT", url, input.region, headers, input.body);
      await assertS3Response(response, "PutObject");

      return {
        key: input.key,
        versionId: response.headers.get("x-amz-version-id"),
        eTag: stripQuotedHeader(response.headers.get("etag")),
        status: response.status,
      };
    },
  };
}

