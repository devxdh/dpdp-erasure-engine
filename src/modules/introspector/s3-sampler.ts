import { fail } from "@/errors";
import type { S3AwsCredentials } from "../network/object-store/aws/type";
import { resolveAwsCredentials } from "../network";
import { signAwsRequest } from "../network/object-store/aws/sigv4";

export interface S3ChunkSampleOptions {
  bucket: string;
  key: string;
  region: string;
  credentials?: S3AwsCredentials;
  env?: Record<string, string | undefined>;
  fetchFn?: typeof fetch;
  maxBytes?: number;
  timeoutMs?: number;
}

export interface S3ClassificationSample {
  bytes: Uint8Array;
  warnings: string[];
  binaryFormat: "parquet" | "avro" | null;
  decompressed: boolean;
}

function encodeS3KeyPath(key: string): string {
  return `/${key.split("/").map((segment) => encodeURIComponent(segment)).join("/")}`;
}

function hasPrefix(bytes: Uint8Array, prefix: readonly number[]): boolean {
  if (bytes.length < prefix.length) {
    return false;
  }

  return prefix.every((byte, index) => bytes[index] === byte);
}

function detectBinaryFormat(key: string, bytes: Uint8Array, contentType: string | null): "parquet" | "avro" | null {
  const normalizedKey = key.toLowerCase();
  const normalizedContentType = contentType?.toLowerCase() ?? "";
  if (normalizedKey.endsWith(".parquet") || normalizedContentType.includes("parquet") || hasPrefix(bytes, [0x50, 0x41, 0x52, 0x31])) {
    return "parquet";
  }

  if (normalizedKey.endsWith(".avro") || normalizedContentType.includes("avro") || hasPrefix(bytes, [0x4f, 0x62, 0x6a, 0x01])) {
    return "avro";
  }

  return null;
}

function shouldGunzip(key: string, contentEncoding: string | null, contentType: string | null): boolean {
  const normalizedKey = key.toLowerCase();
  const normalizedEncoding = contentEncoding?.toLowerCase() ?? "";
  const normalizedContentType = contentType?.toLowerCase() ?? "";
  return (
    normalizedKey.endsWith(".gz") ||
    normalizedKey.endsWith(".gzip") ||
    normalizedEncoding.includes("gzip") ||
    normalizedContentType.includes("gzip")
  );
}

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer as ArrayBuffer;
}

async function gunzipBytes(bytes: Uint8Array): Promise<Uint8Array> {
  if (typeof DecompressionStream !== "undefined") {
    const stream = new Blob([copyToArrayBuffer(bytes)]).stream().pipeThrough(new DecompressionStream("gzip"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }

  fail({
    code: "INTROSPECTOR_GZIP_UNSUPPORTED",
    title: "Gzip decompression unavailable",
    detail: "Runtime does not expose the Web DecompressionStream API required for non-blocking gzip introspection.",
    category: "configuration",
    retryable: false,
    fatal: true,
  });
}

/**
 * Fetches a bounded S3 object prefix using SigV4 and an HTTP Range request.
 *
 * The returned buffer may contain raw PII. Callers must finish classification and then
 * wipe it with `.fill(0)` in a `finally` block.
 *
 * @param options - S3 target, credentials, and byte limit.
 * @returns First object chunk, capped at `maxBytes`.
 * @throws {WorkerError} When S3 rejects or cannot serve the bounded request.
 */
export async function sampleS3ObjectChunk(options: S3ChunkSampleOptions): Promise<Uint8Array> {
  const sample = await sampleS3ObjectForClassification(options);
  return sample.bytes;
}

/**
 * Fetches a bounded S3 object prefix and normalizes it for PII classification.
 *
 * Gzip prefixes are decompressed with Bun-native zlib utilities. Parquet and Avro prefixes are
 * flagged as binary structured formats and returned as an empty wiped-safe byte view because regex
 * scanning their binary pages creates high false-positive rates.
 *
 * @param options - S3 target, credentials, and byte limit.
 * @returns Classification sample bytes plus structural warnings.
 * @throws {WorkerError} When S3 rejects or cannot serve the bounded request.
 */
export async function sampleS3ObjectForClassification(options: S3ChunkSampleOptions): Promise<S3ClassificationSample> {
  const maxBytes = options.maxBytes ?? 1_048_576;
  if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > 1_048_576) {
    fail({
      code: "INTROSPECTOR_S3_RANGE_INVALID",
      title: "Invalid S3 introspection range",
      detail: "S3 introspection reads are capped at 1 MiB.",
      category: "validation",
      retryable: false,
      context: { maxBytes },
    });
  }

  const fetchFn = options.fetchFn ?? fetch;
  const timeoutMs = options.timeoutMs ?? 10_000;
  const url = new URL(`https://${options.bucket}.s3.${options.region}.amazonaws.com${encodeS3KeyPath(options.key)}`);
  const headers = new Headers({
    range: `bytes=0-${maxBytes - 1}`,
  });
  const credentials = options.credentials ?? await resolveAwsCredentials({
    env: options.env,
    fetchFn,
    timeoutMs: Math.min(timeoutMs, 2_000),
  });
  const signedHeaders = await signAwsRequest({
    method: "GET",
    url,
    region: options.region,
    service: "s3",
    headers,
    credentials,
  });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchFn(url, {
      method: "GET",
      headers: signedHeaders,
      signal: controller.signal,
      redirect: "error",
    });

    if (!response.ok && response.status !== 206) {
      fail({
        code: response.status >= 500 || response.status === 429
          ? "INTROSPECTOR_S3_RETRYABLE"
          : "INTROSPECTOR_S3_REJECTED",
        title: "S3 introspection failed",
        detail: `S3 range request returned HTTP ${response.status}.`,
        category: response.status >= 500 || response.status === 429 ? "network" : "external",
        retryable: response.status >= 500 || response.status === 429,
        fatal: response.status === 401 || response.status === 403,
        context: { bucket: options.bucket, region: options.region },
      });
    }

    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.byteLength > maxBytes) {
      bytes.fill(0);
      fail({
        code: "INTROSPECTOR_S3_RANGE_EXCEEDED",
        title: "S3 introspection range exceeded",
        detail: "S3 returned more bytes than the configured hard cap.",
        category: "external",
        retryable: false,
        fatal: true,
        context: { maxBytes },
      });
    }

    const contentType = response.headers.get("content-type");
    const contentEncoding = response.headers.get("content-encoding");
    const binaryFormat = detectBinaryFormat(options.key, bytes, contentType);
    if (binaryFormat) {
      bytes.fill(0);
      return {
        bytes: new Uint8Array(0),
        warnings: ["BINARY_FORMAT_DETECTED: Structural Metadata Scan Required."],
        binaryFormat,
        decompressed: false,
      };
    }

    if (!shouldGunzip(options.key, contentEncoding, contentType)) {
      return {
        bytes,
        warnings: [],
        binaryFormat: null,
        decompressed: false,
      };
    }

    try {
      const decompressed = await gunzipBytes(bytes);
      bytes.fill(0);
      return {
        bytes: decompressed,
        warnings: [],
        binaryFormat: null,
        decompressed: true,
      };
    } catch {
      bytes.fill(0);
      fail({
        code: "INTROSPECTOR_S3_GZIP_INVALID",
        title: "S3 gzip introspection failed",
        detail: "S3 object prefix was marked gzip but could not be decompressed.",
        category: "external",
        retryable: false,
        fatal: false,
        context: { bucket: options.bucket, key: options.key },
      });
    }
  } finally {
    clearTimeout(timer);
  }
}
