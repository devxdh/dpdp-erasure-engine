import { fail, type ApiErrorCode } from "@/errors";
import { promises as dns } from "node:dns";

/**
 * Structured webhook URL validation failure used by both ingestion-time and dispatch-time checks.
 */
export interface WebhookUrlViolation {
  code: ApiErrorCode;
  detail: string;
}

function parseIpv4(hostname: string): [number, number, number, number] | null {
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname)) {
    return null;
  }

  const octets = hostname.split(".").map((segment) => Number(segment));
  if (octets.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
    return null;
  }

  const [a, b, c, d] = octets;
  if (a === undefined || b === undefined || c === undefined || d === undefined) {
    return null;
  }

  return [a, b, c, d];
}

function isPrivateOrSpecialIpv4(hostname: string): boolean {
  const octets = parseIpv4(hostname);
  if (!octets) {
    return false;
  }

  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    (a === 198 && b === 51) ||
    (a === 203 && b === 0) ||
    a >= 224
  );
}

function isIpv6Literal(hostname: string): boolean {
  return hostname.includes(":");
}

function isPrivateOrSpecialIpv6(hostname: string): boolean {
  const normalized = hostname.toLowerCase();
  if (!isIpv6Literal(normalized)) {
    return false;
  }

  if (normalized === "::" || normalized === "::1") {
    return true;
  }

  if (normalized.startsWith("fe80:") || normalized.startsWith("ff")) {
    return true;
  }

  if (normalized.startsWith("fc") || normalized.startsWith("fd")) {
    return true;
  }

  const mappedIpv4Candidate = normalized.slice(normalized.lastIndexOf(":") + 1);
  return isPrivateOrSpecialIpv4(mappedIpv4Candidate);
}

function isUnsafeResolvedAddress(address: string): boolean {
  return isPrivateOrSpecialIpv4(address) || isPrivateOrSpecialIpv6(address);
}

/**
 * Returns a deterministic validation failure when a client-supplied webhook target violates
 * Control Plane egress rules.
 *
 * The API accepts only externally routable HTTPS webhook endpoints. Literal loopback/private
 * network hosts are rejected to reduce SSRF blast radius from client-supplied callback URLs.
 *
 * @param rawValue - Raw URL string supplied by the client or loaded from storage.
 * @returns Violation descriptor or `null` when the URL is acceptable.
 */
export function getWebhookUrlViolation(rawValue: string): WebhookUrlViolation | null {
  let url: URL;
  try {
    url = new URL(rawValue);
  } catch {
    return {
      code: "API_WEBHOOK_URL_INVALID",
      detail: "webhook_url must be a valid absolute URL.",
    };
  }

  if (url.protocol !== "https:") {
    return {
      code: "API_WEBHOOK_URL_PROTOCOL_INVALID",
      detail: "webhook_url must use HTTPS.",
    };
  }

  if (url.username || url.password) {
    return {
      code: "API_WEBHOOK_URL_CREDENTIALS_FORBIDDEN",
      detail: "webhook_url must not embed credentials.",
    };
  }

  const hostname = url.hostname.toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost")) {
    return {
      code: "API_WEBHOOK_URL_HOST_FORBIDDEN",
      detail: "webhook_url must not target localhost.",
    };
  }

  if (isPrivateOrSpecialIpv4(hostname) || isPrivateOrSpecialIpv6(hostname)) {
    return {
      code: "API_WEBHOOK_URL_HOST_FORBIDDEN",
      detail: "webhook_url must not target loopback, private, link-local, or special-use network ranges.",
    };
  }

  return null;
}

/**
 * Parses and enforces Control Plane webhook egress rules.
 *
 * @param rawValue - Raw URL string supplied by the client or loaded from storage.
 * @returns Parsed URL ready for outbound dispatch.
 * @throws {ApiError} When the URL violates Control Plane SSRF guardrails.
 */
export function assertSafeWebhookUrl(rawValue: string): URL {
  const violation = getWebhookUrlViolation(rawValue);
  if (violation) {
    fail({
      code: violation.code,
      title: "Invalid webhook URL",
      detail: violation.detail,
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  return new URL(rawValue);
}

/**
 * Resolves a webhook hostname at dispatch time and rejects DNS answers that target private or special-use ranges.
 *
 * This closes the gap where a client-supplied public hostname later rebinds to an internal address after the
 * ingestion-time URL validation has already succeeded.
 *
 * @param rawValue - Stored webhook URL.
 * @returns Parsed URL ready for outbound dispatch.
 * @throws {ApiError} When DNS resolution yields unsafe addresses.
 */
export async function assertSafeWebhookDispatchTarget(rawValue: string): Promise<URL> {
  const url = assertSafeWebhookUrl(rawValue);
  const hostname = url.hostname.toLowerCase();

  if (parseIpv4(hostname) || isIpv6Literal(hostname)) {
    return url;
  }

  const [ipv4Results, ipv6Results] = await Promise.allSettled([
    dns.resolve4(hostname),
    dns.resolve6(hostname),
  ]);

  const resolvedAddresses = [
    ...(ipv4Results.status === "fulfilled" ? ipv4Results.value : []),
    ...(ipv6Results.status === "fulfilled" ? ipv6Results.value : []),
  ];

  if (resolvedAddresses.some(isUnsafeResolvedAddress)) {
    fail({
      code: "API_WEBHOOK_URL_HOST_FORBIDDEN",
      title: "Invalid webhook URL",
      detail: "webhook_url resolved to a loopback, private, link-local, or special-use network range.",
      status: 502,
      category: "external",
      retryable: false,
    });
  }

  return url;
}
