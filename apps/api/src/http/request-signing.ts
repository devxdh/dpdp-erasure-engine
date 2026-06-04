import type { Context, Next } from "hono";
import type postgres from "postgres";
import { assertIdentifier } from "../db/identifiers";
import { fail } from "../errors";
import { computeHmacSha256Hex, verifyHmacSha256Hex } from "@/crypto";

const textEncoder = new TextEncoder();
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", textEncoder.encode(value));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Computes the canonical worker/API request signature.
 *
 * @param secret - Shared HMAC secret.
 * @param method - HTTP method.
 * @param path - Request path.
 * @param clientId - Worker client identifier.
 * @param timestamp - Unix epoch milliseconds string.
 * @param nonce - Optional per-request nonce used to prevent same-millisecond multi-worker collisions.
 * @param bodyText - Exact request body text.
 * @returns Lowercase hex HMAC digest.
 */
export async function computeRequestSignature(
  secret: string,
  method: string,
  path: string,
  clientId: string,
  timestamp: string,
  bodyText: string,
  nonce: string = ""
): Promise<string> {
  const parts = nonce
    ? [method.toUpperCase(), path, clientId, timestamp, nonce, bodyText]
    : [method.toUpperCase(), path, clientId, timestamp, bodyText];
  return computeHmacSha256Hex(
    secret,
    parts.join("\n")
  );
}

/**
 * Creates middleware verifying HMAC-signed worker requests within a bounded clock-skew window.
 *
 * @param secret - Shared HMAC secret. When absent, request signing is disabled.
 * @param maxSkewMs - Allowed timestamp skew in milliseconds.
 * @returns Hono middleware for worker routes.
 */
export function createWorkerRequestSigningMiddleware(
  secret: string | undefined,
  maxSkewMs: number,
  sql?: postgres.Sql,
  controlSchema?: string
) {
  return async (c: Context, next: Next): Promise<void> => {
    if (!secret) {
      await next();
      return;
    }

    const clientId = c.req.header("x-client-id") ?? "";
    const timestamp = c.req.header("x-dpdp-timestamp");
    const signature = c.req.header("x-dpdp-signature");
    const nonce = c.req.header("x-dpdp-nonce") ?? "";
    if (!timestamp || !signature || !clientId || !UUID_PATTERN.test(clientId)) {
      fail({
        code: "API_WORKER_SIGNATURE_MISSING",
        title: "Missing worker request signature",
        detail: "Worker request signing headers are required and x-client-id must be a UUID.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    const timestampMs = Number(timestamp);
    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > maxSkewMs) {
      fail({
        code: "API_WORKER_SIGNATURE_EXPIRED",
        title: "Expired worker request signature",
        detail: "Worker request signature timestamp is outside the allowed clock-skew window.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    const bodyText = c.req.method === "GET" ? "" : await c.req.raw.clone().text();
    const signedPayload = [c.req.method.toUpperCase(), c.req.path, clientId, timestamp, nonce, bodyText].join("\n");
    const legacySignedPayload = [c.req.method.toUpperCase(), c.req.path, clientId, timestamp, bodyText].join("\n");
    if (!await verifyHmacSha256Hex(secret, signedPayload, signature)) {
      if (nonce || !await verifyHmacSha256Hex(secret, legacySignedPayload, signature)) {
        fail({
          code: "API_WORKER_SIGNATURE_INVALID",
          title: "Invalid worker request signature",
          detail: "Worker request signature verification failed.",
          status: 401,
          category: "authentication",
          retryable: false,
        });
      }
    }

    if (sql && controlSchema) {
      const schema = assertIdentifier(controlSchema, "control schema name");
      const signatureHash = await sha256Hex(signature);
      const requestTimestamp = new Date(timestampMs);
      const expiresAt = new Date(timestampMs + maxSkewMs);
      const rows = await sql<{ signature_hash: string }[]>`
        WITH cleanup AS (
          DELETE FROM ${sql(schema)}.worker_request_replays
          WHERE expires_at < NOW()
        )
        INSERT INTO ${sql(schema)}.worker_request_replays (
          client_id,
          signature_hash,
          request_timestamp,
          expires_at
        )
        SELECT
          ${clientId}::uuid,
          ${signatureHash},
          ${requestTimestamp},
          ${expiresAt}
        WHERE EXISTS (
          SELECT 1
          FROM ${sql(schema)}.clients
          WHERE id = ${clientId}::uuid
        )
        ON CONFLICT (client_id, signature_hash) DO NOTHING
        RETURNING signature_hash
      `;

      const [clientExists] = await sql<{ exists: boolean }[]>`
        SELECT EXISTS (
          SELECT 1
          FROM ${sql(schema)}.clients
          WHERE id = ${clientId}::uuid
        ) AS exists
      `;

      if (clientExists?.exists && rows.length === 0) {
        fail({
          code: "API_WORKER_SIGNATURE_REPLAYED",
          title: "Replayed worker request signature",
          detail: "Worker request signature has already been accepted within the replay window.",
          status: 409,
          category: "authentication",
          retryable: false,
        });
      }
    }

    await next();
  };
}
