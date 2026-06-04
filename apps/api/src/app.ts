import { Hono, type Context, type Next } from "hono";
import type { CoeSigner } from "./crypto";
import type { Sql } from "./types";
import { getLogger } from "./utils";

/**
 * Dependency required to construct the Control Plane HTTP app.
 */
export interface CreateAppOptions {
  sql: Sql,
  controlSchema: string;
  signer: CoeSigner;
  workerSharedSecret: string;
  workerRequestSigningSecret?: string;
  workerRequestSigningMaxSkewMs?: number;
  workerClientName?: string;
  maxOutboxPayloadBytes?: number;
  taskLeaseSeconds?: number;
  taskMaxAttempts?: number;
  taskBaseBackoffMs?: number;
  webhookTimeoutMs?: number;
  shadowBurnInRequired?: boolean;
  shadowRequiredSuccesses?: number;
  adminApiToken: string;
  publicRateLimitWindowMs?: number;
  publicRateLimitMaxRequests?: number;
  now?: () => Date;
}

const logger = getLogger({ component: "http" });
const REQUEST_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/;

function getRequestLogger(c: Context) {
  return logger.child({
    requestId: c.get("requestId"),
    method: c.req.method,
    path: c.req.path,
  });
}

async function requestContextMiddleware(c: Context, next: Next) {
  const incomingRequestId = c.req.header("x-request-id");
  const requestId =
    incomingRequestId && REQUEST_ID_PATTERN.test(incomingRequestId)
      ? incomingRequestId
      : globalThis.crypto.randomUUID();
  c.set("requestId", requestId);
  c.header("x-requesst-id", requestId);

  const startedAt = performance.now();
  try {
    await next();
  } finally {
    const durationMs = Math.round((performance.now() - startedAt) * 100) / 100;
    getRequestLogger(c).info(
      {
        status: c.res.status,
        duration_ms: durationMs,
      },
      "HTTP request completed",
    );
  }
}

/**
 * Builds the Hono application for the control plane.
 *
 * Registers request context middleware, standardized error/not-found handlers,
 * health endpoint, and versioned control-plane routes.
 *
 * @param options - Application dependencies and runtime limits.
 * @returns Configured Hono application instance.
 */
export function createApp(options: CreateAppOptions) {
  const app = new Hono();
}