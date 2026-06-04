import { Hono } from "hono";
import type { Context, Next } from "hono";
import { secureHeaders } from "hono/secure-headers";
import type { CoeSigner } from "./crypto";
import {
  handleApiError,
  handleNotFound,
  PostgresRateLimiter,
  createRateLimitMiddleware,
  createWorkerRequestSigningMiddleware,
  createTenantAuthMiddleware
} from "./http";
import { createAdminRouter, AdminService } from "./modules/admin";
import { createOrgRouter } from "./modules/org/router";
import { ControlPlaneRepository, createControlPlaneRouter, ControlPlaneService } from "./modules/control-plane";
import { createUnifiedWebhookRouter } from "./modules/webhooks";
import {
  apiMetricsMiddleware,
  recordOperationalMetricSnapshot,
  renderApiMetrics,
  getLogger
} from "./observability";
import type { Sql } from "./types";

/**
 * Dependencies required to construct the Control Plane HTTP app.
 */
export interface CreateAppOptions {
  sql: Sql;
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
  c.header("x-request-id", requestId);

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
      "HTTP request completed"
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
  const repository = new ControlPlaneRepository(
    options.sql,
    options.controlSchema,
    options.taskLeaseSeconds ?? 60,
    options.taskMaxAttempts ?? 10,
    options.taskBaseBackoffMs ?? 1000
  );

  const service = new ControlPlaneService({
    repository,
    signer: options.signer,
    workerSharedSecret: options.workerSharedSecret,
    workerClientName: options.workerClientName ?? "worker-1",
    maxOutboxPayloadBytes: options.maxOutboxPayloadBytes ?? 32_768,
    webhookTimeoutMs: options.webhookTimeoutMs,
    shadowBurnInRequired: options.shadowBurnInRequired,
    shadowRequiredSuccesses: options.shadowRequiredSuccesses,
    now: options.now,
  });

  const adminService = new AdminService({
    repository,
    now: options.now,
  });

  const publicRateLimiter = new PostgresRateLimiter(
    options.sql,
    options.controlSchema,
    options.publicRateLimitWindowMs ?? 60_000,
    options.publicRateLimitMaxRequests ?? 60
  );

  app.use("*", secureHeaders());
  app.use("*", requestContextMiddleware);
  app.use("*", apiMetricsMiddleware);
  app.use("/api/v1/erasure-requests", createRateLimitMiddleware(publicRateLimiter));
  app.use("/api/v1/integrations/*", createRateLimitMiddleware(publicRateLimiter));
  app.use("/api/v1/webhooks/*", createRateLimitMiddleware(publicRateLimiter));
  app.use("/api/v1/certificates/*", createRateLimitMiddleware(publicRateLimiter));
  app.use(
    "/api/v1/erasure-requests",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["erasure:write"])
  );
  app.use(
    "/api/v1/erasure-requests/*",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["erasure:write"])
  );
  app.use(
    "/api/v1/integrations/*",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["erasure:write"])
  );
  app.use(
    "/api/v1/admin/*",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["admin:all"])
  );
  app.use(
    "/api/v1/certificates/*",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["audit:read"])
  );
  app.use(
    "/api/v1/org/*",
    createTenantAuthMiddleware(repository, options.adminApiToken, ["org:admin"])
  );
  app.use(
    "/api/v1/worker/*",
    createWorkerRequestSigningMiddleware(
      options.workerRequestSigningSecret,
      options.workerRequestSigningMaxSkewMs ?? 60_000,
      options.sql,
      options.controlSchema
    )
  );

  app.onError(handleApiError);
  app.notFound(handleNotFound);

  app.get("/health", (c) => c.json({ ok: true }, 200));
  app.get("/ready", async (c) => {
    try {
      await options.sql`SELECT 1`;
      return c.json({ ok: true }, 200);
    } catch {
      return c.json({ ok: false }, 503);
    }
  });
  app.get("/metrics", async () => {
    recordOperationalMetricSnapshot(await repository.getOperationalMetricRows());
    return new Response(await renderApiMetrics(), {
      status: 200,
      headers: {
        "content-type": "text/plain; version=0.0.4; charset=utf-8",
      },
    });
  });
  app.route("/api/v1", createControlPlaneRouter(service));
  app.route("/api/v1/webhooks", createUnifiedWebhookRouter({
    sql: options.sql,
    controlSchema: options.controlSchema,
    now: options.now,
  }));
  app.route("/api/v1/admin", createAdminRouter(adminService));
  app.route("/api/v1/org", createOrgRouter(adminService));

  const appWithServices = app as typeof app & {
    app: typeof app;
    controlPlaneService: ControlPlaneService;
  };
  appWithServices.app = app;
  appWithServices.controlPlaneService = service;
  return appWithServices;
}
