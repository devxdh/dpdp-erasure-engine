import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { ZodError } from "zod";
import { fail } from "@/errors";
import { requireTenantContext } from "@/http";
import { formatZodIssues, summarizeZodError } from "@/validation";
import {
  createErasureRequestSchema,
  externalSubjectMappingSchema,
  grcErasureWebhookSchema,
  idempotencyKeyParamSchema,
  integrationProviderParamSchema,
  requestIdParamSchema,
  workerAckSchema,
  workerHeaderSchema,
  workerSyncHeaderSchema,
  workerOutboxEventSchema,
} from "./schema";
import type { ControlPlaneService } from "./service";

function validationHook(target: "json" | "header" | "param") {
  return (result: { success: boolean; error?: unknown }) => {
    if (!result.success) {
      const issues = result.error instanceof ZodError ? formatZodIssues(result.error) : undefined;
      fail({
        code: "API_VALIDATION_FAILED",
        title: "Validation failed",
        detail:
          result.error instanceof ZodError ? summarizeZodError(result.error) : `Invalid ${target} payload.`,
        status: 400,
        category: "validation",
        retryable: false,
        context: {
          target,
        },
        issues,
        cause: result.error,
      });
    }
  };
}

function extractBearerToken(authorization: string | null): string {
  if (!authorization?.match(/^Bearer\s+\S+$/i)) {
    fail({
      code: "API_TENANT_AUTH_MISSING",
      title: "Tenant credentials required",
      detail: "Provide Authorization: Bearer <api-key>.",
      status: 401,
      category: "authentication",
      retryable: false,
    });
  }

  return authorization.replace(/^Bearer\s+/i, "");
}

/**
 * Creates control-plane API routes.
 *
 * @param service - Domain service implementing request orchestration and state transitions.
 * @returns Hono router mounted under `/api/v1`.
 */
export function createControlPlaneRouter(service: ControlPlaneService) {
  const router = new Hono();

  async function authorizeWorker(headers: { "x-client-id": string; authorization: string }) {
    const token = headers.authorization.replace(/^Bearer\s+/i, "");
    const authenticatedClientId = await service.authorizeWorker(headers["x-client-id"], token);
    if (!authenticatedClientId) {
      fail({
        code: "API_WORKER_AUTH_INVALID",
        title: "Invalid worker credentials",
        detail: "Worker authentication failed.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    return authenticatedClientId;
  }

  router.post(
    "/erasure-requests",
    zValidator("json", createErasureRequestSchema, validationHook("json")),
    async (c) => {
      const payload = c.req.valid("json");
      const tenant = requireTenantContext(c);
      const created = await service.createErasureRequest(payload, tenant.organizationId);
      return c.json(created, 202);
    }
  );

  router.put(
    "/integrations/:provider/subject-mappings",
    zValidator("param", integrationProviderParamSchema, validationHook("param")),
    zValidator("json", externalSubjectMappingSchema, validationHook("json")),
    async (c) => {
      const tenant = requireTenantContext(c);
      const params = c.req.valid("param");
      const mapping = await service.registerExternalSubjectMapping(
        params.provider,
        c.req.valid("json"),
        tenant.organizationId
      );
      return c.json(mapping, 200);
    }
  );

  router.post(
    "/integrations/:provider/erasure-webhook",
    zValidator("param", integrationProviderParamSchema, validationHook("param")),
    async (c) => {
      const tenant = requireTenantContext(c);
      const params = c.req.valid("param");
      const signingSecret = extractBearerToken(c.req.header("authorization") ?? null);
      const bodyText = await c.req.raw.clone().text();
      let parsedJson: unknown;
      try {
        parsedJson = JSON.parse(bodyText);
      } catch (error) {
        fail({
          code: "API_VALIDATION_FAILED",
          title: "Validation failed",
          detail: "GRC webhook body must be valid JSON.",
          status: 400,
          category: "validation",
          retryable: false,
          cause: error,
        });
      }

      const parsed = grcErasureWebhookSchema.safeParse(parsedJson);
      if (!parsed.success) {
        validationHook("json")({ success: false, error: parsed.error });
        throw new Error("unreachable");
      }

      const result = await service.ingestGrcWebhook(
        params.provider,
        parsed.data,
        tenant.organizationId,
        bodyText,
        c.req.raw.headers,
        signingSecret
      );
      return c.json(result, 202);
    }
  );

  router.post(
    "/erasure-requests/:idempotency_key/cancel",
    zValidator("param", idempotencyKeyParamSchema, validationHook("param")),
    async (c) => {
      const params = c.req.valid("param");
      const tenant = requireTenantContext(c);
      const cancelled = await service.cancelErasureRequest(params.idempotency_key, tenant.organizationId);
      if (!cancelled) {
        fail({
          code: "API_ERASURE_REQUEST_NOT_FOUND",
          title: "Erasure request not found",
          detail: `No erasure request exists for ${params.idempotency_key}.`,
          status: 404,
          category: "validation",
          retryable: false,
        });
      }

      return c.json(cancelled, 200);
    }
  );

  router.get("/worker/sync", zValidator("header", workerSyncHeaderSchema, validationHook("header")), async (c) => {
    const header = c.req.valid("header");
    const clientId = await authorizeWorker(header);
    const synced = await service.syncWorker(header["x-client-id"], clientId, {
      configHash: header["x-worker-config-hash"].toLowerCase(),
      configVersion: header["x-worker-config-version"],
      dpoIdentifier: header["x-worker-dpo-identifier"],
    });
    return c.json(synced, 200);
  });

  router.post(
    "/worker/tasks/:taskId/ack",
    zValidator("header", workerHeaderSchema, validationHook("header")),
    zValidator("json", workerAckSchema, validationHook("json")),
    async (c) => {
      const header = c.req.valid("header");
      await authorizeWorker(header);
      const result = await service.ackWorkerTask(c.req.param("taskId"), c.req.valid("json"));
      if (!result) {
        fail({
          code: "API_TASK_NOT_FOUND",
          title: "Task not found",
          detail: `Task ${c.req.param("taskId")} does not exist.`,
          status: 404,
          category: "validation",
          retryable: false,
        });
      }

      return c.json({ ok: true, ...result }, 200);
    }
  );

  router.post(
    "/worker/tasks/:taskId/heartbeat",
    zValidator("header", workerHeaderSchema, validationHook("header")),
    async (c) => {
      const header = c.req.valid("header");
      const clientId = await authorizeWorker(header);
      const result = await service.heartbeatWorkerTask(c.req.param("taskId"), clientId, header["x-client-id"]);
      if (!result) {
        fail({
          code: "API_TASK_LEASE_NOT_ACTIVE",
          title: "Task lease is not active",
          detail: `Task ${c.req.param("taskId")} is not actively leased by this worker.`,
          status: 409,
          category: "concurrency",
          retryable: true,
        });
      }

      return c.json({ ok: true, ...result }, 200);
    }
  );

  router.post(
    "/worker/outbox",
    zValidator("header", workerHeaderSchema, validationHook("header")),
    zValidator("json", workerOutboxEventSchema, validationHook("json")),
    async (c) => {
      const header = c.req.valid("header");
      const clientId = await authorizeWorker(header);
      const result = await service.ingestWorkerOutbox(c.req.valid("json"), clientId);
      return c.json(result, 202);
    }
  );

  router.get("/certificates/:requestId",
    zValidator("param", requestIdParamSchema, validationHook("param")),
    async (c) => {
      const params = c.req.valid("param");
      const tenant = requireTenantContext(c);
      const certificate = await service.getCertificate(params.requestId, tenant.organizationId);
      if (!certificate) {
        fail({
          code: "API_CERTIFICATE_NOT_FOUND",
          title: "Certificate not found",
          detail: `Certificate ${params.requestId} does not exist.`,
          status: 404,
          category: "validation",
          retryable: false,
        });
      }

      return c.json(
        {
          request_id: certificate.request_id,
          subject_opaque_id: certificate.subject_opaque_id,
          method: certificate.method,
          legal_framework: certificate.legal_framework,
          applied_rule_name:
            typeof (certificate.payload as Record<string, unknown>)?.applied_rule_name === "string"
              ? ((certificate.payload as Record<string, unknown>).applied_rule_name as string)
              : null,
          applied_rule_citation:
            typeof (certificate.payload as Record<string, unknown>)?.applied_rule_citation === "string"
              ? ((certificate.payload as Record<string, unknown>).applied_rule_citation as string)
              : null,
          shredded_at: certificate.shredded_at.toISOString(),
          final_worm_hash:
            typeof (certificate.payload as Record<string, unknown>)?.final_worm_hash === "string"
              ? ((certificate.payload as Record<string, unknown>).final_worm_hash as string)
              : null,
          blob_receipts: Array.isArray((certificate.payload as Record<string, unknown>)?.blob_receipts)
            ? ((certificate.payload as Record<string, unknown>).blob_receipts as unknown[])
            : [],
          postgres_transaction_ids: Array.isArray((certificate.payload as Record<string, unknown>)?.postgres_transaction_ids)
            ? ((certificate.payload as Record<string, unknown>).postgres_transaction_ids as unknown[])
            : [],
          signature: {
            algorithm: certificate.algorithm,
            key_id: certificate.key_id,
            signature_base64: certificate.signature_base64,
            public_key_spki_base64: certificate.public_key_spki_base64,
          },
        },
        200
      );
    });

  router.get("/certificates/:requestId/verify",
    zValidator("param", requestIdParamSchema, validationHook("param")),
    async (c) => {
      const params = c.req.valid("param");
      const tenant = requireTenantContext(c);
      const verification = await service.verifyCertificate(params.requestId, tenant.organizationId);
      if (!verification) {
        fail({
          code: "API_CERTIFICATE_NOT_FOUND",
          title: "Certificate not found",
          detail: `Certificate ${params.requestId} does not exist.`,
          status: 404,
          category: "validation",
          retryable: false,
        });
      }

      return c.json(verification, 200);
    });

  router.get(
    "/certificates/:requestId/download",
    zValidator("param", requestIdParamSchema, validationHook("param")),
    async (c) => {
      const params = c.req.valid("param");
      const tenant = requireTenantContext(c);
      const pdf = await service.getCertificatePdf(params.requestId, tenant.organizationId);
      if (!pdf) {
        fail({
          code: "API_CERTIFICATE_NOT_FOUND",
          title: "Certificate not found",
          detail: `Certificate ${params.requestId} does not exist.`,
          status: 404,
          category: "validation",
          retryable: false,
        });
      }

      return new Response(pdf, {
        status: 200,
        headers: {
          "content-type": "application/pdf",
          "content-disposition": `attachment; filename="certificate-${params.requestId}.pdf"`,
        },
      });
    }
  );

  return router;
}
