import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { fail } from "@/errors";
import { requireTenantContext } from "@/http";
import {
  adminAuditExportQuerySchema,
  adminApproveWorkerConfigSchema,
  adminBulkPurgeSchema,
  adminClientNameParamSchema,
  adminCreateApiKeySchema,
  adminCreateClientSchema,
  adminCreateOrganizationSchema,
  adminErasureRequestQuerySchema,
  adminProviderCompletionTargetSchema,
  adminProviderParamSchema,
  adminRotateWebhookSecretSchema,
  adminRequestIdParamSchema,
  adminTaskIdParamSchema,
  adminWorkerConfigHashParamSchema,
} from "./schemas";
import type { AdminService } from "./service";

function validationHook(target: "json" | "param" | "query") {
  return (result: { success: boolean; error?: unknown }) => {
    if (!result.success) {
      fail({
        code: "API_VALIDATION_FAILED",
        title: "Validation failed",
        detail: `Invalid ${target} payload.`,
        status: 400,
        category: "validation",
        retryable: false,
        cause: result.error,
      });
    }
  };
}

/**
 * Creates operator-only admin routes for client management, recovery, reporting, and exports.
 *
 * @param service - Admin domain service.
 * @returns Hono router mounted under `/api/v1/admin`.
 */
export function createAdminRouter(service: AdminService) {
  const router = new Hono();

  router.get("/clients", async (c) => c.json(await service.listClients(requireTenantContext(c)), 200));

  router.post(
    "/clients",
    zValidator("json", adminCreateClientSchema, validationHook("json")),
    async (c) => {
      const created = await service.createClient(c.req.valid("json"), requireTenantContext(c));
      return c.json(created, 201);
    }
  );

  router.post(
    "/clients/:name/rotate-key",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    async (c) => {
      const rotated = await service.rotateClientKey(c.req.valid("param").name, requireTenantContext(c));
      return c.json(rotated, 200);
    }
  );

  router.post(
    "/clients/:name/rotate-webhook-secret",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    zValidator("json", adminRotateWebhookSecretSchema, validationHook("json")),
    async (c) => {
      const rotated = await service.rotateClientWebhookSecret(
        c.req.valid("param").name,
        c.req.valid("json"),
        requireTenantContext(c)
      );
      return c.json(rotated, 200);
    }
  );

  router.get(
    "/clients/:name/provider-completions",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    async (c) =>
      c.json(
        await service.listProviderCompletionTargets(c.req.valid("param").name, requireTenantContext(c)),
        200
      )
  );

  router.put(
    "/clients/:name/provider-completions/:provider",
    zValidator("param", adminProviderParamSchema, validationHook("param")),
    zValidator("json", adminProviderCompletionTargetSchema, validationHook("json")),
    async (c) => {
      const params = c.req.valid("param");
      return c.json(
        await service.upsertProviderCompletionTarget(
          params.name,
          params.provider,
          c.req.valid("json"),
          requireTenantContext(c)
        ),
        200
      );
    }
  );

  router.post(
    "/clients/:name/deactivate",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    async (c) => c.json(await service.deactivateClient(c.req.valid("param").name, requireTenantContext(c)), 200)
  );

  router.get(
    "/clients/:name/config-releases",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    async (c) => c.json(await service.listWorkerConfigReleases(c.req.valid("param").name, requireTenantContext(c)), 200)
  );

  router.post(
    "/clients/:name/config-releases",
    zValidator("param", adminClientNameParamSchema, validationHook("param")),
    zValidator("json", adminApproveWorkerConfigSchema, validationHook("json")),
    async (c) =>
      c.json(
        await service.approveWorkerConfigRelease(
          c.req.valid("param").name,
          c.req.valid("json"),
          requireTenantContext(c)
        ),
        201
      )
  );

  router.post(
    "/clients/:name/config-releases/:configHash/revoke",
    zValidator("param", adminWorkerConfigHashParamSchema, validationHook("param")),
    async (c) => {
      const params = c.req.valid("param");
      return c.json(
        await service.revokeWorkerConfigRelease(params.name, params.configHash.toLowerCase(), requireTenantContext(c)),
        200
      );
    }
  );

  router.get("/tasks/dead-letters", async (c) => c.json(await service.listDeadLetters(requireTenantContext(c)), 200));

  router.post(
    "/tasks/:taskId/requeue",
    zValidator("param", adminTaskIdParamSchema, validationHook("param")),
    async (c) => c.json(await service.requeueDeadLetter(c.req.valid("param").taskId, requireTenantContext(c)), 200)
  );

  router.get(
    "/erasure-requests",
    zValidator("query", adminErasureRequestQuerySchema, validationHook("query")),
    async (c) => c.json(await service.listErasureRequests(c.req.valid("query"), requireTenantContext(c)), 200)
  );

  router.get(
    "/erasure-requests/:requestId",
    zValidator("param", adminRequestIdParamSchema, validationHook("param")),
    async (c) => c.json(await service.getErasureRequest(c.req.valid("param").requestId, requireTenantContext(c)), 200)
  );

  router.post(
    "/purge-runs",
    zValidator("json", adminBulkPurgeSchema, validationHook("json")),
    async (c) => c.json(await service.createBulkPurge(c.req.valid("json"), requireTenantContext(c)), 202)
  );

  router.get(
    "/audit/export",
    zValidator("query", adminAuditExportQuerySchema, validationHook("query")),
    async (c) => {
      const rows = await service.exportAuditLedger(c.req.valid("query"), requireTenantContext(c));
      const payload = rows.map((row) => JSON.stringify(row)).join("\n");
      return new Response(payload, {
        status: 200,
        headers: {
          "content-type": "application/x-ndjson; charset=utf-8",
        },
      });
    }
  );

  router.get(
    "/audit/verify",
    zValidator("query", adminAuditExportQuerySchema, validationHook("query")),
    async (c) => c.json(await service.verifyAuditLedger(c.req.valid("query"), requireTenantContext(c)), 200)
  );

  router.post(
    "/organizations",
    zValidator("json", adminCreateOrganizationSchema, validationHook("json")),
    async (c) => c.json(await service.createOrganization(c.req.valid("json")), 201)
  );

  router.get("/org/members", async (c) => c.json(await service.listMembers(requireTenantContext(c)), 200));

  router.post(
    "/org/api-keys",
    zValidator("json", adminCreateApiKeySchema, validationHook("json")),
    async (c) => c.json(await service.createApiKey(c.req.valid("json"), requireTenantContext(c)), 201)
  );

  return router;
}
