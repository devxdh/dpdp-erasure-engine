import { Hono } from "hono";
import { zValidator } from "@hono/zod-validator";
import { fail } from "@/errors";
import { requireTenantContext } from "@/http";
import { adminCreateApiKeySchema, type AdminService } from "@modules/admin";

function validationHook(target: "json") {
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
 * Creates tenant self-service organization routes.
 *
 * @param service - Admin service reused for tenant organization operations.
 * @returns Hono router mounted under `/api/v1/org`.
 */
export function createOrgRouter(service: AdminService) {
  const router = new Hono();

  router.get("/members", async (c) => c.json(await service.listMembers(requireTenantContext(c)), 200));

  router.post(
    "/api-keys",
    zValidator("json", adminCreateApiKeySchema, validationHook("json")),
    async (c) => c.json(await service.createApiKey(c.req.valid("json"), requireTenantContext(c)), 201)
  );

  return router;
}
