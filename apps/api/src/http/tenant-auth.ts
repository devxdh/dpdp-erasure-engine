import type { Context, Next } from "hono";
import { fail } from "../errors";
import { computeTokenHash } from "../modules/control-plane/hash";
import type { ControlPlaneRepository } from "../modules/control-plane/repository";

export interface TenantContext {
  organizationId: string;
  authType: "api_key";
  scopes: string[];
  keyId: string;
}

export interface TenantVariables {
  tenantContext: TenantContext;
}

function hasScope(scopes: string[], requiredScopes: string[]): boolean {
  if (scopes.includes("*")) {
    return true;
  }
  return requiredScopes.every((scope) => scopes.includes(scope));
}

function extractBearerToken(c: Context): string {
  const authorization = c.req.header("authorization");
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
 * Authenticates a Control Plane tenant API key and stores tenant context on Hono.
 *
 * @param repository - Control Plane repository used for API key lookup.
 * @param bootstrapAdminToken - Optional first-run token seeded into the DB-backed `api_keys` table.
 * @param requiredScopes - Scopes required for this route group.
 * @returns Hono middleware.
 */
export function createTenantAuthMiddleware(
  repository: ControlPlaneRepository,
  bootstrapAdminToken: string,
  requiredScopes: string[]
) {
  return async (c: Context, next: Next) => {
    const token = extractBearerToken(c);
    const hashedKey = await computeTokenHash(token);
    const now = new Date();

    let apiKey = await repository.authenticateApiKey(hashedKey, now);
    if (!apiKey && token === bootstrapAdminToken) {
      apiKey = await repository.ensureBootstrapApiKey(hashedKey, now);
    }

    if (!apiKey) {
      fail({
        code: "API_TENANT_AUTH_INVALID",
        title: "Invalid tenant credentials",
        detail: "API key authentication failed.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    if (!hasScope(apiKey.scopes, requiredScopes)) {
      fail({
        code: "API_TENANT_SCOPE_DENIED",
        title: "Insufficient API key scope",
        detail: `Required scopes: ${requiredScopes.join(", ")}.`,
        status: 403,
        category: "authorization",
        retryable: false,
      });
    }

    c.set("tenantContext", {
      organizationId: apiKey.organization_id,
      authType: "api_key",
      scopes: apiKey.scopes,
      keyId: apiKey.id,
    });

    await next();
  };
}

/**
 * Reads the tenant context set by `createTenantAuthMiddleware`.
 *
 * @param c - Hono request context.
 * @returns Authenticated tenant context.
 */
export function requireTenantContext(c: Context): TenantContext {
  const context = c.get("tenantContext") as TenantContext | undefined;
  if (!context) {
    fail({
      code: "API_TENANT_CONTEXT_MISSING",
      title: "Tenant context missing",
      detail: "Route was reached without tenant authentication middleware.",
      status: 500,
      category: "internal",
      retryable: false,
    });
  }
  return context;
}
