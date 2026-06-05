import type { createApp } from "@/app";

type TestApp = ReturnType<typeof createApp>;
type RequestInput = Parameters<TestApp["request"]>[0];

const TENANT_PROTECTED_PREFIXES = ["/api/v1/erasure-requests", "/api/v1/certificates"];

function getRequestPath(input: RequestInput): string {
  if (typeof input === "string") {
    return new URL(input, "http://test.local").pathname;
  }

  if (input instanceof Request) {
    return new URL(input.url).pathname;
  }

  return input.pathname;
}

/**
 * Adds the bootstrap tenant bearer token to legacy integration-test calls that
 * exercise tenant-protected control-plane routes.
 *
 * @param app - Hono app returned by `createApp`.
 * @param token - Bootstrap admin token configured for the test app.
 * @returns The same app instance with a patched `request` method.
 */
export function withBootstrapTenantAuth(app: TestApp, token: string = "admin-secret"): TestApp {
  const request = app.request.bind(app) as TestApp["request"];

  app.request = ((...args: Parameters<TestApp["request"]>) => {
    const [input, init, env] = args;
    const path = getRequestPath(input);
    const shouldInject = TENANT_PROTECTED_PREFIXES.some((prefix) => path.startsWith(prefix));

    if (!shouldInject) {
      return request(input, init, env);
    }

    const headers = new Headers(init?.headers);
    if (!headers.has("authorization")) {
      headers.set("authorization", `Bearer ${token}`);
    }

    return request(input, { ...init, headers }, env);
  }) as TestApp["request"];

  return app;
}
