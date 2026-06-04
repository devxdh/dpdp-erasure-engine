import type { Context } from "hono";
import { asApiError } from "@/errors";
import { getLogger, logError } from "@/observability";

function getRequestLogger(c: Context) {
  return getLogger({
    component: "http",
    requestId: c.get("requestId"),
    method: c.req.method,
    path: c.req.path,
  });
}

/**
 * Centralized API error handler that emits a uniform problem-details response for every failure path.
 *
 * Validation errors preserve structured field issues, while all other errors are normalized into the
 * same response contract for logging, observability, and client remediation.
 *
 * @param error - Unknown error raised during request handling.
 * @param c - Hono request context.
 * @returns JSON response containing standardized problem details.
 */
export function handleApiError(error: unknown, c: Context): Response {
  const normalized = logError(getRequestLogger(c), error, "HTTP request failed");
  return new Response(JSON.stringify(normalized.toProblem(c.req.path, c.get("requestId"))), {
    status: normalized.status,
    headers: {
      "content-type": "application/json",
    },
  });
}

/**
 * Creates a standardized 404 response using the shared API problem-details envelope.
 *
 * @param c - Hono request context.
 * @returns JSON response describing the missing route.
 */
export function handleNotFound(c: Context): Response {
  const problem = asApiError(undefined, {
    code: "API_ROUTE_NOT_FOUND",
    title: "Route not found",
    detail: `No route matches ${c.req.method} ${c.req.path}.`,
    status: 404,
    category: "validation",
  }).toProblem(c.req.path, c.get("requestId"));

  return c.json(problem, 404);
}
