import type { Context, Next } from "hono";
import type postgres from "postgres";
import { assertIdentifier } from "../db/identifiers";
import { fail } from "../errors";
import { recordRateLimit } from "../observability/metrics";

interface RateLimitBucket {
  count: number;
  resetAt: number;
}

interface RateLimiter {
  readonly maxRequests: number;
  take(key: string, now: number): Promise<{ allowed: boolean; remaining: number; resetAt: number }> |
    { allowed: boolean; remaining: number; resetAt: number };
}

/**
 * Fixed-window in-memory limiter for public-facing API endpoints.
 *
 * This is intentionally lightweight and process-local. It reduces abusive bursts on
 * ingress endpoints while still allowing operators to front the API with a distributed
 * gateway/WAF for multi-instance enforcement.
 */
export class MemoryRateLimiter {
  readonly windowMs: number;
  readonly maxRequests: number;
  private readonly buckets = new Map<string, RateLimitBucket>();

  constructor(windowMs: number, maxRequests: number) {
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  private cleanup(now: number): void {
    for (const [key, bucket] of this.buckets) {
      if (bucket.resetAt <= now) {
        this.buckets.delete(key);
      }
    }
  }

  take(key: string, now: number): { allowed: boolean; remaining: number; resetAt: number } {
    this.cleanup(now);
    const current = this.buckets.get(key);
    if (!current || current.resetAt <= now) {
      const resetAt = now + this.windowMs;
      this.buckets.set(key, {
        count: 1,
        resetAt,
      });
      return {
        allowed: true,
        remaining: this.maxRequests - 1,
        resetAt,
      };
    }

    if (current.count >= this.maxRequests) {
      return {
        allowed: false,
        remaining: 0,
        resetAt: current.resetAt,
      };
    }

    current.count += 1;
    return {
      allowed: true,
      remaining: Math.max(0, this.maxRequests - current.count),
      resetAt: current.resetAt,
    };
  }
}

/**
 * Postgres-backed fixed-window limiter for horizontally scaled API deployments.
 *
 * It uses one row per bucket and row-level locks to make request budgets consistent across
 * API replicas. Stale buckets are opportunistically pruned so the table remains bounded.
 */
export class PostgresRateLimiter implements RateLimiter {
  readonly windowMs: number;
  readonly maxRequests: number;
  private readonly sql: postgres.Sql;
  private readonly schema: string;

  constructor(sql: postgres.Sql, controlSchema: string, windowMs: number, maxRequests: number) {
    this.sql = sql;
    this.schema = assertIdentifier(controlSchema, "control schema name");
    this.windowMs = windowMs;
    this.maxRequests = maxRequests;
  }

  async take(key: string, now: number): Promise<{ allowed: boolean; remaining: number; resetAt: number }> {
    const nowDate = new Date(now);
    const resetDate = new Date(now + this.windowMs);
    return this.sql.begin(async (tx) => {
      await tx`
        DELETE FROM ${tx(this.schema)}.api_rate_limits
        WHERE reset_at < ${new Date(now - this.windowMs)}
      `;

      const [current] = await tx<{ count: number; reset_at: Date }[]>`
        SELECT count, reset_at
        FROM ${tx(this.schema)}.api_rate_limits
        WHERE bucket_key = ${key}
        FOR UPDATE
      `;

      if (!current || current.reset_at.getTime() <= now) {
        await tx`
          INSERT INTO ${tx(this.schema)}.api_rate_limits (bucket_key, count, reset_at, updated_at)
          VALUES (${key}, 1, ${resetDate}, ${nowDate})
          ON CONFLICT (bucket_key) DO UPDATE
          SET count = 1,
              reset_at = EXCLUDED.reset_at,
              updated_at = EXCLUDED.updated_at
        `;
        return {
          allowed: true,
          remaining: this.maxRequests - 1,
          resetAt: resetDate.getTime(),
        };
      }

      if (current.count >= this.maxRequests) {
        return {
          allowed: false,
          remaining: 0,
          resetAt: current.reset_at.getTime(),
        };
      }

      const [updated] = await tx<{ count: number; reset_at: Date }[]>`
        UPDATE ${tx(this.schema)}.api_rate_limits
        SET count = count + 1,
            updated_at = ${nowDate}
        WHERE bucket_key = ${key}
        RETURNING count, reset_at
      `;

      return {
        allowed: true,
        remaining: Math.max(0, this.maxRequests - (updated?.count ?? this.maxRequests)),
        resetAt: (updated?.reset_at ?? current.reset_at).getTime(),
      };
    });
  }
}

function resolveClientKey(c: Context): string {
  const forwarded = c.req.header("x-forwarded-for");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() || "unknown";
  }

  const realIp = c.req.header("x-real-ip");
  if (realIp) {
    return realIp;
  }

  const requestId = c.get("requestId");
  return typeof requestId === "string" ? `req:${requestId}` : "unknown";
}

/**
 * Creates Hono middleware enforcing a simple public endpoint request budget.
 *
 * @param limiter - Shared in-memory limiter instance.
 * @returns Middleware that sets rate-limit headers and rejects overflow with 429.
 */
export function createRateLimitMiddleware(limiter: RateLimiter) {
  return async (c: Context, next: Next): Promise<void> => {
    const decision = await limiter.take(resolveClientKey(c), Date.now());
    c.header("x-ratelimit-limit", String(limiter.maxRequests));
    c.header("x-ratelimit-remaining", String(decision.remaining));
    c.header("x-ratelimit-reset", String(Math.ceil(decision.resetAt / 1000)));

    if (!decision.allowed) {
      recordRateLimit(c.req.path);
      fail({
        code: "API_RATE_LIMITED",
        title: "Too many requests",
        detail: "Request budget exceeded. Retry after the current rate-limit window resets.",
        status: 429,
        category: "external",
        retryable: true,
      });
    }

    await next();
  };
}
