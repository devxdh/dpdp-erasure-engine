import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("distributed API rate limiting", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  it("enforces the public request budget through Postgres state", async () => {
    const controlSchema = uniqueSchema("control_rl");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);
    const app = createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("test-key"),
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      publicRateLimitMaxRequests: 1,
      publicRateLimitWindowMs: 60_000,
      shadowBurnInRequired: false,
    });

    const headers = {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
      "x-forwarded-for": "203.0.113.44",
    };

    const first = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers,
      body: JSON.stringify({}),
    });
    expect(first.status).toBe(400);

    const second = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers,
      body: JSON.stringify({}),
    });
    expect(second.status).toBe(429);
    expect(await second.json()).toEqual(
      expect.objectContaining({
        code: "API_RATE_LIMITED",
      })
    );

    const [bucket] = await sql<{ count: number }[]>`
      SELECT count
      FROM ${sql(controlSchema)}.api_rate_limits
      WHERE bucket_key = '203.0.113.44'
    `;
    expect(bucket?.count).toBe(1);
  });
});
