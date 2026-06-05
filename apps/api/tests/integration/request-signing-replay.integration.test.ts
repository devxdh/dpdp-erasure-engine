import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { computeRequestSignature } from "@/http";
import { computeTokenHash } from "@modules/control-plane";
import { createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("worker request replay protection", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function setup() {
    const controlSchema = uniqueSchema("control_replay");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);
    const [client] = await sql<{ id: string }[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash)
      VALUES ('worker-1', ${await computeTokenHash("worker-secret")})
      RETURNING id
    `;
    const app = createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("test-key"),
      workerSharedSecret: "worker-secret",
      workerRequestSigningSecret: "request-signing-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      shadowBurnInRequired: false,
      publicRateLimitMaxRequests: 1_000,
    });
    return { app, controlSchema, workerId: client!.id };
  }

  async function signedHeaders(workerId: string, timestamp: string) {
    return {
      "x-client-id": workerId,
      authorization: "Bearer worker-secret",
      "x-worker-config-hash": "ab".repeat(32),
      "x-worker-config-version": "v-test",
      "x-worker-dpo-identifier": "dpo@example.com",
      "x-dpdp-timestamp": timestamp,
      "x-dpdp-signature": await computeRequestSignature(
        "request-signing-secret",
        "GET",
        "/api/v1/worker/sync",
        workerId,
        timestamp,
        ""
      ),
    };
  }

  it("rejects a worker request signature replay inside the clock-skew window", async () => {
    const { app, controlSchema, workerId } = await setup();
    const timestamp = String(Date.now());
    const headers = await signedHeaders(workerId, timestamp);

    const first = await app.request("/api/v1/worker/sync", { headers });
    expect(first.status).toBe(200);

    const replay = await app.request("/api/v1/worker/sync", { headers });
    expect(replay.status).toBe(409);
    expect(await replay.json()).toEqual(
      expect.objectContaining({
        code: "API_WORKER_SIGNATURE_REPLAYED",
      })
    );

    const [stored] = await sql<{ total: string }[]>`
      SELECT COUNT(*)::text AS total
      FROM ${sql(controlSchema)}.worker_request_replays
      WHERE client_id = ${workerId}
    `;
    expect(stored?.total).toBe("1");
  });
});
