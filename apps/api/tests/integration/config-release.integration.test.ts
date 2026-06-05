import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Worker config release enforcement", () => {
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
    const controlSchema = uniqueSchema("config_release");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);

    const app = createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("config-release-key"),
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      maxOutboxPayloadBytes: 2048,
      now: () => new Date("2026-04-20T10:00:00.000Z"),
    });

    const [client] = await sql<{ id: string }[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash, require_approved_config)
      VALUES ('worker-1', '6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf', TRUE)
      RETURNING id
    `;

    return { app, controlSchema, workerId: client!.id };
  }

  function adminHeaders() {
    return {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };
  }

  function workerHeaders(workerId: string, configHash: string = "ab".repeat(32)) {
    return {
      "x-client-id": workerId,
      authorization: "Bearer worker-secret",
      "x-worker-config-hash": configHash,
      "x-worker-config-version": "v-test",
      "x-worker-dpo-identifier": "dpo@example.com",
    };
  }

  it("fails closed when a worker syncs with an unapproved or revoked config hash", async () => {
    const { app, workerId } = await setup();

    const rejected = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: workerHeaders(workerId),
    });
    expect(rejected.status).toBe(403);
    expect(await rejected.json()).toEqual(
      expect.objectContaining({
        code: "API_WORKER_CONFIG_NOT_APPROVED",
      })
    );

    const approved = await app.request("/api/v1/admin/clients/worker-1/config-releases", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        config_hash: "ab".repeat(32),
        configuration_version: "v-test",
        dpo_identifier: "dpo@example.com",
        legal_review_date: "2026-04-20",
        allowed_live_mutation: true,
        require_approved_config: true,
      }),
    });
    expect(approved.status).toBe(201);

    const accepted = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: workerHeaders(workerId),
    });
    expect(accepted.status).toBe(200);
    expect(await accepted.json()).toEqual({ pending: false });

    const revoked = await app.request(`/api/v1/admin/clients/worker-1/config-releases/${"ab".repeat(32)}/revoke`, {
      method: "POST",
      headers: adminHeaders(),
    });
    expect(revoked.status).toBe(200);

    const rejectedAfterRevoke = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: workerHeaders(workerId),
    });
    expect(rejectedAfterRevoke.status).toBe(403);
  });
});
