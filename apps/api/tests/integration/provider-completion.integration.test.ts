import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { computeWormHash } from "@modules/control-plane";
import { withBootstrapTenantAuth, createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Provider Completion Outbox (Integration)", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  }, 60_000);

  async function setup() {
    const controlSchema = uniqueSchema("provider_completion");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);

    const app = withBootstrapTenantAuth(createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("provider-completion-key"),
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      maxOutboxPayloadBytes: 4096,
      shadowBurnInRequired: false,
      now: () => new Date("2026-04-20T10:00:00.000Z"),
    }));

    const [client] = await sql<Array<{ id: string; organization_id: string }>>`
      INSERT INTO ${sql(controlSchema)}.clients (
        name,
        worker_api_key_hash,
        live_mutation_enabled,
        shadow_success_count
      )
      VALUES (
        'worker-1',
        '6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf',
        TRUE,
        100
      )
      RETURNING id, organization_id
    `;

    return { app, controlSchema, client: client! };
  }

  function adminHeaders() {
    return {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };
  }

  function workerHeaders(workerId: string) {
    return {
      "x-client-id": workerId,
      authorization: "Bearer worker-secret",
      "content-type": "application/json",
    };
  }

  it("enqueues provider-specific completion receipts after terminal COE minting", async () => {
    const { app, controlSchema, client } = await setup();

    const targetResponse = await app.request("/api/v1/admin/clients/worker-1/provider-completions/jira", {
      method: "PUT",
      headers: adminHeaders(),
      body: JSON.stringify({
        completion_url: "https://jira.example.test/webhook/avantii-complete",
        auth_header_name: "Authorization",
        auth_header_value: "Bearer jira-secret",
        is_active: true,
      }),
    });
    expect(targetResponse.status).toBe(200);
    const target = (await targetResponse.json()) as { auth_header_value: string };
    expect(target.auth_header_value).toBe("[REDACTED]");

    const request = {
      subject_opaque_id: "usr_provider_completion",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "ADMIN_PURGE",
      actor_opaque_id: "dpo:provider-completion",
      legal_framework: "DPDP_2023",
      request_timestamp: "2026-04-20T10:00:00.000Z",
      cooldown_days: 0,
      shadow_mode: false,
    };

    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(request),
    });
    expect(createResponse.status).toBe(202);
    const created = (await createResponse.json()) as { request_id: string };

    await sql`
      UPDATE ${sql(controlSchema)}.erasure_jobs
      SET status = 'NOTICE_SENT',
          applied_rule_name = 'DEFAULT',
          applied_rule_citation = 'DPO attested default retention'
      WHERE id = ${created.request_id}
    `;
    await sql`
      INSERT INTO ${sql(controlSchema)}.webhook_ingestions (
        organization_id,
        client_id,
        provider,
        external_reference_id,
        external_subject_hash,
        idempotency_key,
        erasure_job_id,
        received_at
      )
      VALUES (
        ${client.organization_id},
        ${client.id},
        'jira',
        'JIRA-123',
        ${"a".repeat(64)},
        ${crypto.randomUUID()}::uuid,
        ${created.request_id},
        NOW()
      )
    `;

    const eventTimestamp = "2026-04-20T10:00:00.000Z";
    const payload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      event_timestamp: eventTimestamp,
      trigger_source: request.trigger_source,
      actor_opaque_id: request.actor_opaque_id,
      legal_framework: request.legal_framework,
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "DPO attested default retention",
      postgres_transaction_ids: ["txid-provider-completion"],
      blob_receipts: [],
    };
    const idempotencyKey = `outbox-${created.request_id}-shred`;
    const currentHash = await computeWormHash("GENESIS", payload, idempotencyKey);

    const outboxResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: workerHeaders(client.id),
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "SHRED_SUCCESS",
        payload,
        previous_hash: "GENESIS",
        current_hash: currentHash,
        event_timestamp: eventTimestamp,
      }),
    });
    expect(outboxResponse.status).toBe(202);

    const webhooks = await sql<Array<{ url: string; headers: Record<string, string>; payload: Record<string, unknown> }>>`
      SELECT url, headers, payload
      FROM ${sql(controlSchema)}.webhook_outbox
      WHERE job_id = ${created.request_id}
      ORDER BY created_at ASC
    `;
    expect(webhooks).toHaveLength(1);
    expect(webhooks[0]?.url).toBe("https://jira.example.test/webhook/avantii-complete");
    expect(webhooks[0]?.headers).toEqual({ Authorization: "Bearer jira-secret" });
    expect(webhooks[0]?.payload).toEqual(expect.objectContaining({
      provider: "jira",
      external_reference_id: "JIRA-123",
      request_id: created.request_id,
      status: "SHRED_SUCCESS",
    }));
  });
});
