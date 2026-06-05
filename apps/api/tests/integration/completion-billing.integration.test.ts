import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { ControlPlaneRepository, finalizeTerminalOutboxEvent } from "@modules/control-plane";
import { withBootstrapTenantAuth, createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("provider completion and billing state", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function setup(now: Date = new Date("2026-04-20T10:00:00.000Z")) {
    const controlSchema = uniqueSchema("completion_billing");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);

    const repository = new ControlPlaneRepository(sql, controlSchema, 60, 10, 1000);
    const signer = await createEd25519Signer("integration-key");
    const app = withBootstrapTenantAuth(createApp({
      sql,
      controlSchema,
      signer,
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      shadowBurnInRequired: false,
      now: () => now,
    }));

    const [client] = await sql<{ id: string; organization_id: string }[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash)
      VALUES ('worker-1', 'worker-hash')
      RETURNING id, organization_id
    `;

    return { app, controlSchema, repository, signer, client: client! };
  }

  function adminHeaders() {
    return {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };
  }

  it("enqueues provider-native completion callback after terminal certificate minting", async () => {
    const { app, controlSchema, repository, signer, client } = await setup();
    const response = await app.request("/api/v1/admin/clients/worker-1/provider-completions/onetrust", {
      method: "PUT",
      headers: adminHeaders(),
      body: JSON.stringify({
        completion_url: "https://grc.example.test/onetrust/receipt",
        auth_header_name: "Authorization",
        auth_header_value: "Bearer provider-token",
      }),
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual(
      expect.objectContaining({
        provider: "onetrust",
        auth_header_value: "[REDACTED]",
      })
    );

    const jobId = globalThis.crypto.randomUUID();
    const now = new Date("2026-04-20T10:01:00.000Z");
    await sql`
      INSERT INTO ${sql(controlSchema)}.erasure_jobs (
        id,
        organization_id,
        client_id,
        idempotency_key,
        subject_opaque_id,
        trigger_source,
        actor_opaque_id,
        legal_framework,
        request_timestamp,
        cooldown_days,
        shadow_mode,
        status,
        vault_due_at,
        shredded_at,
        created_at,
        updated_at
      ) VALUES (
        ${jobId},
        ${client.organization_id},
        ${client.id},
        ${globalThis.crypto.randomUUID()}::uuid,
        'usr_provider_completion',
        'USER_CONSENT_WITHDRAWAL',
        'dpo_1',
        'DPDP_2023',
        ${now},
        0,
        FALSE,
        'SHREDDED',
        ${now},
        ${now},
        ${now},
        ${now}
      )
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
      ) VALUES (
        ${client.organization_id},
        ${client.id},
        'onetrust',
        'ot-ticket-42',
        'subject-hash',
        ${globalThis.crypto.randomUUID()}::uuid,
        ${jobId},
        ${now}
      )
    `;

    const job = await repository.getJobById(jobId, client.organization_id);
    expect(job).not.toBeNull();
    await finalizeTerminalOutboxEvent(
      repository,
      signer,
      1000,
      job!,
      "SHRED_SUCCESS",
      now,
      "ab".repeat(32),
      [],
      ["12345"]
    );

    const [webhook] = await sql<{ url: string; headers: Record<string, string>; payload: Record<string, unknown> }[]>`
      SELECT url, headers, payload
      FROM ${sql(controlSchema)}.webhook_outbox
      WHERE job_id = ${jobId}::uuid
    `;
    expect(webhook?.url).toBe("https://grc.example.test/onetrust/receipt");
    expect(webhook?.headers).toEqual({ Authorization: "Bearer provider-token" });
    expect(webhook?.payload).toEqual(
      expect.objectContaining({
        provider: "onetrust",
        external_reference_id: "ot-ticket-42",
        request_id: jobId,
        status: "SHRED_SUCCESS",
      })
    );
  });

  it("persists billing subscription state and deduplicates provider event records", async () => {
    const { app, controlSchema, client } = await setup();
    const body = {
      plan_id: "growth",
      provider: "razorpay",
      status: "ACTIVE",
      provider_order_id: "order_1",
      provider_payment_id: "pay_1",
      provider_event_id: "evt_1",
      event_type: "razorpay.checkout.verified",
      metadata: { amount: 990000, currency: "INR" },
    };

    for (let index = 0; index < 2; index += 1) {
      const response = await app.request("/api/v1/admin/billing/subscription", {
        method: "PUT",
        headers: adminHeaders(),
        body: JSON.stringify(body),
      });
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual(
        expect.objectContaining({
          organization_id: client.organization_id,
          plan_id: "growth",
          status: "ACTIVE",
          provider_order_id: "order_1",
        })
      );
    }

    const [count] = await sql<{ count: string }[]>`
      SELECT COUNT(*)::text AS count
      FROM ${sql(controlSchema)}.billing_events
      WHERE organization_id = ${client.organization_id}::uuid
        AND provider_event_id = 'evt_1'
    `;
    expect(count?.count).toBe("1");
  });
});
