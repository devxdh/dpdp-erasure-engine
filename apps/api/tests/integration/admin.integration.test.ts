import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { computeWormHash } from "@modules/control-plane";
import { withBootstrapTenantAuth, createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Control Plane Admin (Integration)", () => {
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
    const controlSchema = uniqueSchema("admin_api");
    schemasToDrop.push(controlSchema);
    await dropSchemas(sql, controlSchema);
    await migrateApiSchema(sql, controlSchema);

    const app = withBootstrapTenantAuth(createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("integration-key"),
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      maxOutboxPayloadBytes: 2048,
      shadowBurnInRequired: false,
      now: () => now,
    }));

    const bootstrapClient = await sql<any[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash)
      VALUES ('worker-1', '6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf')
      RETURNING id
    `;
    const workerId = bootstrapClient[0]!.id;

    return { app, controlSchema, workerId };
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
      "x-worker-config-hash": "ab".repeat(32),
      "x-worker-config-version": "v-test",
      "x-worker-dpo-identifier": "dpo@example.com",
      "content-type": "application/json",
    };
  }

  function buildErasureRequest(overrides: Record<string, unknown> = {}) {
    return {
      subject_opaque_id: "usr_admin_flow",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_admin_flow",
      legal_framework: "DPDP_2023",
      request_timestamp: "2026-04-20T10:00:00.000Z",
      cooldown_days: 0,
      shadow_mode: false,
      ...overrides,
    };
  }

  it("creates, lists, rotates, and deactivates worker clients", async () => {
    const { app, workerId } = await setup();

    const createResponse = await app.request("/api/v1/admin/clients", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        name: "tenant-blue",
        display_name: "Tenant Blue",
      }),
    });
    expect(createResponse.status).toBe(201);
    const created = (await createResponse.json()) as {
      client: { name: string; current_key_id: string; is_active: boolean };
      bearer_token: string;
    };
    expect(created.client.name).toBe("tenant-blue");
    expect(created.client.is_active).toBe(true);
    expect(created.bearer_token).toMatch(/^wkr_/);

    const listResponse = await app.request("/api/v1/admin/clients", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(listResponse.status).toBe(200);
    const clients = (await listResponse.json()) as Array<{ name: string }>;
    expect(clients.map((client) => client.name)).toContain("tenant-blue");

    const rotateResponse = await app.request("/api/v1/admin/clients/tenant-blue/rotate-key", {
      method: "POST",
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(rotateResponse.status).toBe(200);
    const rotated = (await rotateResponse.json()) as {
      client: { current_key_id: string };
      bearer_token: string;
    };
    expect(rotated.client.current_key_id).not.toBe(created.client.current_key_id);
    expect(rotated.bearer_token).toMatch(/^wkr_/);

    const webhookSecretResponse = await app.request("/api/v1/admin/clients/tenant-blue/rotate-webhook-secret", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        previous_secret_grace_hours: 24,
      }),
    });
    expect(webhookSecretResponse.status).toBe(200);
    const webhookSecret = (await webhookSecretResponse.json()) as {
      client: { name: string; webhook_secret_rotated_at: string | null };
      webhook_signing_secret: string;
    };
    expect(webhookSecret.client.name).toBe("tenant-blue");
    expect(webhookSecret.webhook_signing_secret).toMatch(/^whsec_/);

    const deactivateResponse = await app.request("/api/v1/admin/clients/tenant-blue/deactivate", {
      method: "POST",
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(deactivateResponse.status).toBe(200);
    expect(await deactivateResponse.json()).toEqual(
      expect.objectContaining({
        name: "tenant-blue",
        is_active: false,
      })
    );
  });

  it("queues DPO-approved bulk purge batches idempotently and rejects direct PII subjects", async () => {
    const { app, controlSchema } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET live_mutation_enabled = TRUE,
          shadow_success_count = shadow_required_successes
      WHERE name = 'worker-1'
    `;

    const body = {
      client_name: "worker-1",
      batch_id: crypto.randomUUID(),
      subject_opaque_ids: ["usr_purge_001", "usr_purge_002"],
      actor_opaque_id: "dpo:bulk-purge",
      legal_framework: "DPDP_2023",
      request_timestamp: "2026-04-20T10:00:00.000Z",
      shadow_mode: false,
    };

    const createdResponse = await app.request("/api/v1/admin/purge-runs", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(body),
    });
    expect(createdResponse.status).toBe(202);
    const created = (await createdResponse.json()) as {
      inserted: number;
      duplicates: number;
      request_ids: string[];
    };
    expect(created.inserted).toBe(2);
    expect(created.duplicates).toBe(0);
    expect(created.request_ids).toHaveLength(2);

    const replayResponse = await app.request("/api/v1/admin/purge-runs", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(body),
    });
    expect(replayResponse.status).toBe(202);
    const replay = (await replayResponse.json()) as { inserted: number; duplicates: number };
    expect(replay.inserted).toBe(0);
    expect(replay.duplicates).toBe(2);

    const concurrentBody = {
      ...body,
      batch_id: crypto.randomUUID(),
      subject_opaque_ids: ["usr_purge_003", "usr_purge_004"],
    };
    const concurrentResults = await Promise.all(
      Array.from({ length: 5 }, async () => {
        const response = await app.request("/api/v1/admin/purge-runs", {
          method: "POST",
          headers: adminHeaders(),
          body: JSON.stringify(concurrentBody),
        });
        expect(response.status).toBe(202);
        return response.json() as Promise<{ inserted: number; duplicates: number }>;
      })
    );
    expect(concurrentResults.reduce((sum, result) => sum + result.inserted, 0)).toBe(2);
    expect(concurrentResults.reduce((sum, result) => sum + result.duplicates, 0)).toBe(8);

    const rows = await sql<Array<{ task_type: string; trigger_source: string; subject_opaque_id: string }>>`
      SELECT tq.task_type, ej.trigger_source, ej.subject_opaque_id
      FROM ${sql(controlSchema)}.erasure_jobs AS ej
      JOIN ${sql(controlSchema)}.task_queue AS tq
        ON tq.erasure_job_id = ej.id
      WHERE ej.trigger_source = 'ADMIN_PURGE'
      ORDER BY ej.subject_opaque_id
    `;
    expect(rows).toEqual([
      { task_type: "VAULT_USER", trigger_source: "ADMIN_PURGE", subject_opaque_id: "usr_purge_001" },
      { task_type: "VAULT_USER", trigger_source: "ADMIN_PURGE", subject_opaque_id: "usr_purge_002" },
      { task_type: "VAULT_USER", trigger_source: "ADMIN_PURGE", subject_opaque_id: "usr_purge_003" },
      { task_type: "VAULT_USER", trigger_source: "ADMIN_PURGE", subject_opaque_id: "usr_purge_004" },
    ]);

    const piiResponse = await app.request("/api/v1/admin/purge-runs", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        ...body,
        batch_id: crypto.randomUUID(),
        subject_opaque_ids: ["person@example.com"],
      }),
    });
    expect(piiResponse.status).toBe(400);
  });

  it("lists and requeues dead-letter tasks", async () => {
    const { app, workerId } = await setup();
    const request = buildErasureRequest();
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { task_id: string };

    await app.request("/api/v1/worker/sync", {
      headers: workerHeaders(workerId),
    });
    await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: workerHeaders(workerId),
      body: JSON.stringify({
        status: "failed",
        result: {
          error: {
            code: "TASK_PAYLOAD_INVALID",
            title: "Invalid task payload",
            detail: "Malformed input",
            category: "validation",
            retryable: false,
            fatal: false,
          },
        },
      }),
    });

    const deadLettersResponse = await app.request("/api/v1/admin/tasks/dead-letters", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(deadLettersResponse.status).toBe(200);
    expect(await deadLettersResponse.json()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: created.task_id,
          status: "DEAD_LETTER",
        }),
      ])
    );

    const requeueResponse = await app.request(`/api/v1/admin/tasks/${created.task_id}/requeue`, {
      method: "POST",
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(requeueResponse.status).toBe(200);
    expect(await requeueResponse.json()).toEqual(
      expect.objectContaining({
        id: created.task_id,
        status: "QUEUED",
      })
    );
  });

  it("lists and fetches erasure request lifecycle aggregates", async () => {
    const { app } = await setup();
    const request = buildErasureRequest({
      subject_opaque_id: "usr_admin_lifecycle",
      actor_opaque_id: "dpo_admin_lifecycle",
      legal_framework: "DPDP_2023",
    });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(request),
    });
    expect(createResponse.status).toBe(202);
    const created = (await createResponse.json()) as { request_id: string };

    const listResponse = await app.request("/api/v1/admin/erasure-requests?limit=10&offset=0", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(listResponse.status).toBe(200);
    const jobs = (await listResponse.json()) as Array<{
      id: string;
      subject_opaque_id: string;
      status: string;
    }>;
    expect(jobs).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          id: created.request_id,
          subject_opaque_id: "usr_admin_lifecycle",
          status: "WAITING_COOLDOWN",
        }),
      ])
    );

    const detailResponse = await app.request(`/api/v1/admin/erasure-requests/${created.request_id}`, {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(detailResponse.status).toBe(200);
    expect(await detailResponse.json()).toEqual(
      expect.objectContaining({
        id: created.request_id,
        legal_framework: "DPDP_2023",
      })
    );
  });

  it("summarizes usage and exports audit ledger entries", async () => {
    const { app, workerId } = await setup();
    const request = buildErasureRequest({
      subject_opaque_id: "usr_usage_export",
      actor_opaque_id: "usr_usage_export",
    });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      headers: workerHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: workerHeaders(workerId),
      body: JSON.stringify({
        status: "completed",
        result: {
          action: "vaulted",
        },
      }),
    });
    expect(ackResponse.status).toBe(200);

    const payload = {
      request_id: created.request_id,
      subject_opaque_id: "usr_usage_export",
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_usage_export",
      legal_framework: "DPDP_2023",
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Configured default_retention_years policy",
      event_timestamp: "2026-04-20T10:00:00.000Z",
      notification_due_at: "2026-04-20T12:00:00.000Z",
      retention_expiry: "2026-04-21T10:00:00.000Z",
    };
    const currentHash = await computeWormHash("GENESIS", payload, "vault_usage_export");

    const outboxResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: workerHeaders(workerId),
      body: JSON.stringify({
        idempotency_key: "vault_usage_export",
        request_id: created.request_id,
        subject_opaque_id: "usr_usage_export",
        event_type: "USER_VAULTED",
        payload,
        previous_hash: "GENESIS",
        current_hash: currentHash,
        event_timestamp: "2026-04-20T10:00:00.000Z",
      }),
    });
    expect(outboxResponse.status).toBe(202);

    const usageResponse = await app.request("/api/v1/admin/usage", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(usageResponse.status).toBe(200);
    expect(await usageResponse.json()).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          client_name: "worker-1",
          event_type: "USER_VAULTED",
          total_units: 1,
          event_count: 1,
        }),
      ])
    );

    const exportResponse = await app.request("/api/v1/admin/audit/export", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(exportResponse.status).toBe(200);
    const lines = (await exportResponse.text()).trim().split("\n");
    const parsed = lines.map((line) => JSON.parse(line) as Record<string, unknown>);
    expect(parsed).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          worker_idempotency_key: "vault_usage_export",
          event_type: "USER_VAULTED",
        }),
        expect.objectContaining({
          event_type: "WORKER_CONFIG_HEARTBEAT",
        }),
      ])
    );

    const verifyResponse = await app.request("/api/v1/admin/audit/verify?client_name=worker-1", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(verifyResponse.status).toBe(200);
    await expect(verifyResponse.json()).resolves.toEqual(
      expect.objectContaining({
        valid: true,
        checked: 2,
        head: currentHash,
        firstInvalid: null,
      })
    );
  });

  it("exposes prometheus metrics for request accounting", async () => {
    const { app, workerId } = await setup();

    await app.request("/health");
    const metricsResponse = await app.request("/metrics");
    expect(metricsResponse.status).toBe(200);
    const metrics = await metricsResponse.text();
    expect(metrics).toContain("dpdp_api_http_requests_total");
    expect(metrics).toContain("dpdp_api_http_request_duration_seconds");
  });

  it("isolates erasure jobs by organization and enforces API key scopes", async () => {
    const { app } = await setup();

    const organizationResponse = await app.request("/api/v1/admin/organizations", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify({
        name: "tenant-isolated",
        billing_plan: "pilot",
        owner_email: "owner@tenant.example",
      }),
    });
    expect(organizationResponse.status).toBe(201);
    const organizationPayload = (await organizationResponse.json()) as {
      organization: { id: string; name: string };
      api_key: string;
    };

    const limitedKeyResponse = await app.request("/api/v1/org/api-keys", {
      method: "POST",
      headers: {
        authorization: `Bearer ${organizationPayload.api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        label: "audit-only",
        scopes: ["audit:read"],
      }),
    });
    expect(limitedKeyResponse.status).toBe(201);
    const limitedKeyPayload = (await limitedKeyResponse.json()) as { api_key: string };

    const deniedResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: {
        authorization: `Bearer ${limitedKeyPayload.api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(buildErasureRequest({ subject_opaque_id: "usr_scope_denied" })),
    });
    expect(deniedResponse.status).toBe(403);

    const bootstrapRequest = buildErasureRequest({
      subject_opaque_id: "usr_bootstrap_org",
      actor_opaque_id: "dpo_bootstrap",
      cooldown_days: 0,
    });
    const bootstrapCreate = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: adminHeaders(),
      body: JSON.stringify(bootstrapRequest),
    });
    expect(bootstrapCreate.status).toBe(202);
    const bootstrapJob = (await bootstrapCreate.json()) as { request_id: string };

    const tenantRequest = buildErasureRequest({
      subject_opaque_id: "usr_tenant_org",
      actor_opaque_id: "dpo_tenant",
      cooldown_days: 0,
    });
    const tenantCreate = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: {
        authorization: `Bearer ${organizationPayload.api_key}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(tenantRequest),
    });
    expect(tenantCreate.status).toBe(202);
    const tenantJob = (await tenantCreate.json()) as { request_id: string };

    const bootstrapListResponse = await app.request("/api/v1/admin/erasure-requests?limit=20&offset=0", {
      headers: {
        authorization: "Bearer admin-secret",
      },
    });
    expect(bootstrapListResponse.status).toBe(200);
    const bootstrapJobs = (await bootstrapListResponse.json()) as Array<{ id: string; organization_id: string }>;
    expect(bootstrapJobs.map((job) => job.id)).toContain(bootstrapJob.request_id);
    expect(bootstrapJobs.map((job) => job.id)).not.toContain(tenantJob.request_id);

    const tenantListResponse = await app.request("/api/v1/admin/erasure-requests?limit=20&offset=0", {
      headers: {
        authorization: `Bearer ${organizationPayload.api_key}`,
      },
    });
    expect(tenantListResponse.status).toBe(200);
    const tenantJobs = (await tenantListResponse.json()) as Array<{ id: string; organization_id: string }>;
    expect(tenantJobs.map((job) => job.id)).toContain(tenantJob.request_id);
    expect(tenantJobs.map((job) => job.id)).not.toContain(bootstrapJob.request_id);
    expect(tenantJobs.every((job) => job.organization_id === organizationPayload.organization.id)).toBe(true);
  });
});
