import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createApp } from "@/app";
import { createEd25519Signer, verifyEd25519Signature } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { computeWormHash } from "@modules/control-plane";
import { withBootstrapTenantAuth, createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Control Plane API (Integration)", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  }, 60_000);

  async function setup(
    overrides: {
      now?: () => Date;
      taskMaxAttempts?: number;
      taskBaseBackoffMs?: number;
      shadowBurnInRequired?: boolean;
      shadowRequiredSuccesses?: number;
    } = {}
  ) {
    const controlSchema = uniqueSchema("control_api");
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
      taskMaxAttempts: overrides.taskMaxAttempts,
      taskBaseBackoffMs: overrides.taskBaseBackoffMs,
      shadowBurnInRequired: overrides.shadowBurnInRequired ?? false,
      shadowRequiredSuccesses: overrides.shadowRequiredSuccesses,
      now: overrides.now,
    }));

    const bootstrapClient = await sql<any[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash)
      VALUES ('worker-1', '6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf')
      RETURNING id
    `;
    const workerId = bootstrapClient[0]!.id;

    return { app, controlSchema, workerId };
  }

  function buildWorkerAuthHeaders(workerId: string, token: string = "worker-secret") {
    return {
      "x-client-id": workerId,
      authorization: `Bearer ${token}`,
      "x-worker-config-hash": "ab".repeat(32),
      "x-worker-config-version": "v-test",
      "x-worker-dpo-identifier": "dpo@example.com",
    };
  }

  function buildErasureRequest(overrides: Record<string, unknown> = {}) {
    return {
      subject_opaque_id: "usr_8847a92b_4f1c_882a",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_8847a92b_4f1c_882a",
      legal_framework: "DPDP_2023",
      request_timestamp: "2026-04-19T10:00:00.000Z",
      cooldown_days: 30,
      shadow_mode: false,
      ...overrides,
    };
  }

  async function computeCurrentHash(previousHash: string, payload: unknown, idempotencyKey: string): Promise<string> {
    return computeWormHash(previousHash, payload, idempotencyKey);
  }

  async function signGrcWebhook(secret: string, timestamp: string, bodyText: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}\n${bodyText}`));
    return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function signWebhookBody(secret: string, bodyText: string): Promise<string> {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(bodyText));
    return Array.from(new Uint8Array(signature), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function signZendeskWebhook(secret: string, timestamp: string, bodyText: string): Promise<string> {
    return signWebhookBody(secret, `${timestamp}${bodyText}`);
  }

  async function registerProviderMapping(
    app: ReturnType<typeof createApp>,
    provider: "onetrust" | "jira" | "zendesk",
    externalSubjectId: string,
    subjectOpaqueId: string
  ) {
    const response = await app.request(`/api/v1/integrations/${provider}/subject-mappings`, {
      method: "PUT",
      headers: {
        authorization: "Bearer admin-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        external_subject_id: externalSubjectId,
        subject_opaque_id: subjectOpaqueId,
      }),
    });
    expect(response.status).toBe(200);
  }

  it("rejects undeclared PII fields, direct identifiers, and missing mandatory actor metadata", async () => {
    const { app, controlSchema, workerId } = await setup();

    const extraFieldResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ...buildErasureRequest(),
        email: "alice@example.com",
      }),
    });
    expect(extraFieldResponse.status).toBe(400);
    expect(await extraFieldResponse.json()).toEqual(
      expect.objectContaining({
        title: "Validation failed",
        code: "API_VALIDATION_FAILED",
        category: "validation",
        issues: expect.arrayContaining([
          expect.objectContaining({
            param: "<root>",
            code: "unrecognized_keys",
            message: expect.stringContaining("Unrecognized key"),
          }),
        ]),
        request_id: expect.stringMatching(
          /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
        ),
      })
    );

    const emailSubjectResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          subject_opaque_id: "alice@example.com",
        })
      ),
    });
    expect(emailSubjectResponse.status).toBe(400);
    expect(await emailSubjectResponse.json()).toEqual(
      expect.objectContaining({
        code: "API_VALIDATION_FAILED",
        issues: expect.arrayContaining([
          expect.objectContaining({
            param: "subject_opaque_id",
            message: "must be an opaque identifier, not an email address",
          }),
        ]),
      })
    );

    const phoneActorResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          actor_opaque_id: "+91 9876543210",
        })
      ),
    });
    expect(phoneActorResponse.status).toBe(400);
    expect(await phoneActorResponse.json()).toEqual(
      expect.objectContaining({
        code: "API_VALIDATION_FAILED",
        issues: expect.arrayContaining([
          expect.objectContaining({
            param: "actor_opaque_id",
            message: "must be an opaque identifier, not a phone number",
          }),
        ]),
      })
    );

    const missingActorResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        subject_opaque_id: "usr_missing_actor",
        idempotency_key: crypto.randomUUID(),
        trigger_source: "USER_CONSENT_WITHDRAWAL",
        legal_framework: "DPDP_2023",
        request_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });
    expect(missingActorResponse.status).toBe(400);
    expect(await missingActorResponse.json()).toEqual(
      expect.objectContaining({
        code: "API_VALIDATION_FAILED",
        issues: expect.arrayContaining([
          expect.objectContaining({
            param: "actor_opaque_id",
            code: "invalid_type",
          }),
        ]),
      })
    );
  });

  it("verifies signed GRC webhooks, maps external ids to opaque ids, and queues due erasure tasks", async () => {
    const { app, workerId } = await setup();
    const tenantHeaders = {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };

    const mappingResponse = await app.request("/api/v1/integrations/onetrust/subject-mappings", {
      method: "PUT",
      headers: tenantHeaders,
      body: JSON.stringify({
        external_subject_id: "ot_subject_123",
        subject_opaque_id: "usr_mapped_123",
      }),
    });
    expect(mappingResponse.status).toBe(200);
    expect(await mappingResponse.json()).toEqual(
      expect.objectContaining({
        provider: "onetrust",
        subject_opaque_id: "usr_mapped_123",
      })
    );

    const payload = {
      event_id: "ot_event_001",
      external_subject_id: "ot_subject_123",
      legal_framework: "DPDP_2023",
      cooldown_days: 0,
    };
    const bodyText = JSON.stringify(payload);
    const timestamp = String(Date.now());
    const signature = await signGrcWebhook("admin-secret", timestamp, bodyText);
    const webhookResponse = await app.request("/api/v1/integrations/onetrust/erasure-webhook", {
      method: "POST",
      headers: {
        ...tenantHeaders,
        "x-grc-timestamp": timestamp,
        "x-grc-signature": signature,
      },
      body: bodyText,
    });
    expect(webhookResponse.status).toBe(202);
    const webhookAccepted = await webhookResponse.json() as { request_id: string };
    expect(webhookAccepted).toEqual(
      expect.objectContaining({
        provider: "onetrust",
        mapped: true,
        idempotent_replay: false,
      })
    );

    const syncResponse = await app.request("/api/v1/worker/sync", {
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    const synced = await syncResponse.json();
    expect(synced).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          task_type: "VAULT_USER",
          payload: expect.objectContaining({
            request_id: webhookAccepted.request_id,
            subject_opaque_id: "usr_mapped_123",
            actor_opaque_id: "integration:onetrust",
          }),
        }),
      })
    );
  });

  it("rejects unsigned or unmapped GRC webhooks before queue mutation", async () => {
    const { app } = await setup();
    const tenantHeaders = {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };
    const payload = {
      event_id: "zendesk_ticket_001",
      external_subject_id: "zd_subject_missing",
      cooldown_days: 0,
    };
    const bodyText = JSON.stringify(payload);

    const unsignedResponse = await app.request("/api/v1/integrations/zendesk/erasure-webhook", {
      method: "POST",
      headers: tenantHeaders,
      body: bodyText,
    });
    expect(unsignedResponse.status).toBe(401);
    expect(await unsignedResponse.json()).toEqual(
      expect.objectContaining({
        code: "API_GRC_WEBHOOK_SIGNATURE_MISSING",
      })
    );

    const timestamp = String(Date.now());
    const signature = await signGrcWebhook("admin-secret", timestamp, bodyText);
    const unmappedResponse = await app.request("/api/v1/integrations/zendesk/erasure-webhook", {
      method: "POST",
      headers: {
        ...tenantHeaders,
        "x-grc-timestamp": timestamp,
        "x-grc-signature": signature,
      },
      body: bodyText,
    });
    expect(unmappedResponse.status).toBe(404);
    expect(await unmappedResponse.json()).toEqual(
      expect.objectContaining({
        code: "API_GRC_SUBJECT_MAPPING_NOT_FOUND",
      })
    );
  });

  it("hash-normalizes email-only configurable GRC webhook subjects without storing raw PII", async () => {
    const { app, controlSchema, workerId } = await setup();
    const tenantHeaders = {
      authorization: "Bearer admin-secret",
      "content-type": "application/json",
    };

    const mappingResponse = await app.request("/api/v1/integrations/zendesk/subject-mappings", {
      method: "PUT",
      headers: tenantHeaders,
      body: JSON.stringify({
        external_subject_id: "grc.user@example.com",
        subject_opaque_id: "usr_grc_email_only",
      }),
    });
    expect(mappingResponse.status).toBe(200);

    const payload = {
      event_id: "zendesk-email-only-001",
      external_subject_id: "GRC.User@Example.com",
      cooldown_days: 0,
    };
    const bodyText = JSON.stringify(payload);
    const timestamp = String(Date.now());
    const response = await app.request("/api/v1/integrations/zendesk/erasure-webhook", {
      method: "POST",
      headers: {
        ...tenantHeaders,
        "x-grc-timestamp": timestamp,
        "x-grc-signature": await signGrcWebhook("admin-secret", timestamp, bodyText),
      },
      body: bodyText,
    });
    expect(response.status).toBe(202);

    const [mapping] = await sql<{ external_subject_hash: string }[]>`
      SELECT external_subject_hash
      FROM ${sql(controlSchema)}.external_subject_mappings
      WHERE subject_opaque_id = 'usr_grc_email_only'
    `;
    expect(mapping?.external_subject_hash).toMatch(/^[0-9a-f]{64}$/);

    const syncResponse = await app.request("/api/v1/worker/sync", {
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    expect(await syncResponse.json()).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          payload: expect.objectContaining({
            subject_opaque_id: "usr_grc_email_only",
            actor_opaque_id: "integration:zendesk",
          }),
        }),
      })
    );
  });

  it("ingests OneTrust webhooks through client-routed HMAC verification and enqueues COMPILE_DAG idempotently", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'onetrust-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "onetrust", "ot-subject-9001", "usr_onetrust_9001");

    const bodyText = JSON.stringify({
      requestId: "ot-erasure-9001",
      dataSubjectId: "ot-subject-9001",
      timestamp: "2026-05-01T12:00:00.000Z",
    });
    const signature = await signWebhookBody("onetrust-secret", bodyText);

    const first = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": signature,
      },
      body: bodyText,
    });
    expect(first.status).toBe(202);
    const accepted = await first.json() as {
      duplicate: boolean;
      erasure_job_id: string;
      task_id: string;
      subject_opaque_id: string;
    };
    expect(accepted.duplicate).toBe(false);
    expect(accepted.subject_opaque_id).toBe("usr_onetrust_9001");

    const [job] = await sql<{
      subject_opaque_id: string;
      trigger_source: string;
      legal_framework: string;
      cooldown_days: number;
      status: string;
    }[]>`
      SELECT subject_opaque_id, trigger_source, legal_framework, cooldown_days, status
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE id = ${accepted.erasure_job_id}
    `;
    expect(job).toEqual(
      expect.objectContaining({
        subject_opaque_id: accepted.subject_opaque_id,
        trigger_source: "ONETRUST",
        legal_framework: "DPDP",
        cooldown_days: 0,
        status: "WAITING_COOLDOWN",
      })
    );

    const [task] = await sql<{ task_type: string; payload: { erasure_job_id: string } }[]>`
      SELECT task_type, payload
      FROM ${sql(controlSchema)}.task_queue
      WHERE id = ${accepted.task_id}
    `;
    expect(task).toEqual(
      expect.objectContaining({
        task_type: "COMPILE_DAG",
        payload: { erasure_job_id: accepted.erasure_job_id },
      })
    );

    const replay = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": signature,
      },
      body: bodyText,
    });
    expect(replay.status).toBe(200);
    expect(await replay.json()).toEqual(
      expect.objectContaining({
        accepted: true,
        duplicate: true,
        erasure_job_id: accepted.erasure_job_id,
      })
    );

    const [counts] = await sql<{ jobs: string; tasks: string }[]>`
      SELECT
        COUNT(DISTINCT ej.id)::text AS jobs,
        COUNT(tq.id)::text AS tasks
      FROM ${sql(controlSchema)}.erasure_jobs AS ej
      LEFT JOIN ${sql(controlSchema)}.task_queue AS tq
        ON tq.erasure_job_id = ej.id
      WHERE ej.subject_opaque_id = ${accepted.subject_opaque_id}
    `;
    expect(counts).toEqual({ jobs: "1", tasks: "1" });

    const [ingestion] = await sql<{
      ingestions: string;
      erasure_job_id: string | null;
      task_id: string | null;
    }[]>`
      SELECT
        COUNT(*)::text AS ingestions,
        MAX(erasure_job_id::text) AS erasure_job_id,
        MAX(task_id::text) AS task_id
      FROM ${sql(controlSchema)}.webhook_ingestions
      WHERE provider = 'onetrust'
        AND external_reference_id = 'ot-erasure-9001'
    `;
    expect(ingestion).toEqual({
      ingestions: "1",
      erasure_job_id: accepted.erasure_job_id,
      task_id: accepted.task_id,
    });

    const compileLease = await app.request("/api/v1/worker/sync", {
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(compileLease.status).toBe(200);
    const leasedCompile = await compileLease.json() as {
      pending: boolean;
      task: { id: string; task_type: string };
    };
    expect(leasedCompile.task.task_type).toBe("COMPILE_DAG");

    const compileAck = await app.request(`/api/v1/worker/tasks/${leasedCompile.task.id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: {
          action: "compiled_dag",
          compiledTargetCount: 1,
        },
      }),
    });
    expect(compileAck.status).toBe(200);

    const vaultLease = await app.request("/api/v1/worker/sync", {
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(vaultLease.status).toBe(200);
    expect(await vaultLease.json()).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          task_type: "VAULT_USER",
          payload: expect.objectContaining({
            subject_opaque_id: "usr_onetrust_9001",
            trigger_source: "ONETRUST",
          }),
        }),
      })
    );
  });

  it("rejects unmapped unified provider webhooks instead of creating ghost subjects", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'onetrust-secret'
      WHERE id = ${workerId}
    `;

    const bodyText = JSON.stringify({
      requestId: "ot-erasure-unmapped",
      dataSubjectId: "ot-subject-missing",
      timestamp: "2026-05-01T12:00:00.000Z",
    });
    const response = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": await signWebhookBody("onetrust-secret", bodyText),
      },
      body: bodyText,
    });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual(
      expect.objectContaining({
        code: "API_WEBHOOK_SUBJECT_MAPPING_NOT_FOUND",
      })
    );

    const [count] = await sql<{ jobs: string }[]>`
      SELECT COUNT(*)::text AS jobs
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE trigger_source = 'ONETRUST'
    `;
    expect(count?.jobs).toBe("0");

    const [ingestionCount] = await sql<{ ingestions: string }[]>`
      SELECT COUNT(*)::text AS ingestions
      FROM ${sql(controlSchema)}.webhook_ingestions
      WHERE provider = 'onetrust'
        AND external_reference_id = 'ot-erasure-unmapped'
    `;
    expect(ingestionCount?.ingestions).toBe("0");
  });

  it("accepts provider-forced email subjects by hashing the transient identifier before lookup", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'onetrust-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "onetrust", "alice@example.com", "usr_email_mapped");

    const bodyText = JSON.stringify({
      requestId: "ot-erasure-email",
      identifier: "Alice@Example.com",
      timestamp: "2026-05-01T12:00:00.000Z",
    });
    const response = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": await signWebhookBody("onetrust-secret", bodyText),
      },
      body: bodyText,
    });

    expect(response.status).toBe(202);
    const accepted = await response.json() as { subject_opaque_id: string; erasure_job_id: string };
    expect(accepted).toEqual(
      expect.objectContaining({
        subject_opaque_id: "usr_email_mapped",
      })
    );

    const rows = await sql<{ external_subject_hash: string; raw_leaked: boolean }[]>`
      SELECT
        external_subject_hash,
        external_subject_hash ILIKE '%alice@example.com%' AS raw_leaked
      FROM ${sql(controlSchema)}.external_subject_mappings
      WHERE subject_opaque_id = 'usr_email_mapped'
    `;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.external_subject_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(rows[0]!.raw_leaked).toBe(false);
  });

  it("accepts messy provider payloads with secondary PII when an opaque subject id is present", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'onetrust-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "onetrust", "ot-opaque-subject-1", "usr_opaque_subject_1");

    const bodyText = JSON.stringify({
      requestId: "ot-erasure-secondary-pii",
      dataSubjectId: "ot-opaque-subject-1",
      email: "secondary@example.com",
      subject: {
        email: "secondary@example.com",
      },
      timestamp: "2026-05-01T12:00:00.000Z",
    });
    const response = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": await signWebhookBody("onetrust-secret", bodyText),
      },
      body: bodyText,
    });

    expect(response.status).toBe(202);
    const accepted = await response.json() as { subject_opaque_id: string; erasure_job_id: string };
    expect(accepted.subject_opaque_id).toBe("usr_opaque_subject_1");

    const [job] = await sql<{ subject_opaque_id: string; actor_opaque_id: string }[]>`
      SELECT subject_opaque_id, actor_opaque_id
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE id = ${accepted.erasure_job_id}
    `;
    expect(job).toEqual({
      subject_opaque_id: "usr_opaque_subject_1",
      actor_opaque_id: "webhook:onetrust",
    });
  });

  it("rejects conflicting provider replays with the same external reference and a different subject", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'onetrust-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "onetrust", "ot-original-subject", "usr_original_subject");
    await registerProviderMapping(app, "onetrust", "ot-conflicting-subject", "usr_conflicting_subject");

    const originalBody = JSON.stringify({
      requestId: "ot-conflict-reference",
      dataSubjectId: "ot-original-subject",
      timestamp: "2026-05-01T12:00:00.000Z",
    });
    const original = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": await signWebhookBody("onetrust-secret", originalBody),
      },
      body: originalBody,
    });
    expect(original.status).toBe(202);

    const conflictingBody = JSON.stringify({
      requestId: "ot-conflict-reference",
      dataSubjectId: "ot-conflicting-subject",
      timestamp: "2026-05-01T12:00:01.000Z",
    });
    const conflicting = await app.request(`/api/v1/webhooks/onetrust/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-onetrust-signature": await signWebhookBody("onetrust-secret", conflictingBody),
      },
      body: conflictingBody,
    });

    expect(conflicting.status).toBe(409);
    expect(await conflicting.json()).toEqual(
      expect.objectContaining({
        code: "API_WEBHOOK_REPLAY_CONFLICT",
      })
    );

    const [counts] = await sql<{ jobs: string; tasks: string; ingestions: string }[]>`
      SELECT
        (SELECT COUNT(*)::text FROM ${sql(controlSchema)}.erasure_jobs WHERE subject_opaque_id IN ('usr_original_subject', 'usr_conflicting_subject')) AS jobs,
        (SELECT COUNT(*)::text FROM ${sql(controlSchema)}.task_queue WHERE task_type = 'COMPILE_DAG') AS tasks,
        (SELECT COUNT(*)::text FROM ${sql(controlSchema)}.webhook_ingestions WHERE external_reference_id = 'ot-conflict-reference') AS ingestions
    `;
    expect(counts).toEqual({ jobs: "1", tasks: "1", ingestions: "1" });
  });

  it("accepts the previous provider webhook secret during the rotation grace window", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'old-webhook-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "zendesk", "zendesk-rotating-user", "usr_zendesk_rotating");

    const rotateResponse = await app.request("/api/v1/admin/clients/worker-1/rotate-webhook-secret", {
      method: "POST",
      headers: {
        authorization: "Bearer admin-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        previous_secret_grace_hours: 24,
      }),
    });
    expect(rotateResponse.status).toBe(200);
    const rotated = await rotateResponse.json() as { webhook_signing_secret: string };

    const oldSecretBody = JSON.stringify({
      event_id: "zd-rotation-old-secret",
      requester: {
        id: "zendesk-rotating-user",
      },
      created_at: "2026-05-01T14:00:00.000Z",
    });
    const oldSecretTimestamp = String(Date.now());
    const oldSecretResponse = await app.request(`/api/v1/webhooks/zendesk/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-zendesk-webhook-signature-timestamp": oldSecretTimestamp,
        "x-zendesk-webhook-signature": await signZendeskWebhook("old-webhook-secret", oldSecretTimestamp, oldSecretBody),
      },
      body: oldSecretBody,
    });
    expect(oldSecretResponse.status).toBe(202);

    const newSecretBody = JSON.stringify({
      event_id: "zd-rotation-new-secret",
      requester: {
        id: "zendesk-rotating-user",
      },
      created_at: "2026-05-01T14:05:00.000Z",
    });
    const newSecretTimestamp = String(Date.now());
    const newSecretResponse = await app.request(`/api/v1/webhooks/zendesk/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-zendesk-webhook-signature-timestamp": newSecretTimestamp,
        "x-zendesk-webhook-signature": await signZendeskWebhook(rotated.webhook_signing_secret, newSecretTimestamp, newSecretBody),
      },
      body: newSecretBody,
    });
    expect(newSecretResponse.status).toBe(202);
  });

  it("rejects bad provider signatures before creating webhook jobs", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'jira-secret'
      WHERE id = ${workerId}
    `;

    const bodyText = JSON.stringify({
      webhookEvent: "jira:issue_updated",
      issue: {
        id: "10001",
        key: "DSAR-42",
        fields: {
          reporter: {
            accountId: "account-123",
          },
        },
      },
    });

    const response = await app.request(`/api/v1/webhooks/jira/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-hub-signature": "sha256=" + "00".repeat(32),
      },
      body: bodyText,
    });
    expect(response.status).toBe(401);
    expect(await response.json()).toEqual(
      expect.objectContaining({
        code: "API_WEBHOOK_SIGNATURE_INVALID",
      })
    );

    const [count] = await sql<{ jobs: string }[]>`
      SELECT COUNT(*)::text AS jobs
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE trigger_source = 'JIRA'
    `;
    expect(count?.jobs).toBe("0");
  });

  it("normalizes Jira and Zendesk webhook adapters through the unified route", async () => {
    const { app, controlSchema, workerId } = await setup();
    await sql`
      UPDATE ${sql(controlSchema)}.clients
      SET webhook_signing_secret = 'shared-webhook-secret'
      WHERE id = ${workerId}
    `;
    await registerProviderMapping(app, "jira", "jira-account-1", "usr_jira_1");
    await registerProviderMapping(app, "zendesk", "zendesk-user-1", "usr_zendesk_1");

    const jiraBody = JSON.stringify({
      webhookEvent: "jira:issue_created",
      issue: {
        id: "JIRA-100",
        fields: {
          reporter: {
            accountId: "jira-account-1",
          },
        },
      },
      timestamp: "2026-05-01T13:00:00.000Z",
    });
    const zendeskBody = JSON.stringify({
      event_id: "zd-event-100",
      requester: {
        id: "zendesk-user-1",
      },
      created_at: "2026-05-01T13:05:00.000Z",
    });
    const zendeskTimestamp = String(Date.now());

    const jiraResponse = await app.request(`/api/v1/webhooks/jira/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-hub-signature": `sha256=${await signWebhookBody("shared-webhook-secret", jiraBody)}`,
      },
      body: jiraBody,
    });
    expect(jiraResponse.status).toBe(202);

    const zendeskResponse = await app.request(`/api/v1/webhooks/zendesk/${workerId}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-zendesk-webhook-signature-timestamp": zendeskTimestamp,
        "x-zendesk-webhook-signature": await signZendeskWebhook("shared-webhook-secret", zendeskTimestamp, zendeskBody),
      },
      body: zendeskBody,
    });
    expect(zendeskResponse.status).toBe(202);

    const rows = await sql<{ trigger_source: string; task_type: string }[]>`
      SELECT ej.trigger_source, tq.task_type
      FROM ${sql(controlSchema)}.erasure_jobs AS ej
      JOIN ${sql(controlSchema)}.task_queue AS tq
        ON tq.erasure_job_id = ej.id
      WHERE ej.trigger_source IN ('JIRA', 'ZENDESK')
      ORDER BY ej.trigger_source ASC
    `;
    expect(rows).toEqual([
      { trigger_source: "JIRA", task_type: "COMPILE_DAG" },
      { trigger_source: "ZENDESK", task_type: "COMPILE_DAG" },
    ]);
  });

  it("applies secure response headers and normalizes untrusted request ids", async () => {
    const { app, controlSchema, workerId } = await setup();

    const response = await app.request("/health", {
      headers: {
        "x-request-id": "invalid/request?id",
      },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(response.headers.get("x-frame-options")).toBeTruthy();
    expect(response.headers.get("x-request-id")).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
    );
  });

  it("rejects webhook targets that violate Control Plane SSRF guardrails", async () => {
    const { app, controlSchema, workerId } = await setup();

    const insecureProtocol = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          webhook_url: "http://client.example.com/hooks/dpdp",
        })
      ),
    });
    expect(insecureProtocol.status).toBe(400);

    const loopbackHost = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          webhook_url: "https://127.0.0.1/hooks/dpdp",
        })
      ),
    });
    expect(loopbackHost.status).toBe(400);

    const credentialedUrl = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          webhook_url: "https://user:pass@client.example.com/hooks/dpdp",
        })
      ),
    });
    expect(credentialedUrl.status).toBe(400);
  });

  it("reuses the same cooldown timer on idempotent create replay", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({
      subject_opaque_id: "usr_idempotent",
      cooldown_days: 30,
    });

    const firstResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(firstResponse.status).toBe(202);
    const firstBody = (await firstResponse.json()) as {
      request_id: string;
      task_id: string;
      idempotent_replay: boolean;
    };
    expect(firstBody.idempotent_replay).toBe(false);

    const replayResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(replayResponse.status).toBe(202);
    const replayBody = (await replayResponse.json()) as {
      request_id: string;
      task_id: string;
      idempotent_replay: boolean;
    };
    expect(replayBody.request_id).toBe(firstBody.request_id);
    expect(replayBody.task_id).toBe(firstBody.task_id);
    expect(replayBody.idempotent_replay).toBe(true);

    const [counts] = await sql<{ job_count: number; task_count: number }[]>`
      SELECT
        (SELECT COUNT(*)::int FROM ${sql(controlSchema)}.erasure_jobs WHERE idempotency_key = ${request.idempotency_key}::uuid) AS job_count,
        (SELECT COUNT(*)::int FROM ${sql(controlSchema)}.task_queue WHERE erasure_job_id = ${firstBody.request_id}) AS task_count
    `;
    expect(counts).toEqual({
      job_count: 1,
      task_count: 1,
    });
  });

  it("sync dispatches only due jobs and ignores cancelled or future cooldown work", async () => {
    const { app, controlSchema, workerId } = await setup();
    const futureJob = buildErasureRequest({ subject_opaque_id: "usr_future", cooldown_days: 30 });
    const cancelledJob = buildErasureRequest({ subject_opaque_id: "usr_cancel", cooldown_days: 30 });
    const dueJob = buildErasureRequest({ subject_opaque_id: "usr_due", cooldown_days: 0, tenant_id: "tenant_a" });

    await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(futureJob),
    });

    const cancelledCreate = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(cancelledJob),
    });
    expect(cancelledCreate.status).toBe(202);

    const cancelResponse = await app.request(`/api/v1/erasure-requests/${cancelledJob.idempotency_key}/cancel`, {
      method: "POST",
    });
    expect(cancelResponse.status).toBe(200);

    const dueCreate = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(dueJob),
    });
    const dueCreated = (await dueCreate.json()) as { request_id: string; task_id: string };

    const syncResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    const syncPayload = (await syncResponse.json()) as {
      pending: boolean;
      task?: {
        id: string;
        task_type: "VAULT_USER";
        payload: {
          request_id: string;
          subject_opaque_id: string;
          tenant_id?: string;
        };
      };
    };

    expect(syncPayload.pending).toBe(true);
    expect(syncPayload.task?.id).toBe(dueCreated.task_id);
    expect(syncPayload.task?.payload.request_id).toBe(dueCreated.request_id);
    expect(syncPayload.task?.payload.subject_opaque_id).toBe("usr_due");
    expect(syncPayload.task?.payload.tenant_id).toBe("tenant_a");

    await app.request(`/api/v1/worker/tasks/${dueCreated.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });

    const secondSync = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(secondSync.status).toBe(200);
    expect(await secondSync.json()).toEqual({ pending: false });

    const heartbeatEvents = await sql<{ event_type: string; payload: Record<string, unknown> }[]>`
      SELECT event_type, payload
      FROM ${sql(controlSchema)}.audit_ledger
      WHERE event_type = 'WORKER_CONFIG_HEARTBEAT'
    `;
    expect(heartbeatEvents).toHaveLength(1);
    expect(heartbeatEvents[0]?.payload).toEqual(
      expect.objectContaining({
        config_hash: "ab".repeat(32),
        configuration_version: "v-test",
        dpo_identifier: "dpo@example.com",
      })
    );

    const jobRows = await sql<{ subject_opaque_id: string; status: string }[]>`
      SELECT subject_opaque_id, status
      FROM ${sql(controlSchema)}.erasure_jobs
      ORDER BY subject_opaque_id ASC
    `;
    expect(jobRows).toEqual([
      { subject_opaque_id: "usr_cancel", status: "CANCELLED" },
      { subject_opaque_id: "usr_due", status: "EXECUTING" },
      { subject_opaque_id: "usr_future", status: "WAITING_COOLDOWN" },
    ]);

    const cancelledTasks = await sql<{ status: string }[]>`
      SELECT status
      FROM ${sql(controlSchema)}.task_queue
      WHERE erasure_job_id = (
        SELECT id
        FROM ${sql(controlSchema)}.erasure_jobs
        WHERE subject_opaque_id = 'usr_cancel'
      )
    `;
    expect(cancelledTasks).toHaveLength(1);
    expect(cancelledTasks[0]?.status).toBe("FAILED");
  });

  it("cancel endpoint prevents a waiting erasure request from syncing", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({ subject_opaque_id: "usr_abort", cooldown_days: 30 });

    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    expect(createResponse.status).toBe(202);

    const cancelResponse = await app.request(`/api/v1/erasure-requests/${request.idempotency_key}/cancel`, {
      method: "POST",
    });
    expect(cancelResponse.status).toBe(200);

    const syncResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    expect(await syncResponse.json()).toEqual({ pending: false });
  });

  it("enforces shadow-mode burn-in before accepting live mutation requests", async () => {
    const { app, controlSchema, workerId } = await setup({
      shadowBurnInRequired: true,
      shadowRequiredSuccesses: 2,
    });

    const rejectedLive = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          subject_opaque_id: "usr_live_before_burn_in",
          cooldown_days: 0,
          shadow_mode: false,
        })
      ),
    });
    expect(rejectedLive.status).toBe(409);
    expect(await rejectedLive.json()).toEqual(
      expect.objectContaining({
        code: "API_LIVE_MUTATION_BURN_IN_REQUIRED",
      })
    );

    const completeShadowVault = async (subjectId: string) => {
      const createResponse = await app.request("/api/v1/erasure-requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(
          buildErasureRequest({
            subject_opaque_id: subjectId,
            cooldown_days: 0,
            shadow_mode: true,
          })
        ),
      });
      expect(createResponse.status).toBe(202);
      const created = (await createResponse.json()) as { task_id: string };

      const syncResponse = await app.request("/api/v1/worker/sync", {
        method: "GET",
        headers: buildWorkerAuthHeaders(workerId),
      });
      expect(syncResponse.status).toBe(200);
      const syncPayload = (await syncResponse.json()) as { pending: boolean; task?: { id: string } };
      expect(syncPayload.pending).toBe(true);
      expect(syncPayload.task?.id).toBe(created.task_id);

      const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          status: "completed",
          result: { action: "shadow_vaulted" },
        }),
      });
      expect(ackResponse.status).toBe(200);
      return created.task_id;
    };

    const firstShadowTaskId = await completeShadowVault("usr_shadow_1");
    const replayAckResponse = await app.request(`/api/v1/worker/tasks/${firstShadowTaskId}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "shadow_vaulted" },
      }),
    });
    expect(replayAckResponse.status).toBe(200);
    await completeShadowVault("usr_shadow_2");

    const [client] = await sql<{
      shadow_success_count: number;
      shadow_required_successes: number;
      live_mutation_enabled: boolean;
      live_mutation_enabled_at: Date | null;
    }[]>`
      SELECT shadow_success_count, shadow_required_successes, live_mutation_enabled, live_mutation_enabled_at
      FROM ${sql(controlSchema)}.clients
      WHERE name = 'worker-1'
    `;
    expect(client).toEqual(
      expect.objectContaining({
        shadow_success_count: 2,
        shadow_required_successes: 2,
        live_mutation_enabled: true,
      })
    );
    expect(client?.live_mutation_enabled_at).toBeInstanceOf(Date);

    const acceptedLive = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(
        buildErasureRequest({
          subject_opaque_id: "usr_live_after_burn_in",
          cooldown_days: 0,
          shadow_mode: false,
        })
      ),
    });
    expect(acceptedLive.status).toBe(202);
  });

  it("requeues retryable task failures with exponential backoff before redispatch", async () => {
    let now = new Date("2026-04-19T10:00:00.000Z");
    const { app, controlSchema, workerId } = await setup({
      now: () => now,
      taskMaxAttempts: 3,
      taskBaseBackoffMs: 1000,
    });

    const request = buildErasureRequest({ subject_opaque_id: "usr_retry_task", cooldown_days: 0 });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const syncResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);

    const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "failed",
        result: {
          error: {
            code: "DB_SERIALIZATION_FAILURE",
            title: "Serialization failure",
            detail: "Concurrent writer forced rollback.",
            category: "concurrency",
            retryable: true,
            fatal: false,
          },
        },
      }),
    });
    expect(ackResponse.status).toBe(200);
    expect(await ackResponse.json()).toEqual(
      expect.objectContaining({
        ok: true,
        task_id: created.task_id,
        status: "QUEUED",
      })
    );

    const [taskAfterFailure] = await sql<{
      status: string;
      attempt_count: number;
      next_attempt_at: Date;
    }[]>`
      SELECT status, attempt_count, next_attempt_at
      FROM ${sql(controlSchema)}.task_queue
      WHERE id = ${created.task_id}
    `;
    expect(taskAfterFailure?.status).toBe("QUEUED");
    expect(taskAfterFailure?.attempt_count).toBe(1);
    expect(new Date(taskAfterFailure!.next_attempt_at).toISOString()).toBe("2026-04-19T10:00:01.000Z");

    const beforeDueSync = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(beforeDueSync.status).toBe(200);
    expect(await beforeDueSync.json()).toEqual({ pending: false });

    now = new Date("2026-04-19T10:00:01.000Z");
    const afterDueSync = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(afterDueSync.status).toBe(200);
    expect(await afterDueSync.json()).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          id: created.task_id,
        }),
      })
    );
  });

  it("dead-letters non-retryable task failures and marks the job as failed", async () => {
    const { app, controlSchema, workerId } = await setup({
      now: () => new Date("2026-04-19T10:00:00.000Z"),
      taskMaxAttempts: 3,
      taskBaseBackoffMs: 1000,
    });

    const request = buildErasureRequest({ subject_opaque_id: "usr_dead_letter", cooldown_days: 0 });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });

    const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "failed",
        result: {
          error: {
            code: "TASK_PAYLOAD_INVALID",
            title: "Invalid task payload",
            detail: "Opaque identifier is malformed.",
            category: "validation",
            retryable: false,
            fatal: false,
          },
        },
      }),
    });
    expect(ackResponse.status).toBe(200);
    expect(await ackResponse.json()).toEqual(
      expect.objectContaining({
        ok: true,
        task_id: created.task_id,
        status: "DEAD_LETTER",
      })
    );

    const [taskRow] = await sql<{
      status: string;
      attempt_count: number;
      dead_lettered_at: Date | null;
    }[]>`
      SELECT status, attempt_count, dead_lettered_at
      FROM ${sql(controlSchema)}.task_queue
      WHERE id = ${created.task_id}
    `;
    expect(taskRow).toEqual({
      status: "DEAD_LETTER",
      attempt_count: 1,
      dead_lettered_at: new Date("2026-04-19T10:00:00.000Z"),
    });

    const [jobRow] = await sql<{ status: string }[]>`
      SELECT status
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE id = ${created.request_id}
    `;
    expect(jobRow?.status).toBe("FAILED");
  });

  it("ingests a chained USER_VAULTED event and transitions the job to VAULTED", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({ subject_opaque_id: "usr_worm", cooldown_days: 0 });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });
    expect(ackResponse.status).toBe(200);

    const payload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      tenant_id: null,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      retention_years: 10,
      notification_due_at: "2036-04-17T10:00:00.000Z",
      retention_expiry: "2036-04-19T10:00:00.000Z",
    };
    const idempotencyKey = `vault:${created.request_id}`;
    const currentHash = await computeCurrentHash("GENESIS", payload, idempotencyKey);

    const outboxResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload,
        previous_hash: "GENESIS",
        current_hash: currentHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });
    expect(outboxResponse.status).toBe(202);

    const [job] = await sql<{
      status: string;
      notification_due_at: Date | null;
      shred_due_at: Date | null;
    }[]>`
      SELECT status, notification_due_at, shred_due_at
      FROM ${sql(controlSchema)}.erasure_jobs
      WHERE id = ${created.request_id}
    `;
    expect(job?.status).toBe("VAULTED");
    expect(job?.notification_due_at?.toISOString()).toBe("2036-04-17T10:00:00.000Z");
    expect(job?.shred_due_at?.toISOString()).toBe("2036-04-19T10:00:00.000Z");
  });

  it("rebases stale worker outbox heads onto the serialized audit chain", async () => {
    const { app, controlSchema, workerId } = await setup({
      now: () => new Date("2026-04-19T10:00:00.000Z"),
    });
    const request = buildErasureRequest({ subject_opaque_id: "usr_stale_head", cooldown_days: 0 });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    const ackResponse = await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });
    expect(ackResponse.status).toBe(200);

    const vaultPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      tenant_id: null,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Configured default_retention_years policy",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      retention_years: 0,
      notification_due_at: "2026-04-19T10:00:00.000Z",
      retention_expiry: "2026-04-19T10:00:00.000Z",
    };
    const vaultIdempotencyKey = `vault:${created.request_id}`;
    const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, vaultIdempotencyKey);
    const vaultResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: vaultIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload: vaultPayload,
        previous_hash: "GENESIS",
        current_hash: vaultHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });
    expect(vaultResponse.status).toBe(202);

    const noticePayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      tenant_id: null,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Configured default_retention_years policy",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      notification_channel: "email",
    };
    const noticeIdempotencyKey = `notice:${created.request_id}`;
    const staleNoticeHash = await computeCurrentHash("GENESIS", noticePayload, noticeIdempotencyKey);
    const noticeResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: noticeIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "NOTIFICATION_SENT",
        payload: noticePayload,
        previous_hash: "GENESIS",
        current_hash: staleNoticeHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });

    expect(noticeResponse.status).toBe(202);

    const [noticeAudit] = await sql<{ previous_hash: string; current_hash: string }[]>`
      SELECT previous_hash, current_hash
      FROM ${sql(controlSchema)}.audit_ledger
      WHERE worker_idempotency_key = ${noticeIdempotencyKey}
    `;
    expect(noticeAudit?.previous_hash).toBe(vaultHash);
    expect(noticeAudit?.current_hash).toBe(
      await computeCurrentHash(vaultHash, noticePayload, noticeIdempotencyKey)
    );
  });

  it("materializes a NOTIFY_USER task after USER_VAULTED reaches notification_due_at", async () => {
    const now = new Date("2036-04-17T10:00:00.000Z");
    const { app, controlSchema, workerId } = await setup({ now: () => now });
    const request = buildErasureRequest({ subject_opaque_id: "usr_notice_due", cooldown_days: 0 });

    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });

    const vaultPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      tenant_id: null,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      retention_years: 10,
      notification_due_at: "2036-04-17T10:00:00.000Z",
      retention_expiry: "2036-04-19T10:00:00.000Z",
    };
    const idempotencyKey = `vault:${created.request_id}`;
    const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, idempotencyKey);
    const vaultResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: idempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload: vaultPayload,
        previous_hash: "GENESIS",
        current_hash: vaultHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });
    expect(vaultResponse.status).toBe(202);

    const syncResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    expect(await syncResponse.json()).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          task_type: "NOTIFY_USER",
          payload: expect.objectContaining({
            request_id: created.request_id,
            subject_opaque_id: request.subject_opaque_id,
          }),
        }),
      })
    );

    const [taskRow] = await sql<{ task_type: string; status: string }[]>`
      SELECT task_type, status
      FROM ${sql(controlSchema)}.task_queue
      WHERE erasure_job_id = ${created.request_id}
        AND task_type = 'NOTIFY_USER'
    `;
    expect(taskRow?.task_type).toBe("NOTIFY_USER");
    expect(taskRow?.status).toBe("DISPATCHED");
  });

  it("materializes a SHRED_USER task after NOTIFICATION_SENT reaches retention expiry", async () => {
    const now = new Date("2036-04-19T10:00:00.000Z");
    const { app, controlSchema, workerId } = await setup({ now: () => now });
    const request = buildErasureRequest({ subject_opaque_id: "usr_shred_due", cooldown_days: 0 });

    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });

    const vaultPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      notification_due_at: "2036-04-17T10:00:00.000Z",
      retention_expiry: "2036-04-19T10:00:00.000Z",
    };
    const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, `vault:${created.request_id}`);
    await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: `vault:${created.request_id}`,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload: vaultPayload,
        previous_hash: "GENESIS",
        current_hash: vaultHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });

    const noticePayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2036-04-17T10:00:00.000Z",
      sent_at: "2036-04-17T10:00:00.000Z",
    };
    const noticeHash = await computeCurrentHash(vaultHash, noticePayload, `notice:${created.request_id}`);
    const noticeResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: `notice:${created.request_id}`,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "NOTIFICATION_SENT",
        payload: noticePayload,
        previous_hash: vaultHash,
        current_hash: noticeHash,
        event_timestamp: "2036-04-17T10:00:00.000Z",
      }),
    });
    expect(noticeResponse.status).toBe(202);

    const syncResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(syncResponse.status).toBe(200);
    expect(await syncResponse.json()).toEqual(
      expect.objectContaining({
        pending: true,
        task: expect.objectContaining({
          task_type: "SHRED_USER",
          payload: expect.objectContaining({
            request_id: created.request_id,
            subject_opaque_id: request.subject_opaque_id,
          }),
        }),
      })
    );

    const [taskRow] = await sql<{ task_type: string; status: string }[]>`
      SELECT task_type, status
      FROM ${sql(controlSchema)}.task_queue
      WHERE erasure_job_id = ${created.request_id}
        AND task_type = 'SHRED_USER'
    `;
    expect(taskRow?.task_type).toBe("SHRED_USER");
    expect(taskRow?.status).toBe("DISPATCHED");
  });

  it("ingests SHRED_SUCCESS and mints a certificate of erasure", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({ subject_opaque_id: "usr_cert", cooldown_days: 0 });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    const leaseResponse = await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });
    expect(leaseResponse.status).toBe(200);

    await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });

    const vaultPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      notification_due_at: "2036-04-17T10:00:00.000Z",
      retention_expiry: "2036-04-19T10:00:00.000Z",
    };
    const vaultIdempotencyKey = `vault:${created.request_id}`;
    const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, vaultIdempotencyKey);
    const vaultResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: vaultIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload: vaultPayload,
        previous_hash: "GENESIS",
        current_hash: vaultHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });
    expect(vaultResponse.status).toBe(202);

    const noticePayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2036-04-17T10:00:00.000Z",
      sent_at: "2036-04-17T10:00:00.000Z",
    };
    const noticeHash = await computeCurrentHash(vaultHash, noticePayload, `notice:${created.request_id}`);
    const noticeResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: `notice:${created.request_id}`,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "NOTIFICATION_SENT",
        payload: noticePayload,
        previous_hash: vaultHash,
        current_hash: noticeHash,
        event_timestamp: "2036-04-17T10:00:00.000Z",
      }),
    });
    expect(noticeResponse.status).toBe(202);

    const shredPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "PMLA_FINANCIAL",
      applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
      event_timestamp: "2036-04-19T10:00:00.000Z",
      shredded_at: "2036-04-19T10:00:00.000Z",
    };
    const shredIdempotencyKey = `shred:${created.request_id}`;
    const shredHash = await computeCurrentHash(noticeHash, shredPayload, shredIdempotencyKey);
    const shredResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: shredIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "SHRED_SUCCESS",
        payload: shredPayload,
        previous_hash: noticeHash,
        current_hash: shredHash,
        event_timestamp: "2036-04-19T10:00:00.000Z",
      }),
    });
    expect(shredResponse.status).toBe(202);

    const certificateResponse = await app.request(`/api/v1/certificates/${created.request_id}`);
    expect(certificateResponse.status).toBe(200);
    const certificate = (await certificateResponse.json()) as {
      request_id: string;
      subject_opaque_id: string;
      legal_framework: string;
      applied_rule_name: string | null;
      applied_rule_citation: string | null;
      method: string;
      final_worm_hash: string;
    };
    expect(certificate.request_id).toBe(created.request_id);
    expect(certificate.subject_opaque_id).toBe(request.subject_opaque_id);
    expect(certificate.legal_framework).toBe(request.legal_framework);
    expect(certificate.applied_rule_name).toBe("PMLA_FINANCIAL");
    expect(certificate.applied_rule_citation).toBe("Prevention of Money Laundering Act, 2002, Sec 12");
    expect(certificate.method).toBe("CRYPTO_SHREDDING_DEK_DELETE");
    expect(certificate.final_worm_hash).toBe(shredHash);

    const verificationResponse = await app.request(`/api/v1/certificates/${created.request_id}/verify`);
    expect(verificationResponse.status).toBe(200);
    expect(await verificationResponse.json()).toEqual(
      expect.objectContaining({
        request_id: created.request_id,
        valid: true,
        algorithm: "Ed25519",
        key_id: "integration-key",
        payload_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
      })
    );

    const [storedCertificate] = await sql<{
      payload: Record<string, unknown>;
      signature_base64: string;
      public_key_spki_base64: string;
    }[]>`
      SELECT payload, signature_base64, public_key_spki_base64
      FROM ${sql(controlSchema)}.certificates
      WHERE request_id = ${created.request_id}
    `;
    expect(storedCertificate?.payload.final_worm_hash).toBe(shredHash);
    expect(
      await verifyEd25519Signature(
        storedCertificate!.public_key_spki_base64,
        storedCertificate!.signature_base64,
        storedCertificate!.payload
      )
    ).toBe(true);

    const pdfResponse = await app.request(`/api/v1/certificates/${created.request_id}/download`);
    expect(pdfResponse.status).toBe(200);
    expect(pdfResponse.headers.get("content-type")).toBe("application/pdf");
    const pdfBuffer = await pdfResponse.arrayBuffer();
    expect(pdfBuffer.byteLength).toBeGreaterThan(1000);
  });

  it("rejects out-of-order worker terminal events before the notice stage", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({
      subject_opaque_id: "usr_out_of_order",
      cooldown_days: 0,
    });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string };

    const shredPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: request.legal_framework,
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Configured default_retention_years policy",
      event_timestamp: "2036-04-19T10:00:00.000Z",
      shredded_at: "2036-04-19T10:00:00.000Z",
    };
    const shredIdempotencyKey = `shred:${created.request_id}`;
    const shredHash = await computeCurrentHash("GENESIS", shredPayload, shredIdempotencyKey);

    const shredResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: shredIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "SHRED_SUCCESS",
        payload: shredPayload,
        previous_hash: "GENESIS",
        current_hash: shredHash,
        event_timestamp: "2036-04-19T10:00:00.000Z",
      }),
    });

    expect(shredResponse.status).toBe(409);
  });

  it("rejects worker outbox metadata that diverges from the original legal contract", async () => {
    const { app, controlSchema, workerId } = await setup();
    const request = buildErasureRequest({
      subject_opaque_id: "usr_metadata_conflict",
      cooldown_days: 0,
    });
    const createResponse = await app.request("/api/v1/erasure-requests", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    const created = (await createResponse.json()) as { request_id: string; task_id: string };

    await app.request("/api/v1/worker/sync", {
      method: "GET",
      headers: buildWorkerAuthHeaders(workerId),
    });

    await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        status: "completed",
        result: { action: "vaulted" },
      }),
    });

    const vaultPayload = {
      request_id: created.request_id,
      subject_opaque_id: request.subject_opaque_id,
      trigger_source: request.trigger_source,
      legal_framework: "PMLA",
      actor_opaque_id: request.actor_opaque_id,
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Configured default_retention_years policy",
      event_timestamp: "2026-04-19T10:00:00.000Z",
      retention_expiry: "2026-04-20T10:00:00.000Z",
      notification_due_at: "2026-04-19T12:00:00.000Z",
    };
    const vaultIdempotencyKey = `vault:${created.request_id}`;
    const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, vaultIdempotencyKey);

    const outboxResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...buildWorkerAuthHeaders(workerId),
      },
      body: JSON.stringify({
        idempotency_key: vaultIdempotencyKey,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "USER_VAULTED",
        payload: vaultPayload,
        previous_hash: "GENESIS",
        current_hash: vaultHash,
        event_timestamp: "2026-04-19T10:00:00.000Z",
      }),
    });

    expect(outboxResponse.status).toBe(409);
  });

  it("dispatches terminal webhook payload when webhook_url is configured", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    );
    try {
      const { app, controlSchema, workerId } = await setup();
      const webhookUrl = "https://client.example.com/hooks/dpdp";
      const request = buildErasureRequest({
        subject_opaque_id: "usr_webhook",
        cooldown_days: 0,
        webhook_url: webhookUrl,
      });
      const createResponse = await app.request("/api/v1/erasure-requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
      const created = (await createResponse.json()) as { request_id: string; task_id: string };

      const leaseResponse = await app.request("/api/v1/worker/sync", {
        method: "GET",
        headers: buildWorkerAuthHeaders(workerId),
      });
      expect(leaseResponse.status).toBe(200);

      await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          status: "completed",
          result: { action: "vaulted" },
        }),
      });

      const vaultPayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2026-04-19T10:00:00.000Z",
        notification_due_at: "2036-04-17T10:00:00.000Z",
        retention_expiry: "2036-04-19T10:00:00.000Z",
      };
      const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, `vault:${created.request_id}`);
      const vaultResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          idempotency_key: `vault:${created.request_id}`,
          request_id: created.request_id,
          subject_opaque_id: request.subject_opaque_id,
          event_type: "USER_VAULTED",
          payload: vaultPayload,
          previous_hash: "GENESIS",
          current_hash: vaultHash,
          event_timestamp: "2026-04-19T10:00:00.000Z",
        }),
      });
      expect(vaultResponse.status).toBe(202);

      const noticePayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2036-04-17T10:00:00.000Z",
        sent_at: "2036-04-17T10:00:00.000Z",
      };
      const noticeHash = await computeCurrentHash(vaultHash, noticePayload, `notice:${created.request_id}`);
      const noticeResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          idempotency_key: `notice:${created.request_id}`,
          request_id: created.request_id,
          subject_opaque_id: request.subject_opaque_id,
          event_type: "NOTIFICATION_SENT",
          payload: noticePayload,
          previous_hash: vaultHash,
          current_hash: noticeHash,
          event_timestamp: "2036-04-17T10:00:00.000Z",
        }),
      });
      expect(noticeResponse.status).toBe(202);

      const shredPayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2036-04-19T10:00:00.000Z",
        shredded_at: "2036-04-19T10:00:00.000Z",
      };
      const shredIdempotencyKey = `shred:${created.request_id}`;
      const shredHash = await computeCurrentHash(noticeHash, shredPayload, shredIdempotencyKey);

      const shredResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          idempotency_key: shredIdempotencyKey,
          request_id: created.request_id,
          subject_opaque_id: request.subject_opaque_id,
          event_type: "SHRED_SUCCESS",
          payload: shredPayload,
          previous_hash: noticeHash,
          current_hash: shredHash,
          event_timestamp: "2036-04-19T10:00:00.000Z",
        }),
      });
      expect(shredResponse.status).toBe(202);
      expect(await app.controlPlaneService.processWebhookOutbox()).toBe(1);
      expect(fetchSpy).toHaveBeenCalledWith(
        new URL(webhookUrl),
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({ "content-type": "application/json" }),
          redirect: "error",
        })
      );
    } finally {
      fetchSpy.mockRestore();
    }
  });

  it("retries terminal webhook delivery on idempotent SHRED_SUCCESS replay", async () => {
    const fetchSpy = vi
      .spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ error: "bad gateway" }), {
          status: 502,
          headers: { "content-type": "application/json" },
        })
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      );

    try {
      const { app, controlSchema, workerId } = await setup();
      const request = buildErasureRequest({
        subject_opaque_id: "usr_webhook_replay",
        cooldown_days: 0,
        webhook_url: "https://client.example.com/hooks/replay",
      });
      const createResponse = await app.request("/api/v1/erasure-requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
      const created = (await createResponse.json()) as { request_id: string; task_id: string };

      const leaseResponse = await app.request("/api/v1/worker/sync", {
        method: "GET",
        headers: buildWorkerAuthHeaders(workerId),
      });
      expect(leaseResponse.status).toBe(200);

      await app.request(`/api/v1/worker/tasks/${created.task_id}/ack`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          status: "completed",
          result: { action: "vaulted" },
        }),
      });

      const vaultPayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2026-04-19T10:00:00.000Z",
        notification_due_at: "2036-04-17T10:00:00.000Z",
        retention_expiry: "2036-04-19T10:00:00.000Z",
      };
      const vaultHash = await computeCurrentHash("GENESIS", vaultPayload, `vault:${created.request_id}`);
      const vaultResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          idempotency_key: `vault:${created.request_id}`,
          request_id: created.request_id,
          subject_opaque_id: request.subject_opaque_id,
          event_type: "USER_VAULTED",
          payload: vaultPayload,
          previous_hash: "GENESIS",
          current_hash: vaultHash,
          event_timestamp: "2026-04-19T10:00:00.000Z",
        }),
      });
      expect(vaultResponse.status).toBe(202);

      const noticePayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2036-04-17T10:00:00.000Z",
        sent_at: "2036-04-17T10:00:00.000Z",
      };
      const noticeHash = await computeCurrentHash(vaultHash, noticePayload, `notice:${created.request_id}`);
      const noticeResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify({
          idempotency_key: `notice:${created.request_id}`,
          request_id: created.request_id,
          subject_opaque_id: request.subject_opaque_id,
          event_type: "NOTIFICATION_SENT",
          payload: noticePayload,
          previous_hash: vaultHash,
          current_hash: noticeHash,
          event_timestamp: "2036-04-17T10:00:00.000Z",
        }),
      });
      expect(noticeResponse.status).toBe(202);

      const shredPayload = {
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        trigger_source: request.trigger_source,
        legal_framework: request.legal_framework,
        actor_opaque_id: request.actor_opaque_id,
        applied_rule_name: "PMLA_FINANCIAL",
        applied_rule_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        event_timestamp: "2036-04-19T10:00:00.000Z",
        shredded_at: "2036-04-19T10:00:00.000Z",
      };
      const shredEvent = {
        idempotency_key: `shred:${created.request_id}`,
        request_id: created.request_id,
        subject_opaque_id: request.subject_opaque_id,
        event_type: "SHRED_SUCCESS",
        payload: shredPayload,
        previous_hash: noticeHash,
        current_hash: await computeCurrentHash(noticeHash, shredPayload, `shred:${created.request_id}`),
        event_timestamp: "2036-04-19T10:00:00.000Z",
      };

      const firstResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify(shredEvent),
      });
      expect(firstResponse.status).toBe(202);
      expect(await app.controlPlaneService.processWebhookOutbox()).toBe(0);

      const replayResponse = await app.request("/api/v1/worker/outbox", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...buildWorkerAuthHeaders(workerId),
        },
        body: JSON.stringify(shredEvent),
      });
      expect(replayResponse.status).toBe(202);
      expect(await replayResponse.json()).toEqual({
        accepted: true,
        idempotent_replay: true,
      });
      expect(await app.controlPlaneService.processWebhookOutbox()).toBe(1);
      expect(fetchSpy).toHaveBeenCalledTimes(2);
    } finally {
      fetchSpy.mockRestore();
    }
  });
});
