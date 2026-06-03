import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import {
  createTestSql,
  dropSchemas,
  insertUser,
  prepareWorkerSchemas,
  uniqueSchema,
  TEST_SECRETS,
} from "./helpers";
import { ComplianceWorker } from "@modules/worker";
import { type MockMailer } from "@modules/engine";
import type { Sql } from "@/types";

describe("Compliance Worker Daemon (E2E Lifecycle)", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  it("orchestrates the full lifecycle: vault -> outbox sync -> notify -> shred", async () => {
    const appSchema = uniqueSchema("e2e_app");
    const engineSchema = uniqueSchema("e2e_engine");
    schemasToDrop.push(appSchema, engineSchema);

    // Setup fresh schemas
    await prepareWorkerSchemas(sql, appSchema, engineSchema, {
      withDependencies: true,
    });

    const userId = await insertUser(sql, appSchema, "e2e@example.com", "E2E User");

    // 1. Mock the Central API (The Brain)
    const mockApi = {
      syncTask: vi.fn(),
      ackTask: vi.fn(),
      pushOutboxEvent: vi.fn(),
    };

    // 2. Mock the Mailer (SMTP Transport)
    const mockMailer: MockMailer = {
      sendEmail: vi.fn().mockResolvedValue(undefined),
    };

    // 3. Initialize the Worker Runtime (The class we will build next!)
    const worker = new ComplianceWorker({
      sql,
      secrets: TEST_SECRETS,
      config: {
        version: "1.0",
        database: {
          app_schema: appSchema,
          engine_schema: engineSchema,
        },
        compliance_policy: {
          default_retention_years: 5,
          notice_window_hours: 48,
          retention_rules: [],
        },
        graph: {
          root_table: "users",
          root_id_column: "id",
          max_depth: 32,
          root_pii_columns: {
            email: "HMAC",
            full_name: "STATIC_MASK",
          },
        },
        satellite_targets: [],
        blob_targets: [],
        rules: [
          {
            id: "dpdp_standard",
            root_table: `${appSchema}.users`,
            targets: [
              {
                table: `${appSchema}.users`,
                parent_columns: [],
                child_columns: [],
                primary_key_columns: [],
                pii_columns: ["email", "full_name"],
              },
              {
                table: `${appSchema}.orders`,
                parent: `${appSchema}.users`,
                join: `${appSchema}.users.id = ${appSchema}.orders.user_id`,
                parent_columns: ["id"],
                child_columns: ["user_id"],
                primary_key_columns: ["id"],
                pii_columns: [],
              },
            ],
          },
        ],
        outbox: {
          batch_size: 10,
          lease_seconds: 60,
          max_attempts: 3,
          base_backoff_ms: 100,
        },
        security: {
          notification_lease_seconds: 60,
          master_key_env: "DPDP_MASTER_KEY",
          hmac_key_env: "DPDP_HMAC_KEY",
        },
        integrity: {
          expected_schema_hash: "1".repeat(64),
        },
        legal_attestation: {
          dpo_identifier: "dpo@example.com",
          configuration_version: "v-test",
          legal_review_date: "2026-04-20",
          acknowledgment: "Configuration reviewed by the Data Protection Officer.",
        },
        masterKey: TEST_SECRETS.kek,
        hmacKey: TEST_SECRETS.hmacKey,
      },
      apiClient: mockApi,
      mailer: mockMailer,
    });

    // --- STAGE 1: VAULTING ---
    // Simulate the API giving us a VAULT_USER task
    mockApi.syncTask.mockResolvedValueOnce({
      pending: true,
      task: {
        id: "task-1",
        task_type: "VAULT_USER",
        payload: {
          request_id: crypto.randomUUID(),
          subject_opaque_id: userId.toString(),
          idempotency_key: crypto.randomUUID(),
          trigger_source: "USER_CONSENT_WITHDRAWAL",
          actor_opaque_id: userId.toString(),
          legal_framework: "DPDP_2023",
          request_timestamp: new Date().toISOString(),
          cooldown_days: 0,
          shadow_mode: false,
          userId,
        },
      },
    });
    mockApi.ackTask.mockResolvedValueOnce(true);
    mockApi.pushOutboxEvent.mockResolvedValueOnce(true);

    // Run one loop of the worker to process the task
    await worker.processNextTask();

    expect(mockApi.syncTask).toHaveBeenCalled();
    expect(mockApi.ackTask).toHaveBeenCalledWith("task-1", "completed", expect.objectContaining({ action: "vaulted" }));

    // Flush the outbox to ensure the API receives the USER_VAULTED event
    await worker.flushOutbox();
    expect(mockApi.pushOutboxEvent).toHaveBeenCalledWith(
      expect.objectContaining({ event_type: "USER_VAULTED" })
    );

    // --- STAGE 3: NOTIFYING ---
    // Fast forward time to trigger the notification window (e.g., 4.9 years later)
    const notifyTime = new Date();
    notifyTime.setUTCFullYear(notifyTime.getUTCFullYear() + 5);
    notifyTime.setUTCDate(notifyTime.getUTCDate() - 1);

    mockApi.syncTask.mockResolvedValueOnce({
      pending: true,
      task: { id: "task-2", task_type: "NOTIFY_USER", payload: { userId, now: notifyTime.toISOString() } },
    });
    mockApi.ackTask.mockResolvedValueOnce(true);

    await worker.processNextTask();

    expect(mockMailer.sendEmail).toHaveBeenCalledTimes(1);
    expect(mockApi.ackTask).toHaveBeenCalledWith("task-2", "completed", expect.objectContaining({ action: "sent" }));

    // --- STAGE 4: SHREDDING ---
    // Fast forward past the expiry date
    const shredTime = new Date(notifyTime);
    shredTime.setUTCDate(shredTime.getUTCDate() + 3);

    mockApi.syncTask.mockResolvedValueOnce({
      pending: true,
      task: { id: "task-3", task_type: "SHRED_USER", payload: { userId, now: shredTime.toISOString() } },
    });
    mockApi.ackTask.mockResolvedValueOnce(true);

    await worker.processNextTask();

    expect(mockApi.ackTask).toHaveBeenCalledWith("task-3", "completed", expect.objectContaining({ action: "shredded" }));

    // Verify Final Database State: Key is gone, payload is { destroyed: true }
    const [vaultRow] = await sql`SELECT encrypted_pii FROM ${sql(engineSchema)}.pii_vault WHERE root_id = ${userId.toString()}`;
    expect(vaultRow?.encrypted_pii).toEqual({ v: 1, destroyed: true });
  });
});
