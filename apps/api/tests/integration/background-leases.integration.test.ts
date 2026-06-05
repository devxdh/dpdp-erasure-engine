import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { migrateApiSchema } from "@/db";
import { ControlPlaneRepository } from "@modules/control-plane";
import { createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Control Plane background leases", () => {
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
    const schema = uniqueSchema("api_leases");
    schemasToDrop.push(schema);
    await dropSchemas(sql, schema);
    await migrateApiSchema(sql, schema);

    const repository = new ControlPlaneRepository(sql, schema, 60, 10, 1000);
    const [client] = await sql<{ id: string; organization_id: string }[]>`
      INSERT INTO ${sql(schema)}.clients (name, worker_api_key_hash)
      VALUES (${`worker-${schema}`}, ${"hash".repeat(16)})
      RETURNING id, organization_id
    `;
    const jobId = crypto.randomUUID();
    await sql`
      INSERT INTO ${sql(schema)}.erasure_jobs (
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
        status,
        vault_due_at,
        created_at,
        updated_at
      )
      VALUES (
        ${jobId},
        ${client!.organization_id},
        ${client!.id},
        ${crypto.randomUUID()},
        'usr_lease_test',
        'USER_CONSENT_WITHDRAWAL',
        'dpo_lease_test',
        'DPDP_2023',
        ${new Date("2026-04-20T10:00:00.000Z")},
        0,
        'WAITING_COOLDOWN',
        ${new Date("2026-04-20T10:00:00.000Z")},
        ${new Date("2026-04-20T10:00:00.000Z")},
        ${new Date("2026-04-20T10:00:00.000Z")}
      )
    `;

    return {
      schema,
      repository,
      organizationId: client!.organization_id,
      clientId: client!.id,
      jobId,
    };
  }

  it("prevents two webhook dispatchers from claiming the same outbound webhook lease", async () => {
    const { repository, jobId } = await setup();
    const now = new Date("2026-04-20T10:00:00.000Z");
    await repository.enqueueWebhook({
      jobId,
      url: "https://tenant.example/hooks/erasure",
      payload: { request_id: jobId },
      now,
    });

    const firstClaim = await repository.claimPendingWebhooks(10, now);
    const secondClaim = await repository.claimPendingWebhooks(10, now);

    expect(firstClaim).toHaveLength(1);
    expect(firstClaim[0]!.lease_token).toMatch(/^[0-9a-f-]{36}$/i);
    expect(secondClaim).toHaveLength(0);

    await repository.markWebhookFailed(
      firstClaim[0]!.id,
      crypto.randomUUID(),
      "wrong lease",
      new Date("2026-04-20T10:01:00.000Z"),
      false,
      now
    );
    const stillLeased = await repository.claimPendingWebhooks(10, now);
    expect(stillLeased).toHaveLength(0);

    await repository.markWebhookFailed(
      firstClaim[0]!.id,
      firstClaim[0]!.lease_token!,
      "temporary failure",
      new Date("2026-04-20T10:01:00.000Z"),
      false,
      now
    );
    const retryClaim = await repository.claimPendingWebhooks(10, new Date("2026-04-20T10:01:01.000Z"));
    expect(retryClaim).toHaveLength(1);
    expect(retryClaim[0]!.attempt_count).toBe(1);
  });

  it("prevents two archive loops from claiming the same certificate and releases failed leases on backoff", async () => {
    const { repository, jobId, organizationId } = await setup();
    const now = new Date("2026-04-20T10:00:00.000Z");
    await repository.insertCertificate({
      requestId: jobId,
      organizationId,
      subjectOpaqueId: "usr_lease_test",
      method: "AES_256_GCM_DEK_SHRED",
      legalFramework: "DPDP_2023",
      shreddedAt: now,
      payload: { request_id: jobId, final_worm_hash: "ab".repeat(32) },
      signatureBase64: "signature",
      publicKeySpkiBase64: "public-key",
      keyId: "test-key",
      algorithm: "Ed25519",
      archiveNextAttemptAt: now,
    });

    const firstClaim = await repository.claimUnarchivedCertificates(now, 10);
    const secondClaim = await repository.claimUnarchivedCertificates(now, 10);

    expect(firstClaim).toHaveLength(1);
    expect(firstClaim[0]!.archive_lease_token).toMatch(/^[0-9a-f-]{36}$/i);
    expect(secondClaim).toHaveLength(0);

    const nextAttempt = new Date("2026-04-20T10:05:00.000Z");
    await repository.markCertificateArchiveFailed(
      jobId,
      firstClaim[0]!.archive_lease_token!,
      "s3 unavailable",
      nextAttempt,
      now
    );

    expect(await repository.claimUnarchivedCertificates(new Date("2026-04-20T10:04:59.000Z"), 10)).toHaveLength(0);
    const retryClaim = await repository.claimUnarchivedCertificates(new Date("2026-04-20T10:05:01.000Z"), 10);
    expect(retryClaim).toHaveLength(1);
    expect(retryClaim[0]!.archive_attempt_count).toBe(1);

    await repository.markCertificateArchived(
      jobId,
      retryClaim[0]!.archive_lease_token!,
      new Date("2026-04-20T10:05:02.000Z"),
      {
        bucket: "archive-bucket",
        objectKey: `certificates/${jobId}.pdf`,
        objectETag: '"etag"',
        objectVersionId: "version-1",
        retentionUntil: new Date("2027-04-20T10:05:02.000Z"),
      }
    );
    expect(await repository.claimUnarchivedCertificates(new Date("2026-04-20T10:05:03.000Z"), 10)).toHaveLength(0);
  });

  it("extends an active worker task lease without resurrecting completed tasks", async () => {
    const { repository, schema, organizationId, clientId, jobId } = await setup();
    const claimTime = new Date("2026-04-20T10:00:00.000Z");
    await sql`
      INSERT INTO ${sql(schema)}.task_queue (
        id,
        organization_id,
        client_id,
        erasure_job_id,
        task_type,
        payload,
        status,
        attempt_count,
        next_attempt_at,
        created_at,
        updated_at
      )
      VALUES (
        ${crypto.randomUUID()},
        ${organizationId},
        ${clientId},
        ${jobId},
        'COMPILE_DAG',
        ${sql.json({ erasure_job_id: jobId })},
        'QUEUED',
        0,
        ${claimTime},
        ${claimTime},
        ${claimTime}
      )
    `;

    const task = await repository.claimNextTask(
      clientId,
      "worker-lease-test",
      claimTime
    );

    expect(task).not.toBeNull();
    const originalExpiry = task!.lease_expires_at!.getTime();

    const extended = await repository.extendTaskLease(
      task!.id,
      task!.client_id,
      "worker-lease-test",
      new Date("2026-04-20T10:00:30.000Z")
    );
    expect(extended).not.toBeNull();
    expect(extended!.lease_expires_at!.getTime()).toBeGreaterThan(originalExpiry);

    await repository.ackTask(
      task!.id,
      "completed",
      { action: "compiled_dag", userHash: null, dryRun: false, compiledTargetCount: 0 },
      new Date("2026-04-20T10:00:31.000Z")
    );

    await expect(
      repository.extendTaskLease(
        task!.id,
        task!.client_id,
        "worker-lease-test",
        new Date("2026-04-20T10:00:32.000Z")
      )
    ).resolves.toBeNull();
  });
});
