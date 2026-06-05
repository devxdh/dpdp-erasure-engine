import { afterAll, beforeAll, describe, expect, it } from "vitest";
import postgres from "postgres";
import { createApp } from "../../src/app";
import { createEd25519Signer } from "@/crypto";
import { migrateApiSchema } from "@/db";
import { computeWormHash } from "@modules/control-plane";
import { withBootstrapTenantAuth, createTestSql, dropSchemas, uniqueSchema } from "../helpers";

describe("Blob-PDF Integration", () => {
  let sql: postgres.Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function setup() {
    const controlSchema = uniqueSchema("blob_pdf_test");
    schemasToDrop.push(controlSchema);
    await migrateApiSchema(sql, controlSchema);

    const app = withBootstrapTenantAuth(createApp({
      sql,
      controlSchema,
      signer: await createEd25519Signer("integration-key"),
      workerSharedSecret: "worker-secret",
      adminApiToken: "admin-secret",
      workerClientName: "worker-1",
      shadowBurnInRequired: false,
    }));

    const bootstrapClient = await sql<any[]>`
      INSERT INTO ${sql(controlSchema)}.clients (name, worker_api_key_hash)
      VALUES ('worker-1', '6fb46f7a92742970166379ed5195e79c4493a7cc5664280c039cfd4095ba5faf')
      RETURNING id
    `;
    const workerId = bootstrapClient[0]!.id;

    return { app, workerId, controlSchema };
  }

  it("generates a PDF including S3 purge receipts after SHRED_SUCCESS ingestion", async () => {
    const { app, workerId, controlSchema } = await setup();
    const requestId = crypto.randomUUID();

    // 1. Manually seed an executing job
    await sql`
      INSERT INTO ${sql(controlSchema)}.erasure_jobs (id, client_id, idempotency_key, subject_opaque_id, trigger_source, actor_opaque_id, legal_framework, request_timestamp, cooldown_days, status, vault_due_at)
      SELECT ${requestId}, id, gen_random_uuid(), 'usr_blob_test', 'ADMIN_PURGE', 'admin', 'DPDP_2023', NOW(), 0, 'NOTICE_SENT', NOW()
      FROM ${sql(controlSchema)}.clients WHERE id = ${workerId}
    `;

    // 2. Prepare the shred payload with S3 receipts
    const shredPayload = {
      request_id: requestId,
      subject_opaque_id: "usr_blob_test",
      trigger_source: "ADMIN_PURGE",
      legal_framework: "DPDP_2023",
      actor_opaque_id: "admin",
      applied_rule_name: "DEFAULT",
      applied_rule_citation: "Standard policy",
      event_timestamp: new Date().toISOString(),
      shredded_at: new Date().toISOString(),
      blob_receipts: [
        {
          provider: "aws_s3",
          action: "versioned_hard_delete",
          objectRefHash: "h1",
          versionCount: 5,
          deletedVersionIdHashes: ["v1", "v2", "v3", "v4", "v5"],
          retainedVersionIdHashes: [],
          status: "purged",
        },
        {
          provider: "aws_s3",
          action: "hard_delete",
          objectRefHash: "h2",
          versionCount: 1,
          deletedVersionIdHashes: ["v6"],
          retainedVersionIdHashes: [],
          status: "captured_version_deleted",
        },
      ],
    };

    const currentHash = await computeWormHash("GENESIS", shredPayload, `shred:${requestId}`);

    // 3. Ingest the shred event
    const outboxResponse = await app.request("/api/v1/worker/outbox", {
      method: "POST",
      headers: {
        "x-client-id": workerId,
        "authorization": "Bearer worker-secret",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        idempotency_key: `shred:${requestId}`,
        request_id: requestId,
        subject_opaque_id: "usr_blob_test",
        event_type: "SHRED_SUCCESS",
        payload: shredPayload,
        previous_hash: "GENESIS",
        current_hash: currentHash,
        event_timestamp: shredPayload.event_timestamp,
      }),
    });

    expect(outboxResponse.status).toBe(202);

    // 4. Download and verify the PDF
    const pdfResponse = await app.request(`/api/v1/certificates/${requestId}/download`);
    expect(pdfResponse.status).toBe(200);
    expect(pdfResponse.headers.get("content-type")).toBe("application/pdf");

    const pdfBuffer = await pdfResponse.arrayBuffer();
    expect(pdfBuffer.byteLength).toBeGreaterThan(1000);
  });
});
