import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { Sql } from "@/types";
import { shredUser } from "@modules/engine";
import { vaultUser } from "@modules/engine";
import { type S3Client } from "@modules/network";
import {
  TEST_SECRETS,
  createTestSql,
  dropSchemas,
  insertUser,
  prepareWorkerSchemas,
  uniqueSchema,
} from "./helpers";

describe("S3 blob compliance provider", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function prepare() {
    const appSchema = uniqueSchema("blob_app");
    const engineSchema = uniqueSchema("blob_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await prepareWorkerSchemas(sql, appSchema, engineSchema, { withDependencies: true });
    await sql`ALTER TABLE ${sql(appSchema)}.users ADD COLUMN kyc_document_url TEXT`;
    const userId = await insertUser(sql, appSchema, "blob@example.com", "Blob User");
    await sql`
      UPDATE ${sql(appSchema)}.users
      SET kyc_document_url = 's3://kyc-bucket/kyc/john-doe-aadhar.pdf?versionId=v1'
      WHERE id = ${userId}
    `;

    return { appSchema, engineSchema, userId };
  }

  function mockS3Client() {
    const client: S3Client = {
      headObject: vi.fn(async (input) => ({
        bucket: input.bucket,
        key: input.key,
        versionId: input.versionId ?? "v1",
        eTag: "etag-v1",
      })),
      putObjectLegalHold: vi.fn(async () => undefined),
      listObjectVersions: vi.fn(async () => [
        { key: "kyc/john-doe-aadhar.pdf", versionId: "v1", eTag: "etag-v1", isDeleteMarker: false },
        { key: "kyc/john-doe-aadhar.pdf", versionId: "v2", eTag: "etag-v2", isDeleteMarker: false },
        { key: "kyc/john-doe-aadhar.pdf", versionId: "delete-marker", eTag: null, isDeleteMarker: true },
      ]),
      deleteObjectVersion: vi.fn(async (input) => ({
        key: input.key,
        versionId: input.versionId ?? null,
        deleteMarker: false,
        status: 204,
      })),
      putObject: vi.fn(async (input) => ({
        key: input.key,
        versionId: "sanitized-v1",
        eTag: "sanitized-etag",
        status: 200,
      })),
    };

    return client;
  }

  it("applies legal hold, masks the DB URL, and stores raw object coordinates only in the worker schema", async () => {
    const { appSchema, engineSchema, userId } = await prepare();
    const s3Client = mockS3Client();

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC",
        full_name: "STATIC_MASK",
      },
      satelliteTargets: [],
      blobTargets: [
        {
          table: "users",
          column: "kyc_document_url",
          provider: "aws_s3",
          region: "ap-south-1",
          action: "versioned_hard_delete",
          retention_mode: "governance",
          expected_bucket_owner: "123456789012",
          require_version_id: true,
        },
      ],
      s3Client,
      now: new Date("2026-01-10T00:00:00.000Z"),
    });

    expect(result.action).toBe("vaulted");
    expect(result.blobProtectionCount).toBe(1);
    expect(s3Client.putObjectLegalHold).toHaveBeenCalledWith(expect.objectContaining({
      bucket: "kyc-bucket",
      key: "kyc/john-doe-aadhar.pdf",
      versionId: "v1",
      expectedBucketOwner: "123456789012",
      status: "ON",
    }));

    const [user] = await sql<{ kyc_document_url: string }[]>`
      SELECT kyc_document_url
      FROM ${sql(appSchema)}.users
      WHERE id = ${userId}
    `;
    expect(user?.kyc_document_url).toMatch(/^[0-9a-f]{64}$/);

    const [blobRow] = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.blob_objects
      WHERE user_uuid_hash = ${result.userHash}
    `;
    expect(blobRow?.bucket).toBe("kyc-bucket");
    expect(blobRow?.object_key).toBe("kyc/john-doe-aadhar.pdf");
    expect(blobRow?.version_id).toBe("v1");
    expect(blobRow?.expected_bucket_owner).toBe("123456789012");

    const [outboxRow] = await sql<{ payload: { blob_protections: unknown[] } }[]>`
      SELECT payload
      FROM ${sql(engineSchema)}.outbox
      WHERE event_type = 'USER_VAULTED'
    `;
    expect(JSON.stringify(outboxRow?.payload)).not.toContain("john-doe-aadhar");
    expect(outboxRow?.payload.blob_protections).toHaveLength(1);
  });

  it("removes legal hold and deletes every S3 version during shredding", async () => {
    const { appSchema, engineSchema, userId } = await prepare();
    const s3Client = mockS3Client();
    const now = new Date("2026-01-10T00:00:00.000Z");

    const vaultResult = await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC",
        full_name: "STATIC_MASK",
      },
      satelliteTargets: [],
      blobTargets: [
        {
          table: "users",
          column: "kyc_document_url",
          provider: "aws_s3",
          region: "ap-south-1",
          action: "versioned_hard_delete",
          retention_mode: "governance",
          expected_bucket_owner: "123456789012",
          require_version_id: true,
        },
      ],
      s3Client,
      now,
    });

    await sql`
      UPDATE ${sql(engineSchema)}.pii_vault
      SET notification_sent_at = ${now},
          retention_expiry = ${now}
      WHERE user_uuid_hash = ${vaultResult.userHash}
    `;

    const shredResult = await shredUser(sql, userId, {
      appSchema,
      engineSchema,
      rootTable: "users",
      now,
      hmacKey: TEST_SECRETS.hmacKey,
      s3Client,
    });

    expect(shredResult.action).toBe("shredded");
    expect(shredResult.blobReceiptCount).toBe(1);
    expect(s3Client.putObjectLegalHold).toHaveBeenCalledWith(expect.objectContaining({
      versionId: "v1",
      expectedBucketOwner: "123456789012",
      status: "OFF",
    }));
    expect(s3Client.deleteObjectVersion).toHaveBeenCalledTimes(3);
    expect(s3Client.deleteObjectVersion).toHaveBeenCalledWith(expect.objectContaining({ versionId: "v1", expectedBucketOwner: "123456789012" }));
    expect(s3Client.deleteObjectVersion).toHaveBeenCalledWith(expect.objectContaining({ versionId: "v2", expectedBucketOwner: "123456789012" }));
    expect(s3Client.deleteObjectVersion).toHaveBeenCalledWith(expect.objectContaining({ versionId: "delete-marker", expectedBucketOwner: "123456789012" }));

    const [blobRow] = await sql<{ shred_status: string; shred_receipt: { deletedVersionIdHashes: string[] } }[]>`
      SELECT shred_status, shred_receipt
      FROM ${sql(engineSchema)}.blob_objects
      WHERE user_uuid_hash = ${vaultResult.userHash}
    `;
    expect(blobRow?.shred_status).toBe("purged");
    expect(blobRow?.shred_receipt.deletedVersionIdHashes).toHaveLength(3);

    const [outboxRow] = await sql<{ payload: { blob_receipts: unknown[] } }[]>`
      SELECT payload
      FROM ${sql(engineSchema)}.outbox
      WHERE event_type = 'SHRED_SUCCESS'
    `;
    expect(JSON.stringify(outboxRow?.payload)).not.toContain("john-doe-aadhar");
    expect(outboxRow?.payload.blob_receipts).toHaveLength(1);
  });
});
