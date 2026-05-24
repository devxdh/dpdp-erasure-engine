import type postgres from "postgres";
import type { BlobAction, DiscoveredBlobObject, BlobShredReceipt } from "./types";

export interface BlobObjectRow {
  id: string;
  user_uuid_hash: string;
  request_id: string | null;
  tenant_id: string;
  root_schema: string;
  root_table: string;
  root_id: string;
  source_table: string;
  source_column: string;
  provider: "aws_s3";
  action: BlobAction;
  retention_mode: "governance" | "compliance";
  region: string;
  expected_bucket_owner: string | null;
  bucket: string;
  object_key: string;
  version_id: string;
  e_tag: string | null;
  masked_value: string;
  legal_hold_status: "ON" | "OFF" | "not_supported";
  legal_hold_applied_at: Date | null;
  overwrite_status: "not_requested" | "applied";
  overwrite_e_tag: string | null;
  overwrite_version_id: string | null;
  overwrite_applied_at: Date | null;
  shred_status: "pending" | "purged" | "captured_version_deleted" | "retained_by_policy";
  shred_receipt: BlobShredReceipt | null;
  shredded_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export interface InsertBlobObjectInput {
  engineSchema: string;
  userHash: string;
  requestId?: string | null;
  tenantId?: string;
  rootSchema: string;
  rootTable: string;
  rootId: string;
  discovered: DiscoveredBlobObject;
  now: Date;
}

/**
 * Persists one protected S3 object receipt in the worker-local vault ledger.
 *
 * @param tx - Active vault transaction.
 * @param input - Blob metadata discovered from the local database and S3.
 * @returns Inserted or replayed blob object row.
 */
export async function insertBlobObject(
  tx: postgres.TransactionSql,
  input: InsertBlobObjectInput
): Promise<BlobObjectRow> {
  const [row] = await tx<BlobObjectRow[]>`
    INSERT INTO ${tx(input.engineSchema)}.blob_objects (
      user_uuid_hash,
      request_id,
      tenant_id,
      root_schema,
      root_table,
      root_id,
      source_table,
      source_column,
      provider,
      action,
      retention_mode,
      region,
      expected_bucket_owner,
      bucket,
      object_key,
      version_id,
      e_tag,
      masked_value,
      legal_hold_status,
      legal_hold_applied_at,
      overwrite_status,
      overwrite_e_tag,
      overwrite_version_id,
      overwrite_applied_at,
      shred_status,
      created_at,
      updated_at
    )
    VALUES (
      ${input.userHash},
      ${input.requestId ?? null},
      ${input.tenantId ?? ""},
      ${input.rootSchema},
      ${input.rootTable},
      ${input.rootId},
      ${input.discovered.sourceTable},
      ${input.discovered.sourceColumn},
      'aws_s3',
      ${input.discovered.target.action},
      ${input.discovered.target.retention_mode},
      ${input.discovered.target.region},
      ${input.discovered.target.expected_bucket_owner ?? null},
      ${input.discovered.bucket},
      ${input.discovered.key},
      ${input.discovered.versionId},
      ${input.discovered.eTag},
      ${input.discovered.maskedValue},
      'ON',
      ${input.now},
      ${input.discovered.overwriteVersionId ? "applied" : "not_requested"},
      ${input.discovered.overwriteETag},
      ${input.discovered.overwriteVersionId},
      ${input.discovered.overwriteVersionId ? input.now : null},
      'pending',
      ${input.now},
      ${input.now}
    )
    ON CONFLICT (user_uuid_hash, source_table, source_column, bucket, object_key, version_id)
    DO UPDATE
      SET legal_hold_status = EXCLUDED.legal_hold_status,
          expected_bucket_owner = EXCLUDED.expected_bucket_owner,
          legal_hold_applied_at = EXCLUDED.legal_hold_applied_at,
          overwrite_status = EXCLUDED.overwrite_status,
          overwrite_e_tag = EXCLUDED.overwrite_e_tag,
          overwrite_version_id = EXCLUDED.overwrite_version_id,
          overwrite_applied_at = EXCLUDED.overwrite_applied_at,
          updated_at = EXCLUDED.updated_at
    RETURNING *
  `;

  return row!;
}

/**
 * Lists pending blob objects attached to one vaulted subject.
 *
 * @param tx - Active shred transaction.
 * @param engineSchema - Worker engine schema.
 * @param userHash - Vault subject hash.
 * @returns Pending blob object rows.
 */
export async function getPendingBlobObjectsForUser(
  tx: postgres.TransactionSql,
  engineSchema: string,
  userHash: string
): Promise<BlobObjectRow[]> {
  return tx<BlobObjectRow[]>`
    SELECT *
    FROM ${tx(engineSchema)}.blob_objects
    WHERE user_uuid_hash = ${userHash}
      AND shred_status = 'pending'
    ORDER BY created_at ASC, id ASC
    FOR UPDATE
  `;
}

/**
 * Counts pending blob objects for a subject without claiming them.
 *
 * @param tx - Active shred transaction.
 * @param engineSchema - Worker engine schema.
 * @param userHash - Vault subject hash.
 * @returns Number of pending blob object rows.
 */
export async function countPendingBlobObjectsForUser(
  tx: postgres.TransactionSql,
  engineSchema: string,
  userHash: string
): Promise<number> {
  const [row] = await tx<{ total: number }[]>`
    SELECT COUNT(*)::int AS total
    FROM ${tx(engineSchema)}.blob_objects
    WHERE user_uuid_hash = ${userHash}
      AND shred_status = 'pending'
  `;

  return row?.total ?? 0;
}

/**
 * Counts active references to the same physical S3 object held by other subjects.
 *
 * @param tx - Active shred transaction.
 * @param engineSchema - Worker engine schema.
 * @param row - Blob object being considered for destructive S3 deletion.
 * @returns Number of non-purged references owned by other subjects.
 */
export async function countOtherActiveBlobReferences(
  tx: postgres.TransactionSql,
  engineSchema: string,
  row: BlobObjectRow
): Promise<number> {
  const [result] = await tx<{ total: number }[]>`
    SELECT COUNT(*)::int AS total
    FROM ${tx(engineSchema)}.blob_objects
    WHERE provider = ${row.provider}
      AND bucket = ${row.bucket}
      AND object_key = ${row.object_key}
      AND user_uuid_hash <> ${row.user_uuid_hash}
      AND shred_status IN ('pending', 'retained_by_policy')
  `;

  return result?.total ?? 0;
}

/**
 * Marks a blob object as shredded or explicitly retained by policy.
 *
 * @param tx - Active shred transaction.
 * @param engineSchema - Worker engine schema.
 * @param rowId - Blob object row id.
 * @param receipt - Sanitized non-PII deletion receipt.
 * @param now - Completion timestamp.
 */
export async function markBlobObjectShredded(
  tx: postgres.TransactionSql,
  engineSchema: string,
  rowId: string,
  receipt: BlobShredReceipt,
  now: Date
): Promise<void> {
  await tx`
    UPDATE ${tx(engineSchema)}.blob_objects
    SET shred_status = ${receipt.status},
        shred_receipt = ${tx.json(receipt as unknown as postgres.JSONValue)},
        legal_hold_status = CASE
          WHEN ${receipt.status === "retained_by_policy"} THEN legal_hold_status
          ELSE 'OFF'
        END,
        shredded_at = ${now},
        updated_at = ${now}
    WHERE id = ${rowId}
  `;
}
