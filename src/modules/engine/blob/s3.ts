import type { BlobTarget } from "@/modules/config";
import { createS3Client, parseS3ObjectUrl, type S3Client, type S3ObjectVersion } from "@/modules/network";
import type { Tsql } from "@/types";
import type { BlobProtectionResult, BlobShredReceipt, DiscoveredBlobObject } from "./types";
import { fail } from "@/errors";
import { yieldWorkerEventLoop } from "../vault/satellite-mutation";
import { generateHMAC } from "@/modules/crypto";
import { bytesToBase64 } from "@/lib";
import { countOtherActiveBlobReferences, getPendingBlobObjectsForUser, insertBlobObject, markBlobObjectShredded, type BlobObjectRow } from "./store";


export interface ProtectBlobTargetsInput {
  tx: Tsql;
  appSchema: string;
  engineSchema: string;
  rootTable: string;
  rootIdColumn: string;
  rootId: string | number;
  userHash: string;
  requestId?: string | null;
  tenantId?: string;
  targets: readonly BlobTarget[];
  lockedRootRow: Record<string, unknown>;
  hmacKey: Uint8Array;
  s3Client?: S3Client;
  shadowMode?: boolean;
  now: Date;
}

interface ProtectedBlobTargetsResult {
  rootColumnMasks: Record<string, string>;
  receipts: BlobProtectionResult[];
}

interface BlobCandidate {
  target: BlobTarget;
  sourceTable: string;
  sourceColumn: string;
  originalValue: string;
}

interface ProtectedBlobTargetsResult {
  rootColumnMasks: Record<string, string>;
  receipts: BlobProtectionResult[];
}


async function hmacBlobField(prefix: string, value: string, hmacKey: Uint8Array): Promise<string> {
  return generateHMAC(`${prefix}:${value}`, bytesToBase64(hmacKey));
}

async function buildObjectRefHash(
  bucket: string,
  key: string,
  versionId: string,
  hmacKey: Uint8Array
): Promise<string> {
  return hmacBlobField("s3-object-ref", `${bucket}\n${key}\n${versionId}`, hmacKey);
}

async function buildVersionHash(versionId: string, hmacKey: Uint8Array): Promise<string> {
  return hmacBlobField("s3-version-id", versionId, hmacKey);
}


async function updateBlobSourceColumn(
  tx: Tsql,
  appSchema: string,
  rootId: string | number,
  tenantId: string | undefined,
  candidate: BlobCandidate,
  maskedValue: string
): Promise<void> {
  if (!candidate.target.lookup_column) {
    return;
  }

  const tenantFilter = tenantId ? tx` AND tenant_id = ${tenantId}` : tx``;
  await tx`
    UPDATE ${tx(appSchema)}.${tx(candidate.target.table)}
    SET ${tx(candidate.target.column)} = ${maskedValue}
    WHERE ${tx(candidate.target.lookup_column)} = ${rootId}
      AND ${tx(candidate.target.column)} = ${candidate.originalValue}
      ${tenantFilter}
  `;
}

async function loadMaskingBlob(target: BlobTarget): Promise<Uint8Array> {
  if (!target.masking_blob_path) {
    fail({
      code: "BLOB_MASKING_ASSET_MISSING",
      title: "Blob masking asset missing",
      detail: `Blob target ${target.table}.${target.column} requires masking_blob_path for overwrite mode.`,
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  return new Uint8Array(await Bun.file(target.masking_blob_path).arrayBuffer());
}


function normalizeBlobCell(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }

  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * Checks whether configured blob targets contain any S3 URL values for the locked subject.
 *
 * @param input - Active vault transaction and target metadata.
 * @returns `true` when at least one configured blob cell contains a non-empty URL.
 */
export async function hasBlobTargetValues(input: ProtectBlobTargetsInput): Promise<boolean> {
  return (await collectBlobCandidates(input)).length > 0;
}

async function collectBlobCandidates(input: ProtectBlobTargetsInput): Promise<BlobCandidate[]> {
  const candidates: BlobCandidate[] = [];

  for (const target of input.targets) {
    if (target.table === input.rootTable) {
      const originalValue = normalizeBlobCell(input.lockedRootRow[target.column]);
      if (originalValue) {
        candidates.push({
          target,
          sourceTable: target.table,
          sourceColumn: target.column,
          originalValue,
        });
      }
      continue;
    }

    if (!target.lookup_column) {
      fail({
        code: "BLOB_LOOKUP_COLUMN_MISSING",
        title: "Blob target lookup column missing",
        detail: `Blob target ${target.table}.${target.column} requires lookup_column because it is not the root table.`,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    const tenantFilter = input.tenantId ? input.tx` AND tenant_id = ${input.tenantId}` : input.tx``;
    const rows = await input.tx<{ value: string | null }[]>`
      SELECT ${input.tx(target.column)}::text AS value
      FROM ${input.tx(input.appSchema)}.${input.tx(target.table)}
      WHERE ${input.tx(target.lookup_column)} = ${input.rootId}
      ${tenantFilter}
      FOR UPDATE
    `;

    for (const row of rows) {
      const originalValue = normalizeBlobCell(row.value);
      if (!originalValue) {
        continue;
      }

      candidates.push({
        target,
        sourceTable: target.table,
        sourceColumn: target.column,
        originalValue,
      });
    }
  }

  return candidates;
}

/**
 * Applies S3 legal holds, optional sanitized overwrites, and local DB URL masking for configured blob targets.
 *
 * External S3 side effects are skipped in shadow mode so a shadow task cannot mutate object storage
 * while its Postgres transaction rolls back.
 *
 * @param input - Active vault transaction, config, locked root row, S3 client, and crypto key.
 * @returns Root-column masks to merge into the root update plus sanitized outbox receipts.
 */
export async function protectBlobTargets(input: ProtectBlobTargetsInput): Promise<ProtectedBlobTargetsResult> {
  if (input.targets.length === 0) {
    return { rootColumnMasks: {}, receipts: [] };
  }

  const candidates = await collectBlobCandidates(input);
  if (candidates.length === 0) {
    return { rootColumnMasks: {}, receipts: [] };
  }

  const s3Client = input.shadowMode ? undefined : input.s3Client ?? createS3Client();
  const rootColumnMasks: Record<string, string> = {};
  const receipts: BlobProtectionResult[] = [];

  for (const candidate of candidates) {
    const pointer = parseS3ObjectUrl(candidate.originalValue);
    const maskedValue = await hmacBlobField(
      `blob-url:${input.appSchema}:${candidate.sourceTable}:${candidate.sourceColumn}`,
      candidate.originalValue,
      input.hmacKey
    );

    let versionId = pointer.versionId;
    let eTag: string | null = null;
    let overwriteETag: string | null = null;
    let overwriteVersionId: string | null = null;

    if (!input.shadowMode) {
      const head = await s3Client!.headObject({
        bucket: pointer.bucket,
        key: pointer.key,
        versionId: pointer.versionId,
        region: candidate.target.region,
        expectedBucketOwner: candidate.target.expected_bucket_owner,
      });
      versionId = versionId ?? head.versionId ?? undefined;
      eTag = head.eTag;

      if (candidate.target.require_version_id && !versionId) {
        fail({
          code: "BLOB_VERSION_ID_MISSING",
          title: "S3 object version id missing",
          detail: `Blob target ${candidate.sourceTable}.${candidate.sourceColumn} resolved to an S3 object without a version id.`,
          category: "integrity",
          retryable: false,
          fatal: true,
        });
      }

      await s3Client!.putObjectLegalHold({
        bucket: pointer.bucket,
        key: pointer.key,
        versionId,
        region: candidate.target.region,
        expectedBucketOwner: candidate.target.expected_bucket_owner,
        status: "ON",
      });

      if (candidate.target.action === "overwrite") {
        const overwriteReceipt = await s3Client!.putObject({
          bucket: pointer.bucket,
          key: pointer.key,
          region: candidate.target.region,
          expectedBucketOwner: candidate.target.expected_bucket_owner,
          body: await loadMaskingBlob(candidate.target),
          contentType: candidate.target.masking_blob_path?.endsWith(".pdf")
            ? "application/pdf"
            : "application/octet-stream",
        });
        overwriteETag = overwriteReceipt.eTag;
        overwriteVersionId = overwriteReceipt.versionId;
      }
    } else {
      versionId = versionId ?? "SHADOW_VERSION";
    }

    const resolvedVersionId = versionId ?? "null";
    const discovered: DiscoveredBlobObject = {
      target: candidate.target,
      sourceTable: candidate.sourceTable,
      sourceColumn: candidate.sourceColumn,
      originalValue: candidate.originalValue,
      maskedValue,
      bucket: pointer.bucket,
      key: pointer.key,
      versionId: resolvedVersionId,
      eTag,
      overwriteETag,
      overwriteVersionId,
    };

    if (candidate.target.table === input.rootTable) {
      rootColumnMasks[candidate.target.column] = maskedValue;
    } else {
      await updateBlobSourceColumn(
        input.tx,
        input.appSchema,
        input.rootId,
        input.tenantId,
        candidate,
        maskedValue
      );
    }

    await insertBlobObject(input.tx, {
      engineSchema: input.engineSchema,
      userHash: input.userHash,
      requestId: input.requestId,
      tenantId: input.tenantId,
      rootSchema: input.appSchema,
      rootTable: input.rootTable,
      rootId: String(input.rootId),
      discovered,
      now: input.now,
    });

    receipts.push({
      sourceTable: candidate.sourceTable,
      sourceColumn: candidate.sourceColumn,
      provider: "aws_s3",
      action: candidate.target.action,
      objectRefHash: await buildObjectRefHash(pointer.bucket, pointer.key, resolvedVersionId, input.hmacKey),
      versionIdHash: await buildVersionHash(resolvedVersionId, input.hmacKey),
      legalHoldApplied: !input.shadowMode,
      overwriteApplied: Boolean(overwriteVersionId),
    });

    await yieldWorkerEventLoop();
  }

  return { rootColumnMasks, receipts };
}

function filterVersionsForDeletion(row: BlobObjectRow, versions: S3ObjectVersion[]): S3ObjectVersion[] {
  if (row.action !== "overwrite" || !row.overwrite_version_id) {
    return versions;
  }

  return versions.filter((version) => version.versionId !== row.overwrite_version_id);
}

async function buildReceipt(
  row: BlobObjectRow,
  deletedVersions: readonly string[],
  retainedVersions: readonly string[],
  hmacKey: Uint8Array,
  status: BlobShredReceipt["status"]
): Promise<BlobShredReceipt> {
  return {
    provider: "aws_s3",
    action: row.action,
    objectRefHash: await buildObjectRefHash(row.bucket, row.object_key, row.version_id, hmacKey),
    versionCount: deletedVersions.length + retainedVersions.length,
    deletedVersionIdHashes: await Promise.all(deletedVersions.map((versionId) => buildVersionHash(versionId, hmacKey))),
    retainedVersionIdHashes: await Promise.all(retainedVersions.map((versionId) => buildVersionHash(versionId, hmacKey))),
    status,
  };
}

/**
 * Removes legal holds and purges all configured S3 object versions for a shredded subject.
 *
 * Raw bucket names and keys remain only in the worker-local database. Returned receipts are HMACed
 * so Control Plane CoEs can prove deletion without receiving object paths that may contain PII.
 *
 * @param tx - Active shred transaction.
 * @param engineSchema - Worker engine schema.
 * @param userHash - Subject hash in the local vault.
 * @param hmacKey - Worker HMAC key used to sanitize receipt identifiers.
 * @param now - Shred timestamp.
 * @param s3Client - Optional S3 client override for tests.
 * @returns Sanitized deletion receipts safe for the Control Plane outbox.
 */
export async function shredBlobObjects(
  tx: Tsql,
  engineSchema: string,
  userHash: string,
  hmacKey: Uint8Array,
  now: Date,
  s3Client: S3Client = createS3Client()
): Promise<BlobShredReceipt[]> {
  const rows = await getPendingBlobObjectsForUser(tx, engineSchema, userHash);
  const receipts: BlobShredReceipt[] = [];

  for (const row of rows) {
    if (row.action === "legal_hold_only") {
      const receipt = await buildReceipt(row, [], [row.version_id], hmacKey, "retained_by_policy");
      await markBlobObjectShredded(tx, engineSchema, row.id, receipt, now);
      receipts.push(receipt);
      continue;
    }

    const otherReferences = await countOtherActiveBlobReferences(tx, engineSchema, row);
    if (otherReferences > 0) {
      fail({
        code: "BLOB_SHARED_OBJECT_CONFLICT",
        title: "Shared S3 object deletion refused",
        detail: "The worker refuses to delete an S3 object that is still referenced by another unshredded subject.",
        category: "integrity",
        retryable: false,
        fatal: true,
        context: {
          provider: row.provider,
          bucket: row.bucket,
          objectKeyHash: await buildObjectRefHash(row.bucket, row.object_key, row.version_id, hmacKey),
          otherReferences,
        },
      });
    }

    if (row.legal_hold_status === "ON") {
      await s3Client.putObjectLegalHold({
        bucket: row.bucket,
        key: row.object_key,
        versionId: row.version_id,
        region: row.region,
        expectedBucketOwner: row.expected_bucket_owner ?? undefined,
        status: "OFF",
      });
    }

    if (row.action === "hard_delete") {
      const deleted = await s3Client.deleteObjectVersion({
        bucket: row.bucket,
        key: row.object_key,
        versionId: row.version_id === "null" ? undefined : row.version_id,
        region: row.region,
        expectedBucketOwner: row.expected_bucket_owner ?? undefined,
        bypassGovernanceRetention: row.retention_mode === "governance",
      });
      const deletedVersionId = deleted.versionId ?? row.version_id;
      const receipt = await buildReceipt(row, [deletedVersionId], [], hmacKey, "captured_version_deleted");
      await markBlobObjectShredded(tx, engineSchema, row.id, receipt, now);
      receipts.push(receipt);
      await yieldWorkerEventLoop();
      continue;
    }

    const versions = await s3Client.listObjectVersions({
      bucket: row.bucket,
      key: row.object_key,
      region: row.region,
      expectedBucketOwner: row.expected_bucket_owner ?? undefined,
    });
    const versionsToDelete = filterVersionsForDeletion(row, versions);
    const deletedVersionIds: string[] = [];

    for (const version of versionsToDelete) {
      await s3Client.deleteObjectVersion({
        bucket: row.bucket,
        key: row.object_key,
        versionId: version.versionId,
        region: row.region,
        expectedBucketOwner: row.expected_bucket_owner ?? undefined,
        bypassGovernanceRetention: row.retention_mode === "governance",
      });
      deletedVersionIds.push(version.versionId);
      await yieldWorkerEventLoop();
    }

    const retainedVersionIds =
      row.action === "overwrite" && row.overwrite_version_id ? [row.overwrite_version_id] : [];
    const receipt = await buildReceipt(row, deletedVersionIds, retainedVersionIds, hmacKey, "purged");
    await markBlobObjectShredded(tx, engineSchema, row.id, receipt, now);
    receipts.push(receipt);
  }

  return receipts;
}
