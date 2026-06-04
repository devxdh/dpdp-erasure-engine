import type {
  CertificateRow,
  InsertCertificateInput,
  RepositoryContext,
} from "./types";

/**
 * Inserts a signed Certificate of Erasure idempotently.
 *
 * @param context - Repository SQL context.
 * @param input - Persisted certificate payload and signature envelope.
 * @returns `true` when inserted, `false` when certificate already exists.
 */
export async function insertCertificate(
  context: RepositoryContext,
  input: InsertCertificateInput
): Promise<boolean> {
  const rows = await context.sql<{ request_id: string }[]>`
    INSERT INTO ${context.sql(context.schema)}.certificates (
      request_id,
      organization_id,
      subject_opaque_id,
      method,
      legal_framework,
      shredded_at,
      payload,
      signature_base64,
      public_key_spki_base64,
      key_id,
      algorithm,
      archive_next_attempt_at
    ) VALUES (
      ${input.requestId},
      ${input.organizationId},
      ${input.subjectOpaqueId},
      ${input.method},
      ${input.legalFramework},
      ${input.shreddedAt},
      ${context.sql.json(input.payload as import("postgres").JSONValue)},
      ${input.signatureBase64},
      ${input.publicKeySpkiBase64},
      ${input.keyId},
      ${input.algorithm},
      ${input.archiveNextAttemptAt ?? context.sql`NOW()`}
    )
    ON CONFLICT (request_id) DO NOTHING
    RETURNING request_id
  `;

  return rows.length > 0;
}

/**
 * Fetches minted certificate by request id.
 *
 * @param context - Repository SQL context.
 * @param requestId - Erasure request UUID.
 * @returns Certificate row or `null`.
 */
export async function getCertificateByRequestId(
  context: RepositoryContext,
  requestId: string,
  organizationId?: string
): Promise<CertificateRow | null> {
  const [certificate] = await context.sql<CertificateRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.certificates
    WHERE request_id = ${requestId}
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
  `;

  return certificate ?? null;
}

/**
 * Claims a batch of certificates that have not been archived to WORM storage yet.
 *
 * @param context - Repository SQL context.
 * @param limit - Batch size.
 * @param now - Claim timestamp.
 * @param organizationId - Optional tenant scope.
 * @param leaseSeconds - Exclusive processing window.
 * @returns Claimed certificate rows carrying a non-null archive lease token.
 */
export async function claimUnarchivedCertificates(
  context: RepositoryContext,
  now: Date,
  limit: number = 50,
  organizationId?: string,
  leaseSeconds: number = 300
): Promise<CertificateRow[]> {
  const leaseToken = globalThis.crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + leaseSeconds * 1000);

  return context.sql<CertificateRow[]>`
    WITH claimed AS (
      UPDATE ${context.sql(context.schema)}.certificates
      SET archive_status = 'LEASED',
          archive_lease_token = ${leaseToken}::uuid,
          archive_lease_expires_at = ${leaseExpiresAt}
      WHERE request_id IN (
        SELECT request_id
        FROM ${context.sql(context.schema)}.certificates
        WHERE archived_at IS NULL
          AND archive_status IN ('PENDING', 'LEASED', 'FAILED')
          AND archive_next_attempt_at <= ${now}
          AND (archive_lease_expires_at IS NULL OR archive_lease_expires_at <= ${now})
          AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
        ORDER BY archive_next_attempt_at ASC, created_at ASC
        LIMIT ${limit}
        FOR UPDATE SKIP LOCKED
      )
      RETURNING *
    )
    SELECT claimed.*, org.certificate_archive_retention_days AS archive_retention_days
    FROM claimed
    JOIN ${context.sql(context.schema)}.organizations AS org
      ON org.id = claimed.organization_id
  `;
}

export interface MarkCertificateArchivedInput {
  requestId: string;
  leaseToken: string;
  bucket: string;
  objectKey: string;
  objectETag: string | null;
  objectVersionId: string | null;
  retentionUntil: Date;
  now: Date;
}

/**
 * Marks a certificate as successfully archived to WORM storage.
 *
 * @param context - Repository SQL context.
 * @param input - Lease token and immutable archive receipt metadata.
 */
export async function markCertificateArchived(
  context: RepositoryContext,
  input: MarkCertificateArchivedInput
): Promise<void> {
  await context.sql`
    UPDATE ${context.sql(context.schema)}.certificates
    SET archived_at = ${input.now},
        archive_status = 'ARCHIVED',
        archive_lease_token = NULL,
        archive_lease_expires_at = NULL,
        archive_last_error = NULL,
        archive_bucket = ${input.bucket},
        archive_object_key = ${input.objectKey},
        archive_object_etag = ${input.objectETag},
        archive_object_version_id = ${input.objectVersionId},
        archive_retention_until = ${input.retentionUntil}
    WHERE request_id = ${input.requestId}
      AND archive_lease_token = ${input.leaseToken}::uuid
  `;
}

/**
 * Releases a certificate archive lease after a failed upload and schedules a retry.
 *
 * @param context - Repository SQL context.
 * @param requestId - Certificate request ID.
 * @param leaseToken - Lease token returned by `claimUnarchivedCertificates`.
 * @param error - Truncated operator-facing failure reason.
 * @param nextAttemptAt - Next retry timestamp.
 * @param now - Failure timestamp.
 */
export async function markCertificateArchiveFailed(
  context: RepositoryContext,
  requestId: string,
  leaseToken: string,
  error: string,
  nextAttemptAt: Date,
  now: Date
): Promise<void> {
  await context.sql`
    UPDATE ${context.sql(context.schema)}.certificates
    SET archive_status = 'FAILED',
        archive_attempt_count = archive_attempt_count + 1,
        archive_next_attempt_at = ${nextAttemptAt},
        archive_lease_token = NULL,
        archive_lease_expires_at = NULL,
        archive_last_error = ${error.slice(0, 1024)}
    WHERE request_id = ${requestId}
      AND archive_lease_token = ${leaseToken}::uuid
  `;
}
