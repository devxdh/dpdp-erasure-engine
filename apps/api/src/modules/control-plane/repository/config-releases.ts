import type {
  ApproveWorkerConfigReleaseInput,
  RepositoryContext,
  WorkerConfigReleaseRow,
} from "./types";

/**
 * Approves or replaces a worker configuration release for a client.
 *
 * The row is keyed by `(client_id, config_hash)`. Re-approving the same hash updates
 * the DPO metadata and clears any previous revocation.
 *
 * @param context - Repository SQL context.
 * @param input - DPO attestation and release metadata.
 * @returns Persisted release row or `null` when the client does not exist in the tenant.
 */
export async function approveWorkerConfigRelease(
  context: RepositoryContext,
  input: ApproveWorkerConfigReleaseInput
): Promise<WorkerConfigReleaseRow | null> {
  return context.sql.begin(async (tx) => {
    const [client] = await tx<{ id: string }[]>`
      SELECT id
      FROM ${tx(context.schema)}.clients
      WHERE organization_id = ${input.organizationId}
        AND name = ${input.clientName}
      FOR UPDATE
    `;
    if (!client) {
      return null;
    }

    await tx`
      UPDATE ${tx(context.schema)}.clients
      SET require_approved_config = ${input.requireApprovedConfig}
      WHERE id = ${client.id}
    `;

    const [release] = await tx<WorkerConfigReleaseRow[]>`
      INSERT INTO ${tx(context.schema)}.worker_config_releases (
        organization_id,
        client_id,
        config_hash,
        configuration_version,
        dpo_identifier,
        legal_review_date,
        status,
        allowed_live_mutation,
        approved_at,
        revoked_at,
        notes,
        created_at
      )
      VALUES (
        ${input.organizationId},
        ${client.id},
        ${input.configHash},
        ${input.configurationVersion},
        ${input.dpoIdentifier},
        ${input.legalReviewDate ?? null},
        'APPROVED',
        ${input.allowedLiveMutation},
        ${input.now},
        NULL,
        ${input.notes ?? null},
        ${input.now}
      )
      ON CONFLICT (client_id, config_hash) DO UPDATE
      SET configuration_version = EXCLUDED.configuration_version,
          dpo_identifier = EXCLUDED.dpo_identifier,
          legal_review_date = EXCLUDED.legal_review_date,
          status = 'APPROVED',
          allowed_live_mutation = EXCLUDED.allowed_live_mutation,
          approved_at = EXCLUDED.approved_at,
          revoked_at = NULL,
          notes = EXCLUDED.notes
      RETURNING *
    `;

    return release ?? null;
  });
}

/**
 * Revokes a worker configuration release so future sync attempts fail closed.
 *
 * @param context - Repository SQL context.
 * @param organizationId - Tenant organization id.
 * @param clientName - Worker client name.
 * @param configHash - SHA-256 hash of the worker YAML.
 * @param now - Revocation timestamp.
 * @returns Revoked release row or `null` when no matching release exists.
 */
export async function revokeWorkerConfigRelease(
  context: RepositoryContext,
  organizationId: string,
  clientName: string,
  configHash: string,
  now: Date
): Promise<WorkerConfigReleaseRow | null> {
  const [row] = await context.sql<WorkerConfigReleaseRow[]>`
    UPDATE ${context.sql(context.schema)}.worker_config_releases AS release
    SET status = 'REVOKED',
        revoked_at = ${now}
    FROM ${context.sql(context.schema)}.clients AS client
    WHERE release.client_id = client.id
      AND client.organization_id = ${organizationId}
      AND client.name = ${clientName}
      AND release.config_hash = ${configHash}
    RETURNING release.*
  `;
  return row ?? null;
}

/**
 * Reads the active config release for sync-time fail-closed checks.
 *
 * @param context - Repository SQL context.
 * @param clientId - Worker client UUID.
 * @param configHash - SHA-256 hash observed in the sync heartbeat.
 * @returns Matching release row or `null`.
 */
export async function getWorkerConfigRelease(
  context: RepositoryContext,
  clientId: string,
  configHash: string
): Promise<WorkerConfigReleaseRow | null> {
  const [row] = await context.sql<WorkerConfigReleaseRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.worker_config_releases
    WHERE client_id = ${clientId}
      AND config_hash = ${configHash}
    LIMIT 1
  `;
  return row ?? null;
}

/**
 * Lists config releases for a tenant-owned worker client.
 *
 * @param context - Repository SQL context.
 * @param organizationId - Tenant organization id.
 * @param clientName - Worker client name.
 * @returns Newest releases first.
 */
export async function listWorkerConfigReleases(
  context: RepositoryContext,
  organizationId: string,
  clientName: string
): Promise<WorkerConfigReleaseRow[]> {
  return context.sql<WorkerConfigReleaseRow[]>`
    SELECT release.*
    FROM ${context.sql(context.schema)}.worker_config_releases AS release
    JOIN ${context.sql(context.schema)}.clients AS client
      ON client.id = release.client_id
    WHERE client.organization_id = ${organizationId}
      AND client.name = ${clientName}
    ORDER BY release.created_at DESC
  `;
}
