import type {
  ExternalSubjectMappingRow,
  RepositoryContext,
  UpsertExternalSubjectMappingInput,
} from "./types";

/**
 * Upserts a zero-PII mapping from a GRC-local subject id hash to an opaque subject id.
 *
 * @param context - Repository SQL context.
 * @param input - Tenant, provider, hashed external id, and mapped opaque id.
 * @returns Persisted mapping row.
 */
export async function upsertExternalSubjectMapping(
  context: RepositoryContext,
  input: UpsertExternalSubjectMappingInput
): Promise<ExternalSubjectMappingRow> {
  const [row] = await context.sql<ExternalSubjectMappingRow[]>`
    INSERT INTO ${context.sql(context.schema)}.external_subject_mappings (
      organization_id,
      provider,
      external_subject_hash,
      subject_opaque_id,
      tenant_id,
      created_at,
      updated_at
    )
    VALUES (
      ${input.organizationId},
      ${input.provider},
      ${input.externalSubjectHash},
      ${input.subjectOpaqueId},
      ${input.tenantId ?? null},
      ${input.now},
      ${input.now}
    )
    ON CONFLICT (organization_id, provider, external_subject_hash)
    DO UPDATE SET
      subject_opaque_id = EXCLUDED.subject_opaque_id,
      tenant_id = EXCLUDED.tenant_id,
      updated_at = EXCLUDED.updated_at
    RETURNING *
  `;
  return row!;
}

/**
 * Looks up a tenant-scoped GRC subject mapping by provider and external subject hash.
 *
 * @param context - Repository SQL context.
 * @param organizationId - Tenant organization id.
 * @param provider - GRC provider slug.
 * @param externalSubjectHash - SHA-256 hash of provider plus external subject id.
 * @returns Matching mapping or `null`.
 */
export async function getExternalSubjectMapping(
  context: RepositoryContext,
  organizationId: string,
  provider: string,
  externalSubjectHash: string
): Promise<ExternalSubjectMappingRow | null> {
  const [row] = await context.sql<ExternalSubjectMappingRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.external_subject_mappings
    WHERE organization_id = ${organizationId}
      AND provider = ${provider}
      AND external_subject_hash = ${externalSubjectHash}
  `;
  return row ?? null;
}
