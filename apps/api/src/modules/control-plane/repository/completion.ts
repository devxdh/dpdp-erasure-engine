import type { RepositoryContext } from "./types";

export interface ProviderCompletionTargetRow {
  id: string;
  organization_id: string;
  client_id: string;
  provider: "onetrust" | "jira" | "zendesk";
  completion_url: string;
  auth_header_name: string | null;
  auth_header_value: string | null;
  is_active: boolean;
  created_at: Date;
  updated_at: Date;
}

export interface UpsertProviderCompletionTargetInput {
  organizationId: string;
  clientName: string;
  provider: "onetrust" | "jira" | "zendesk";
  completionUrl: string;
  authHeaderName?: string | null;
  authHeaderValue?: string | null;
  isActive: boolean;
  now: Date;
}

/**
 * Creates or updates the tenant-owned provider completion endpoint for a worker client.
 *
 * @param context - Repository dependencies.
 * @param input - Provider callback URL and optional provider auth header.
 * @returns Persisted completion target or `null` when the client is not tenant-owned.
 */
export async function upsertProviderCompletionTarget(
  context: RepositoryContext,
  input: UpsertProviderCompletionTargetInput
): Promise<ProviderCompletionTargetRow | null> {
  const [row] = await context.sql<ProviderCompletionTargetRow[]>`
    INSERT INTO ${context.sql(context.schema)}.provider_completion_targets (
      organization_id,
      client_id,
      provider,
      completion_url,
      auth_header_name,
      auth_header_value,
      is_active,
      created_at,
      updated_at
    )
    SELECT
      ${input.organizationId}::uuid,
      c.id,
      ${input.provider},
      ${input.completionUrl},
      ${input.authHeaderName ?? null},
      ${input.authHeaderValue ?? null},
      ${input.isActive},
      ${input.now},
      ${input.now}
    FROM ${context.sql(context.schema)}.clients AS c
    WHERE c.organization_id = ${input.organizationId}::uuid
      AND c.name = ${input.clientName}
    ON CONFLICT (organization_id, client_id, provider) DO UPDATE
    SET completion_url = EXCLUDED.completion_url,
        auth_header_name = EXCLUDED.auth_header_name,
        auth_header_value = EXCLUDED.auth_header_value,
        is_active = EXCLUDED.is_active,
        updated_at = EXCLUDED.updated_at
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Lists provider completion targets for one tenant and optional client.
 *
 * @param context - Repository dependencies.
 * @param organizationId - Tenant organization id.
 * @param clientName - Optional worker client name filter.
 * @returns Completion targets newest first.
 */
export async function listProviderCompletionTargets(
  context: RepositoryContext,
  organizationId: string,
  clientName?: string
): Promise<ProviderCompletionTargetRow[]> {
  return context.sql<ProviderCompletionTargetRow[]>`
    SELECT pct.*
    FROM ${context.sql(context.schema)}.provider_completion_targets AS pct
    JOIN ${context.sql(context.schema)}.clients AS c
      ON c.id = pct.client_id
    WHERE pct.organization_id = ${organizationId}::uuid
      AND (${clientName ?? null}::text IS NULL OR c.name = ${clientName ?? null})
    ORDER BY pct.updated_at DESC
  `;
}

/**
 * Resolves active provider completion targets for the GRC webhook that created a job.
 *
 * @param context - Repository dependencies.
 * @param jobId - Erasure job id.
 * @returns Active provider completion targets bound to the job's original provider webhook.
 */
export async function getProviderCompletionTargetsForJob(
  context: RepositoryContext,
  jobId: string
): Promise<Array<ProviderCompletionTargetRow & { external_reference_id: string }>> {
  return context.sql<Array<ProviderCompletionTargetRow & { external_reference_id: string }>>`
    SELECT pct.*, wi.external_reference_id
    FROM ${context.sql(context.schema)}.webhook_ingestions AS wi
    JOIN ${context.sql(context.schema)}.provider_completion_targets AS pct
      ON pct.organization_id = wi.organization_id
     AND pct.client_id = wi.client_id
     AND pct.provider = wi.provider
     AND pct.is_active = TRUE
    WHERE wi.erasure_job_id = ${jobId}::uuid
  `;
}
