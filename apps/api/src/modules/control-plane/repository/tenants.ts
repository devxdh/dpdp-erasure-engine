import type {
  ApiKeyRow,
  CreateApiKeyInput,
  CreateOrganizationInput,
  OrganizationRow,
  OrganizationUserRow,
  RepositoryContext,
} from "./types";

/**
 * Creates an organization and optional first owner member.
 *
 * @param context - Repository SQL context.
 * @param input - Organization and owner metadata.
 * @returns Persisted organization row.
 */
export async function createOrganization(
  context: RepositoryContext,
  input: CreateOrganizationInput
): Promise<OrganizationRow> {
  return context.sql.begin(async (tx) => {
    const [organization] = await tx<OrganizationRow[]>`
      INSERT INTO ${tx(context.schema)}.organizations (
        name,
        billing_plan,
        certificate_archive_retention_days,
        created_at
      )
      VALUES (
        ${input.name},
        ${input.billingPlan},
        ${input.certificateArchiveRetentionDays ?? 365},
        ${input.now}
      )
      RETURNING *
    `;

    if (input.ownerEmail) {
      await tx`
        INSERT INTO ${tx(context.schema)}.users (
          email,
          oidc_provider_id,
          organization_id,
          role,
          created_at
        )
        VALUES (
          ${input.ownerEmail.toLowerCase()},
          ${input.oidcProviderId ?? `email:${input.ownerEmail.toLowerCase()}`},
          ${organization!.id},
          'OWNER',
          ${input.now}
        )
        ON CONFLICT (organization_id, email) DO NOTHING
      `;
    }

    return organization!;
  });
}

/**
 * Finds an organization by stable name.
 *
 * @param context - Repository SQL context.
 * @param name - Organization name.
 * @returns Matching organization or `null`.
 */
export async function getOrganizationByName(
  context: RepositoryContext,
  name: string
): Promise<OrganizationRow | null> {
  const [organization] = await context.sql<OrganizationRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.organizations
    WHERE name = ${name}
  `;
  return organization ?? null;
}

/**
 * Ensures the bootstrap organization exists.
 *
 * @param context - Repository SQL context.
 * @returns Bootstrap organization row.
 */
export async function ensureBootstrapOrganization(
  context: RepositoryContext
): Promise<OrganizationRow> {
  const [organization] = await context.sql<OrganizationRow[]>`
    INSERT INTO ${context.sql(context.schema)}.organizations (name, billing_plan)
    VALUES ('bootstrap', 'internal')
    ON CONFLICT (name) DO UPDATE
      SET name = EXCLUDED.name
    RETURNING *
  `;
  return organization!;
}

/**
 * Creates a DB-backed API key hash for an organization.
 *
 * @param context - Repository SQL context.
 * @param input - API key metadata and digest.
 * @returns Persisted API key row.
 */
export async function createApiKey(
  context: RepositoryContext,
  input: CreateApiKeyInput
): Promise<ApiKeyRow> {
  const [row] = await context.sql<ApiKeyRow[]>`
    INSERT INTO ${context.sql(context.schema)}.api_keys (
      organization_id,
      hashed_key,
      label,
      scopes,
      created_at
    )
    VALUES (
      ${input.organizationId},
      ${input.hashedKey},
      ${input.label},
      ${input.scopes},
      ${input.now}
    )
    RETURNING *
  `;
  return row!;
}

/**
 * Ensures the local bootstrap admin key exists as a normal tenant API key.
 *
 * @param context - Repository SQL context.
 * @param hashedKey - SHA-256 digest of the bootstrap admin token.
 * @param now - Seed timestamp.
 * @returns Persisted API key row.
 */
export async function ensureBootstrapApiKey(
  context: RepositoryContext,
  hashedKey: string,
  now: Date
): Promise<ApiKeyRow> {
  const organization = await ensureBootstrapOrganization(context);
  const [row] = await context.sql<ApiKeyRow[]>`
    INSERT INTO ${context.sql(context.schema)}.api_keys (
      organization_id,
      hashed_key,
      label,
      scopes,
      created_at
    )
    VALUES (
      ${organization.id},
      ${hashedKey},
      'bootstrap-admin',
      ARRAY['*']::TEXT[],
      ${now}
    )
    ON CONFLICT (hashed_key) DO UPDATE
      SET label = EXCLUDED.label,
          scopes = EXCLUDED.scopes
    RETURNING *
  `;
  return row!;
}

/**
 * Finds an API key by SHA-256 digest and updates its last-used timestamp.
 *
 * @param context - Repository SQL context.
 * @param hashedKey - SHA-256 digest of the presented key.
 * @param now - Authentication timestamp.
 * @returns Matching API key or `null`.
 */
export async function authenticateApiKey(
  context: RepositoryContext,
  hashedKey: string,
  now: Date
): Promise<ApiKeyRow | null> {
  const [row] = await context.sql<ApiKeyRow[]>`
    UPDATE ${context.sql(context.schema)}.api_keys
    SET last_used_at = ${now}
    WHERE hashed_key = ${hashedKey}
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Lists members for one organization.
 *
 * @param context - Repository SQL context.
 * @param organizationId - Tenant organization id.
 * @returns Organization members sorted by creation time.
 */
export async function listOrganizationMembers(
  context: RepositoryContext,
  organizationId: string
): Promise<OrganizationUserRow[]> {
  return context.sql<OrganizationUserRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.users
    WHERE organization_id = ${organizationId}
    ORDER BY created_at ASC
  `;
}
