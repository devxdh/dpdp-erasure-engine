import type {
  ClientRow,
  CreateClientInput,
  RepositoryContext,
  RotateClientKeyInput,
  RotateClientWebhookSecretInput,
} from "./types";

/**
 * Upserts a worker client record and rotates its token hash atomically.
 *
 * @param context - Repository SQL context.
 * @param name - Stable worker client name.
 * @param workerApiKeyHash - SHA-256 digest of worker bearer token.
 * @returns Persisted client row.
 */
export async function ensureClient(
  context: RepositoryContext,
  name: string,
  workerApiKeyHash: string,
  organizationId?: string
): Promise<ClientRow> {
  const [row] = await context.sql<ClientRow[]>`
    INSERT INTO ${context.sql(context.schema)}.clients (
      organization_id,
      name,
      worker_api_key_hash,
      display_name,
      current_key_id,
      is_active,
      shadow_required_successes,
      rotated_at
    )
    VALUES (
      COALESCE(${organizationId ?? null}::uuid, (SELECT id FROM ${context.sql(context.schema)}.organizations WHERE name = 'bootstrap')),
      ${name},
      ${workerApiKeyHash},
      ${name},
      'bootstrap',
      TRUE,
      100,
      NOW()
    )
    ON CONFLICT (organization_id, name) DO UPDATE
      SET worker_api_key_hash = EXCLUDED.worker_api_key_hash
    RETURNING *
  `;
  return row!;
}

/**
 * Finds a registered worker client by its unique ID.
 *
 * @param context - Repository SQL context.
 * @param id - Worker client UUID.
 * @returns Matching client row or `null`.
 */
export async function getClientById(
  context: RepositoryContext,
  id: string
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.clients
    WHERE id = ${id}
  `;
  return row ?? null;
}

/**
 * Finds a registered worker client by name.
 *
 * @param context - Repository SQL context.
 * @param name - Worker client name.
 * @returns Matching client row or `null`.
 */
export async function getClientByName(
  context: RepositoryContext,
  name: string,
  organizationId?: string
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.clients
    WHERE name = ${name}
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
  `;
  return row ?? null;
}

/**
 * Lists registered worker clients ordered by creation time.
 *
 * @param context - Repository SQL context.
 * @returns All persisted worker clients.
 */
export async function listClients(
  context: RepositoryContext,
  organizationId?: string
): Promise<ClientRow[]> {
  return context.sql<ClientRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.clients
    WHERE (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
    ORDER BY created_at ASC
  `;
}

/**
 * Creates a new worker client with its initial key metadata.
 *
 * @param context - Repository SQL context.
 * @param input - Client attributes and hashed token.
 * @returns Persisted client row.
 */
export async function createClient(
  context: RepositoryContext,
  input: CreateClientInput
): Promise<ClientRow> {
  const [row] = await context.sql<ClientRow[]>`
    INSERT INTO ${context.sql(context.schema)}.clients (
      organization_id,
      name,
      display_name,
      worker_api_key_hash,
      current_key_id,
      is_active,
      rotated_at,
      require_approved_config,
      created_at
    )
    VALUES (
      ${input.organizationId},
      ${input.name},
      ${input.displayName ?? null},
      ${input.workerApiKeyHash},
      ${input.currentKeyId},
      TRUE,
      ${input.now},
      ${input.requireApprovedConfig ?? false},
      ${input.now}
    )
    RETURNING *
  `;
  return row!;
}

/**
 * Rotates the active worker token hash for an existing client.
 *
 * @param context - Repository SQL context.
 * @param input - Rotation metadata and new hashed token.
 * @returns Updated client row or `null`.
 */
export async function rotateClientKey(
  context: RepositoryContext,
  input: RotateClientKeyInput
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    UPDATE ${context.sql(context.schema)}.clients
    SET worker_api_key_hash = ${input.workerApiKeyHash},
        current_key_id = ${input.currentKeyId},
        rotated_at = ${input.now},
        is_active = TRUE
    WHERE name = ${input.name}
      AND (${input.organizationId ?? null}::uuid IS NULL OR organization_id = ${input.organizationId ?? null})
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Rotates the provider webhook signing secret while preserving the previous secret temporarily.
 *
 * @param context - Repository SQL context.
 * @param input - Rotation metadata, replacement secret, and grace window.
 * @returns Updated client row or `null` when the client is missing.
 */
export async function rotateClientWebhookSecret(
  context: RepositoryContext,
  input: RotateClientWebhookSecretInput
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    UPDATE ${context.sql(context.schema)}.clients
    SET webhook_previous_signing_secret = webhook_signing_secret,
        webhook_signing_secret = ${input.webhookSigningSecret},
        webhook_secret_rotated_at = ${input.now},
        webhook_previous_secret_expires_at = CASE
          WHEN webhook_signing_secret IS NULL THEN NULL
          ELSE ${input.now} + MAKE_INTERVAL(hours := ${input.previousSecretGraceHours})
        END
    WHERE name = ${input.name}
      AND organization_id = ${input.organizationId}
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Directly stores an initial provider webhook signing secret when no old value needs rotation.
 *
 * @param context - Repository SQL context.
 * @param input - Client, tenant, and replacement secret metadata.
 * @returns Updated client row or `null` when the client is missing.
 */
export async function setClientWebhookSecret(
  context: RepositoryContext,
  input: Omit<RotateClientWebhookSecretInput, "previousSecretGraceHours">
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    UPDATE ${context.sql(context.schema)}.clients
    SET webhook_signing_secret = ${input.webhookSigningSecret},
        webhook_secret_rotated_at = ${input.now},
        webhook_previous_signing_secret = NULL,
        webhook_previous_secret_expires_at = NULL
    WHERE name = ${input.name}
      AND organization_id = ${input.organizationId}
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Enables or disables a worker client without deleting its audit lineage.
 *
 * @param context - Repository SQL context.
 * @param name - Stable worker client name.
 * @param active - Desired active state.
 * @returns Updated client row or `null`.
 */
export async function setClientActiveState(
  context: RepositoryContext,
  name: string,
  active: boolean,
  organizationId?: string
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    UPDATE ${context.sql(context.schema)}.clients
    SET is_active = ${active}
    WHERE name = ${name}
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Marks a client as successfully authenticated by a worker request.
 *
 * @param context - Repository SQL context.
 * @param clientId - Worker client id.
 * @param now - Authentication timestamp.
 */
export async function touchClientAuthentication(
  context: RepositoryContext,
  clientId: string,
  now: Date
): Promise<void> {
  await context.sql`
    UPDATE ${context.sql(context.schema)}.clients
    SET last_authenticated_at = ${now}
    WHERE id = ${clientId}
  `;
}

/**
 * Records one successful shadow-mode vault and enables live mutation after the burn-in threshold.
 *
 * @param context - Repository SQL context.
 * @param clientId - Worker client id.
 * @param requiredSuccesses - Control-plane threshold before live mutations are accepted.
 * @param now - State transition timestamp.
 * @returns Updated client row or `null` when the client is missing.
 */
export async function recordShadowVaultSuccess(
  context: RepositoryContext,
  clientId: string,
  requiredSuccesses: number,
  now: Date
): Promise<ClientRow | null> {
  const [row] = await context.sql<ClientRow[]>`
    UPDATE ${context.sql(context.schema)}.clients
    SET shadow_success_count = shadow_success_count + 1,
        shadow_required_successes = ${requiredSuccesses},
        live_mutation_enabled = CASE
          WHEN shadow_success_count + 1 >= ${requiredSuccesses} THEN TRUE
          ELSE live_mutation_enabled
        END,
        live_mutation_enabled_at = CASE
          WHEN live_mutation_enabled_at IS NULL
           AND shadow_success_count + 1 >= ${requiredSuccesses}
            THEN ${now}
          ELSE live_mutation_enabled_at
        END
    WHERE id = ${clientId}
    RETURNING *
  `;
  return row ?? null;
}

/**
 * Idempotently records shadow burn-in for a completed task and increments the client once.
 *
 * The task marker prevents duplicate counts when a worker retries an acknowledgement after the
 * Control Plane committed the first response but the network dropped the HTTP reply.
 *
 * @param context - Repository SQL context.
 * @param taskId - Completed `VAULT_USER` task id.
 * @param clientId - Worker client id.
 * @param requiredSuccesses - Control-plane threshold before live mutations are accepted.
 * @param now - State transition timestamp.
 * @returns Updated client row, or `null` when this task was already counted.
 */
export async function recordShadowVaultSuccessForTask(
  context: RepositoryContext,
  taskId: string,
  clientId: string,
  requiredSuccesses: number,
  now: Date
): Promise<ClientRow | null> {
  return context.sql.begin(async (tx) => {
    const [marked] = await tx<{ id: string }[]>`
      UPDATE ${tx(context.schema)}.task_queue
      SET shadow_burn_in_recorded_at = ${now},
          updated_at = ${now}
      WHERE id = ${taskId}
        AND client_id = ${clientId}
        AND task_type = 'VAULT_USER'
        AND status = 'COMPLETED'
        AND shadow_burn_in_recorded_at IS NULL
      RETURNING id
    `;

    if (!marked) {
      return null;
    }

    const [row] = await tx<ClientRow[]>`
      UPDATE ${tx(context.schema)}.clients
      SET shadow_success_count = shadow_success_count + 1,
          shadow_required_successes = ${requiredSuccesses},
          live_mutation_enabled = CASE
            WHEN shadow_success_count + 1 >= ${requiredSuccesses} THEN TRUE
            ELSE live_mutation_enabled
          END,
          live_mutation_enabled_at = CASE
            WHEN live_mutation_enabled_at IS NULL
             AND shadow_success_count + 1 >= ${requiredSuccesses}
              THEN ${now}
            ELSE live_mutation_enabled_at
          END
      WHERE id = ${clientId}
      RETURNING *
    `;

    return row ?? null;
  });
}
