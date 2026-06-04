import type postgres from "postgres";
import type {
  BulkAdminPurgeInsertResult,
  CreateJobAndQueueTaskInput,
  CreateBulkAdminPurgeJobsInput,
  CreatedJobRecord,
  ErasureJobRow,
  ListErasureJobsInput,
  RepositoryContext,
  TaskQueueRow,
  TransitionJobFromOutboxInput,
} from "./types";

/**
 * Fetches an erasure job by request id.
 *
 * @param context - Repository SQL context.
 * @param jobId - Erasure job UUID.
 * @returns Job row or `null`.
 */
export async function getJobById(
  context: RepositoryContext,
  jobId: string,
  organizationId?: string
): Promise<ErasureJobRow | null> {
  const [job] = await context.sql<ErasureJobRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.erasure_jobs
    WHERE id = ${jobId}
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
  `;
  return job ?? null;
}

/**
 * Fetches an erasure job by idempotency key.
 *
 * @param context - Repository SQL context.
 * @param idempotencyKey - Request idempotency UUID.
 * @returns Job row or `null`.
 */
export async function getJobByIdempotencyKey(
  context: RepositoryContext,
  idempotencyKey: string,
  organizationId?: string
): Promise<ErasureJobRow | null> {
  const [job] = await context.sql<ErasureJobRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.erasure_jobs
    WHERE idempotency_key = ${idempotencyKey}::uuid
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
  `;
  return job ?? null;
}

/**
 * Lists erasure lifecycle aggregates for operator dashboard views.
 *
 * @param context - Repository SQL context.
 * @param input - Pagination and optional status filter.
 * @returns Matching erasure jobs newest first.
 */
export async function listErasureJobs(
  context: RepositoryContext,
  input: ListErasureJobsInput
): Promise<ErasureJobRow[]> {
  if (input.status) {
    return context.sql<ErasureJobRow[]>`
      SELECT *
      FROM ${context.sql(context.schema)}.erasure_jobs
      WHERE (${input.organizationId ?? null}::uuid IS NULL OR organization_id = ${input.organizationId ?? null})
        AND status = ${input.status}
      ORDER BY created_at DESC
      LIMIT ${input.limit}
      OFFSET ${input.offset}
    `;
  }

  return context.sql<ErasureJobRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.erasure_jobs
    WHERE (${input.organizationId ?? null}::uuid IS NULL OR organization_id = ${input.organizationId ?? null})
    ORDER BY created_at DESC
    LIMIT ${input.limit}
    OFFSET ${input.offset}
  `;
}

/**
 * Creates many administrator-approved purge jobs and their initial `VAULT_USER` tasks.
 *
 * The insert is set-based and idempotent on `(organization_id, idempotency_key)`, so a DPO
 * can safely retry the same batch without creating duplicate lifecycle timers.
 *
 * @param context - Repository SQL context.
 * @param input - Tenant, worker client, request metadata, and per-subject rows.
 * @returns Inserted/duplicate counts and inserted request ids.
 */
export async function createBulkAdminPurgeJobs(
  context: RepositoryContext,
  input: CreateBulkAdminPurgeJobsInput
): Promise<BulkAdminPurgeInsertResult> {
  if (input.rows.length === 0) {
    return { inserted: 0, duplicates: 0, requestIds: [] };
  }

  return context.sql.begin(async (tx) => {
    const rowsJson = input.rows.map((row) => ({
      job_id: row.jobId,
      task_id: row.taskId,
      idempotency_key: row.idempotencyKey,
      subject_opaque_id: row.subjectOpaqueId,
      payload: row.payload,
    }));

    const insertedJobs = await tx<{ id: string }[]>`
      WITH input_rows AS (
        SELECT *
        FROM jsonb_to_recordset(${tx.json(rowsJson as postgres.JSONValue)}::jsonb) AS row(
          job_id uuid,
          task_id uuid,
          idempotency_key uuid,
          subject_opaque_id text,
          payload jsonb
        )
      ),
      inserted_jobs AS (
        INSERT INTO ${tx(context.schema)}.erasure_jobs (
          id,
          organization_id,
          client_id,
          idempotency_key,
          subject_opaque_id,
          trigger_source,
          actor_opaque_id,
          legal_framework,
          request_timestamp,
          tenant_id,
          cooldown_days,
          shadow_mode,
          status,
          vault_due_at,
          created_at,
          updated_at
        )
        SELECT
          row.job_id,
          ${input.organizationId}::uuid,
          ${input.clientId}::uuid,
          row.idempotency_key,
          row.subject_opaque_id,
          'ADMIN_PURGE',
          ${input.actorOpaqueId},
          ${input.legalFramework},
          ${input.requestTimestamp},
          ${input.tenantId ?? null},
          0,
          ${input.shadowMode},
          'WAITING_COOLDOWN',
          NOW() + MAKE_INTERVAL(days := 0),
          ${input.now},
          ${input.now}
        FROM input_rows AS row
        ON CONFLICT (organization_id, idempotency_key) DO NOTHING
        RETURNING id
      )
      SELECT id
      FROM inserted_jobs
    `;

    await tx`
      WITH input_rows AS (
        SELECT *
        FROM jsonb_to_recordset(${tx.json(rowsJson as postgres.JSONValue)}::jsonb) AS row(
          job_id uuid,
          task_id uuid,
          idempotency_key uuid,
          subject_opaque_id text,
          payload jsonb
        )
      )
      INSERT INTO ${tx(context.schema)}.task_queue (
        id,
        organization_id,
        client_id,
        erasure_job_id,
        task_type,
        payload,
        status,
        attempt_count,
        next_attempt_at,
        created_at,
        updated_at
      )
      SELECT
        row.task_id,
        ${input.organizationId}::uuid,
        ${input.clientId}::uuid,
        row.job_id,
        'VAULT_USER',
        row.payload,
        'QUEUED',
        0,
        ${input.now},
        ${input.now},
        ${input.now}
      FROM input_rows AS row
      JOIN ${tx(context.schema)}.erasure_jobs AS ej
        ON ej.id = row.job_id
       AND ej.organization_id = ${input.organizationId}::uuid
      ON CONFLICT (erasure_job_id, task_type) DO NOTHING
    `;

    return {
      inserted: insertedJobs.length,
      duplicates: input.rows.length - insertedJobs.length,
      requestIds: insertedJobs.map((row) => row.id),
    };
  });
}

/**
 * Creates an erasure job and initial `VAULT_USER` task in one transaction.
 *
 * @param context - Repository SQL context.
 * @param input - Precomputed ids, normalized request payload, and timestamp.
 * @returns Inserted job and task rows.
 */
export async function createJobAndQueueTask(
  context: RepositoryContext,
  input: CreateJobAndQueueTaskInput
): Promise<CreatedJobRecord> {
  return context.sql.begin(async (tx) => {
    const [job] = await tx<ErasureJobRow[]>`
      INSERT INTO ${tx(context.schema)}.erasure_jobs (
        id,
        organization_id,
        client_id,
        idempotency_key,
        subject_opaque_id,
        trigger_source,
        actor_opaque_id,
        legal_framework,
        request_timestamp,
        tenant_id,
        cooldown_days,
        shadow_mode,
        webhook_url,
        status,
        vault_due_at,
        created_at,
        updated_at
      )
      VALUES (
        ${input.jobId},
        ${input.organizationId},
        ${input.clientId},
        ${input.request.idempotency_key}::uuid,
        ${input.request.subject_opaque_id},
        ${input.request.trigger_source},
        ${input.request.actor_opaque_id},
        ${input.request.legal_framework},
        ${new Date(input.request.request_timestamp)},
        ${input.request.tenant_id ?? null},
        ${input.request.cooldown_days},
        ${input.request.shadow_mode},
        ${input.request.webhook_url ?? null},
        'WAITING_COOLDOWN',
        NOW() + MAKE_INTERVAL(days := ${input.request.cooldown_days}),
        ${input.now},
        ${input.now}
      )
      RETURNING *
    `;

    const [task] = await tx<TaskQueueRow[]>`
      INSERT INTO ${tx(context.schema)}.task_queue (
        id,
        organization_id,
        client_id,
        erasure_job_id,
        task_type,
        payload,
        status,
        attempt_count,
        next_attempt_at,
        created_at,
        updated_at
      )
      VALUES (
        ${input.taskId},
        ${input.organizationId},
        ${input.clientId},
        ${input.jobId},
        'VAULT_USER',
        ${tx.json(input.payload as postgres.JSONValue)},
        'QUEUED',
        0,
        ${input.now},
        ${input.now},
        ${input.now}
      )
      RETURNING *
    `;

    return { job: job!, task: task! };
  });
}

/**
 * Cancels a job only when it is still in `WAITING_COOLDOWN`.
 *
 * @param context - Repository SQL context.
 * @param idempotencyKey - Request idempotency UUID.
 * @param now - Update timestamp.
 * @returns Cancelled job row or `null` if no eligible job was found.
 */
export async function cancelWaitingJobByIdempotencyKey(
  context: RepositoryContext,
  idempotencyKey: string,
  now: Date,
  organizationId?: string
): Promise<ErasureJobRow | null> {
  return context.sql.begin(async (tx) => {
    const [job] = await tx<ErasureJobRow[]>`
      UPDATE ${tx(context.schema)}.erasure_jobs
      SET status = 'CANCELLED',
          updated_at = ${now}
      WHERE idempotency_key = ${idempotencyKey}::uuid
        AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
        AND status = 'WAITING_COOLDOWN'
      RETURNING *
    `;

    if (!job) {
      return null;
    }

    await tx`
      UPDATE ${tx(context.schema)}.task_queue
      SET status = 'FAILED',
          completed_at = ${now},
          lease_expires_at = NULL,
          error_text = ${JSON.stringify({
      code: "API_TASK_CANCELLED",
      detail: "Task cancelled because erasure request moved to CANCELLED during cooldown.",
    })},
          updated_at = ${now}
      WHERE erasure_job_id = ${job.id}
        AND status IN ('QUEUED', 'DISPATCHED')
    `;

    return job;
  });
}

/**
 * Transitions erasure job state from worker outbox event semantics.
 *
 * @param context - Repository SQL context.
 * @param input - Job id, event type, and timestamps.
 */
export async function transitionJobFromOutbox(
  context: RepositoryContext,
  input: TransitionJobFromOutboxInput
): Promise<void> {
  const nextState =
    input.eventType === "USER_VAULTED"
      ? "VAULTED"
      : input.eventType === "NOTIFICATION_SENT"
        ? "NOTICE_SENT"
        : "SHREDDED";

  await context.sql`
    UPDATE ${context.sql(context.schema)}.erasure_jobs
    SET status = ${nextState},
        notification_due_at = CASE
          WHEN ${input.eventType === "USER_VAULTED"}
            THEN ${input.notificationDueAt ?? null}
          ELSE notification_due_at
        END,
        shred_due_at = CASE
          WHEN ${input.eventType === "USER_VAULTED"}
            THEN ${input.shredDueAt ?? null}
          ELSE shred_due_at
        END,
        applied_rule_name = CASE
          WHEN ${input.eventType === "USER_VAULTED" || input.eventType === "USER_HARD_DELETED"}
            THEN ${input.appliedRuleName ?? null}
          ELSE applied_rule_name
        END,
        applied_rule_citation = CASE
          WHEN ${input.eventType === "USER_VAULTED" || input.eventType === "USER_HARD_DELETED"}
            THEN ${input.appliedRuleCitation ?? null}
          ELSE applied_rule_citation
        END,
        shredded_at = CASE
          WHEN ${input.eventType === "SHRED_SUCCESS" || input.eventType === "USER_HARD_DELETED"}
            THEN ${input.shreddedAt ?? input.now}
          ELSE shredded_at
        END,
        updated_at = ${input.now}
    WHERE id = ${input.jobId}
  `;
}
