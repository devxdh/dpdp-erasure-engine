import type { Tsql } from "@/types";
import type {
  DeferredLifecycleTaskType,
  RepositoryContext,
  TaskQueueRow,
} from "./types";
import {
  calculateTaskRetryDelayMs,
  shouldRetryTaskFailure,
} from "./types";

/**
 * Fetches the earliest task associated with a job.
 *
 * @param context - Repository SQL context.
 * @param jobId - Erasure job UUID.
 * @returns Task row or `null`.
 */
export async function getTaskByJobId(
  context: RepositoryContext,
  jobId: string,
  organizationId?: string
): Promise<TaskQueueRow | null> {
  const [task] = await context.sql<TaskQueueRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.task_queue
    WHERE erasure_job_id = ${jobId}
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
    ORDER BY created_at ASC
    LIMIT 1
  `;
  return task ?? null;
}

function buildLifecyclePayload(tx: Tsql) {
  return tx`
    jsonb_strip_nulls(
      jsonb_build_object(
        'request_id', ej.id,
        'subject_opaque_id', ej.subject_opaque_id,
        'idempotency_key', ej.idempotency_key::text,
        'trigger_source', ej.trigger_source,
        'actor_opaque_id', ej.actor_opaque_id,
        'legal_framework', ej.legal_framework,
        'request_timestamp', ej.request_timestamp,
        'tenant_id', ej.tenant_id,
        'cooldown_days', ej.cooldown_days,
        'shadow_mode', ej.shadow_mode,
        'webhook_url', ej.webhook_url
      )
    )
  `;
}

async function insertDueLifecycleTasks(
  context: RepositoryContext,
  tx: Tsql,
  clientId: string,
  now: Date,
  limit: number
): Promise<number> {
  let inserted = 0;
  const insertLifecycleTask = async (taskType: DeferredLifecycleTaskType) => {
    const dueColumn =
      taskType === "NOTIFY_USER" ? tx`ej.notification_due_at` : tx`ej.shred_due_at`;
    const requiredStatus = taskType === "NOTIFY_USER" ? "VAULTED" : "NOTICE_SENT";

    const rows = await tx<{ id: string }[]>`
      WITH due_jobs AS (
        SELECT ej.id
        FROM ${tx(context.schema)}.erasure_jobs AS ej
        WHERE ej.client_id = ${clientId}
          AND ej.status = ${requiredStatus}
          AND ${dueColumn} IS NOT NULL
          AND ${dueColumn} <= ${now}
        ORDER BY ${dueColumn} ASC, ej.created_at ASC
        LIMIT ${limit}
        FOR UPDATE SKIP LOCKED
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
        gen_random_uuid(),
        ej.organization_id,
        ej.client_id,
        ej.id,
        ${taskType},
        ${buildLifecyclePayload(tx)},
        'QUEUED',
        0,
        ${now},
        ${now},
        ${now}
      FROM ${tx(context.schema)}.erasure_jobs AS ej
      JOIN due_jobs AS due
        ON due.id = ej.id
      WHERE ej.client_id = ${clientId}
      ON CONFLICT (erasure_job_id, task_type) DO NOTHING
      RETURNING id
    `;
    inserted += rows.length;
  };

  await insertLifecycleTask("NOTIFY_USER");
  await insertLifecycleTask("SHRED_USER");
  return inserted;
}

/**
 * Materializes due NOTIFY/SHRED lifecycle tasks in bounded batches.
 *
 * The scheduler is intentionally separate from task leasing so worker sync remains a cheap
 * indexed queue claim under high polling concurrency. A non-blocking advisory lock ensures
 * only one materializer per worker client scans due jobs at a time.
 *
 * @param context - Repository SQL context.
 * @param clientId - Worker client whose lifecycle queue should be materialized.
 * @param now - Materialization timestamp.
 * @param limit - Maximum jobs to inspect per lifecycle type.
 * @returns Number of tasks inserted.
 */
export async function materializeDueLifecycleTasks(
  context: RepositoryContext,
  clientId: string,
  now: Date,
  limit: number = 1000
): Promise<number> {
  return context.sql.begin(async (tx) => {
    const [lock] = await tx<{ acquired: boolean }[]>`
      SELECT pg_try_advisory_xact_lock(hashtext(${`task-materializer:${clientId}`})) AS acquired
    `;
    if (!lock?.acquired) {
      return 0;
    }

    return insertDueLifecycleTasks(context, tx, clientId, now, limit);
  });
}

async function materializeVaultTaskAfterCompilation(
  context: RepositoryContext,
  tx: Tsql,
  task: TaskQueueRow,
  now: Date
): Promise<void> {
  await tx`
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
      gen_random_uuid(),
      ej.organization_id,
      ej.client_id,
      ej.id,
      'VAULT_USER',
      ${buildLifecyclePayload(tx)},
      'QUEUED',
      0,
      ${now},
      ${now},
      ${now}
    FROM ${tx(context.schema)}.erasure_jobs AS ej
    WHERE ej.id = ${task.erasure_job_id}
      AND ej.client_id = ${task.client_id}
      AND ej.organization_id = ${task.organization_id}
      AND ej.status NOT IN ('CANCELLED', 'SHREDDED', 'FAILED')
    ON CONFLICT (erasure_job_id, task_type) DO NOTHING
  `;
}

/**
 * Claims the next due task using `FOR UPDATE SKIP LOCKED` leasing semantics.
 *
 * @param context - Repository SQL context.
 * @param clientId - Authenticated worker client id.
 * @param workerClientName - Worker client name recorded in lease metadata.
 * @param now - Lease anchor timestamp.
 * @returns Leased task row or `null` when no due task is available.
 */
export async function claimNextTask(
  context: RepositoryContext,
  clientId: string,
  workerClientName: string,
  now: Date
): Promise<TaskQueueRow | null> {
  const claim = () => context.sql.begin(async (tx) => {
    const [candidate] = await tx<TaskQueueRow[]>`
      SELECT tq.*
      FROM ${tx(context.schema)}.task_queue AS tq
      JOIN ${tx(context.schema)}.erasure_jobs AS ej
        ON ej.id = tq.erasure_job_id
      WHERE tq.client_id = ${clientId}
        AND tq.status IN ('QUEUED', 'DISPATCHED')
        AND tq.next_attempt_at <= ${now}
        AND (tq.status = 'QUEUED' OR tq.lease_expires_at IS NULL OR tq.lease_expires_at <= ${now})
        AND ej.status NOT IN ('CANCELLED', 'SHREDDED', 'FAILED')
        AND (
          (tq.task_type = 'COMPILE_DAG' AND ej.vault_due_at <= NOW())
          OR
          (tq.task_type = 'VAULT_USER' AND ej.vault_due_at <= NOW())
          OR (tq.task_type = 'NOTIFY_USER' AND ej.notification_due_at IS NOT NULL AND ej.notification_due_at <= ${now})
          OR (tq.task_type = 'SHRED_USER' AND ej.shred_due_at IS NOT NULL AND ej.shred_due_at <= ${now})
        )
      ORDER BY
        CASE
          WHEN tq.task_type = 'COMPILE_DAG' THEN ej.vault_due_at
          WHEN tq.task_type = 'VAULT_USER' THEN ej.vault_due_at
          WHEN tq.task_type = 'NOTIFY_USER' THEN ej.notification_due_at
          ELSE ej.shred_due_at
        END ASC,
        tq.next_attempt_at ASC,
        tq.created_at ASC
      LIMIT 1
      FOR UPDATE OF tq, ej SKIP LOCKED
    `;

    if (!candidate) {
      return null;
    }

    const leaseExpiresAt = new Date(now.getTime() + context.taskLeaseSeconds * 1000);
    const [leased] = await tx<TaskQueueRow[]>`
      UPDATE ${tx(context.schema)}.task_queue
      SET status = 'DISPATCHED',
          worker_client_name = ${workerClientName},
          leased_at = ${now},
          lease_expires_at = ${leaseExpiresAt},
          updated_at = ${now}
      WHERE id = ${candidate.id}
      RETURNING *
    `;

    await tx`
      UPDATE ${tx(context.schema)}.erasure_jobs
      SET status = CASE WHEN status = 'WAITING_COOLDOWN' THEN 'EXECUTING' ELSE status END,
          updated_at = ${now}
      WHERE id = ${candidate.erasure_job_id}
    `;

    return leased ?? null;
  });

  const claimed = await claim();
  if (claimed) {
    return claimed;
  }

  await materializeDueLifecycleTasks(context, clientId, now, 100);
  return claim();
}

/**
 * Acknowledges task completion or failure and applies retry/DLQ state transitions.
 *
 * @param context - Repository SQL context.
 * @param taskId - Task UUID.
 * @param status - Worker ack status.
 * @param result - Worker result payload persisted for diagnostics.
 * @param now - Completion timestamp.
 * @returns Updated task row, current non-dispatched row, or `null` when task is missing.
 */
export async function ackTask(
  context: RepositoryContext,
  taskId: string,
  status: "completed" | "failed",
  result: unknown,
  now: Date
): Promise<TaskQueueRow | null> {
  return context.sql.begin(async (tx) => {
    const [task] = await tx<TaskQueueRow[]>`
      SELECT *
      FROM ${tx(context.schema)}.task_queue
      WHERE id = ${taskId}
      FOR UPDATE
    `;

    if (!task) {
      return null;
    }

    if (task.status !== "DISPATCHED") {
      return task;
    }

    if (status === "completed") {
      const [updated] = await tx<TaskQueueRow[]>`
        UPDATE ${tx(context.schema)}.task_queue
        SET status = 'COMPLETED',
            completed_at = ${now},
            error_text = NULL,
            lease_expires_at = NULL,
            updated_at = ${now}
        WHERE id = ${taskId}
        RETURNING *
      `;

      if (updated?.task_type === "COMPILE_DAG") {
        await materializeVaultTaskAfterCompilation(context, tx, updated, now);
      }

      return updated ?? null;
    }

    const attemptNumber = task.attempt_count + 1;
    const retryable = shouldRetryTaskFailure(result);
    const exhausted = attemptNumber >= context.taskMaxAttempts;

    if (!retryable || exhausted) {
      const [updated] = await tx<TaskQueueRow[]>`
        UPDATE ${tx(context.schema)}.task_queue
        SET status = 'DEAD_LETTER',
            attempt_count = ${attemptNumber},
            completed_at = ${now},
            dead_lettered_at = ${now},
            error_text = ${JSON.stringify(result)},
            lease_expires_at = NULL,
            updated_at = ${now}
        WHERE id = ${taskId}
        RETURNING *
      `;

      await tx`
        UPDATE ${tx(context.schema)}.erasure_jobs
        SET status = 'FAILED',
            updated_at = ${now}
        WHERE id = ${task.erasure_job_id}
      `;

      return updated ?? null;
    }

    const retryDelayMs = calculateTaskRetryDelayMs(
      attemptNumber,
      context.taskBaseBackoffMs
    );
    const [updated] = await tx<TaskQueueRow[]>`
      UPDATE ${tx(context.schema)}.task_queue
      SET status = 'QUEUED',
          worker_client_name = NULL,
          leased_at = NULL,
          lease_expires_at = NULL,
          completed_at = NULL,
          attempt_count = ${attemptNumber},
          next_attempt_at = ${now}::timestamptz + (${retryDelayMs} * interval '1 millisecond'),
          error_text = ${JSON.stringify(result)},
          updated_at = ${now}
      WHERE id = ${taskId}
      RETURNING *
    `;

    return updated ?? null;
  });
}

/**
 * Extends an active task lease held by an authenticated worker.
 *
 * This is intentionally narrow: it only updates tasks that are still `DISPATCHED`,
 * belong to the authenticated client, and are attributed to the current worker name.
 * Completed or requeued tasks are never resurrected by a late heartbeat.
 *
 * @param context - Repository SQL context.
 * @param taskId - Leased task UUID.
 * @param clientId - Authenticated worker client id.
 * @param workerClientName - Worker name stored on the active lease.
 * @param now - Heartbeat timestamp.
 * @returns Updated task row, or `null` when the lease is no longer active.
 */
export async function extendTaskLease(
  context: RepositoryContext,
  taskId: string,
  clientId: string,
  workerClientName: string,
  now: Date
): Promise<TaskQueueRow | null> {
  return context.sql.begin(async (tx) => {
    const leaseExpiresAt = new Date(now.getTime() + context.taskLeaseSeconds * 1000);
    const [task] = await tx<TaskQueueRow[]>`
      UPDATE ${tx(context.schema)}.task_queue
      SET lease_expires_at = ${leaseExpiresAt},
          updated_at = ${now}
      WHERE id = ${taskId}
        AND client_id = ${clientId}
        AND status = 'DISPATCHED'
        AND worker_client_name = ${workerClientName}
      RETURNING *
    `;

    return task ?? null;
  });
}

/**
 * Lists dead-lettered tasks for operator recovery workflows.
 *
 * @param context - Repository SQL context.
 * @returns Dead-lettered tasks newest first.
 */
export async function listDeadLetterTasks(
  context: RepositoryContext,
  organizationId?: string
): Promise<TaskQueueRow[]> {
  return context.sql<TaskQueueRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.task_queue
    WHERE status = 'DEAD_LETTER'
      AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
    ORDER BY dead_lettered_at DESC NULLS LAST, updated_at DESC
  `;
}

/**
 * Requeues a dead-lettered task for manual operator recovery.
 *
 * @param context - Repository SQL context.
 * @param taskId - Dead-letter task UUID.
 * @param now - Requeue timestamp.
 * @returns Updated task row or `null`.
 */
export async function requeueDeadLetterTask(
  context: RepositoryContext,
  taskId: string,
  now: Date,
  organizationId?: string
): Promise<TaskQueueRow | null> {
  return context.sql.begin(async (tx) => {
    const [task] = await tx<TaskQueueRow[]>`
      SELECT *
      FROM ${tx(context.schema)}.task_queue
      WHERE id = ${taskId}
        AND (${organizationId ?? null}::uuid IS NULL OR organization_id = ${organizationId ?? null})
      FOR UPDATE
    `;

    if (!task || task.status !== "DEAD_LETTER") {
      return null;
    }

    await tx`
      UPDATE ${tx(context.schema)}.erasure_jobs
      SET status = CASE WHEN status = 'FAILED' THEN 'EXECUTING' ELSE status END,
          updated_at = ${now}
      WHERE id = ${task.erasure_job_id}
    `;

    const [updated] = await tx<TaskQueueRow[]>`
      UPDATE ${tx(context.schema)}.task_queue
      SET status = 'QUEUED',
          worker_client_name = NULL,
          leased_at = NULL,
          lease_expires_at = NULL,
          completed_at = NULL,
          next_attempt_at = ${now},
          dead_lettered_at = NULL,
          error_text = NULL,
          updated_at = ${now}
      WHERE id = ${taskId}
      RETURNING *
    `;

    return updated ?? null;
  });
}
