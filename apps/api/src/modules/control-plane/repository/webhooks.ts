import type { RepositoryContext } from "./types";

export interface WebhookOutboxRow {
  id: string;
  organization_id: string;
  job_id: string;
  url: string;
  headers: Record<string, string>;
  payload: unknown;
  status: "PENDING" | "RETRYING" | "PROCESSED" | "FAILED";
  attempt_count: number;
  lease_token: string | null;
  lease_expires_at: Date | null;
  next_attempt_at: Date;
  last_error: string | null;
  processed_at: Date | null;
  created_at: Date;
}

/**
 * Enqueues a webhook for asynchronous background delivery.
 */
export async function enqueueWebhook(
  context: RepositoryContext,
  input: {
    jobId: string;
    url: string;
    headers?: Record<string, string>;
    payload: unknown;
    now: Date;
  }
): Promise<void> {
  await context.sql`
    INSERT INTO ${context.sql(context.schema)}.webhook_outbox (
      organization_id,
      job_id,
      url,
      headers,
      payload,
      next_attempt_at,
      created_at,
      updated_at
    ) VALUES (
      (SELECT organization_id FROM ${context.sql(context.schema)}.erasure_jobs WHERE id = ${input.jobId}),
      ${input.jobId},
      ${input.url},
      ${context.sql.json(input.headers ?? {})},
      ${context.sql.json(input.payload as any)},
      ${input.now},
      ${input.now},
      ${input.now}
    )
    ON CONFLICT (job_id, url) DO UPDATE
    SET payload = CASE
          WHEN webhook_outbox.status = 'PROCESSED' THEN webhook_outbox.payload
          ELSE EXCLUDED.payload
        END,
        headers = CASE
          WHEN webhook_outbox.status = 'PROCESSED' THEN webhook_outbox.headers
          ELSE EXCLUDED.headers
        END,
        status = CASE
          WHEN webhook_outbox.status = 'PROCESSED' THEN webhook_outbox.status
          ELSE 'PENDING'
        END,
        lease_token = NULL,
        lease_expires_at = NULL,
        next_attempt_at = CASE
          WHEN webhook_outbox.status = 'PROCESSED' THEN webhook_outbox.next_attempt_at
          ELSE EXCLUDED.next_attempt_at
        END,
        updated_at = EXCLUDED.updated_at
  `;
}

/**
 * Claims a batch of pending webhooks for delivery attempts.
 */
export async function claimPendingWebhooks(
  context: RepositoryContext,
  limit: number = 10,
  now: Date,
  leaseSeconds: number = 60
): Promise<WebhookOutboxRow[]> {
  const leaseToken = globalThis.crypto.randomUUID();
  const leaseExpiresAt = new Date(now.getTime() + leaseSeconds * 1000);

  return context.sql<WebhookOutboxRow[]>`
    UPDATE ${context.sql(context.schema)}.webhook_outbox
    SET status = 'RETRYING',
        lease_token = ${leaseToken}::uuid,
        lease_expires_at = ${leaseExpiresAt},
        updated_at = ${now}
    WHERE id IN (
      SELECT id
      FROM ${context.sql(context.schema)}.webhook_outbox
      WHERE status IN ('PENDING', 'RETRYING')
        AND next_attempt_at <= ${now}
        AND (lease_expires_at IS NULL OR lease_expires_at <= ${now})
      ORDER BY next_attempt_at ASC
      LIMIT ${limit}
      FOR UPDATE SKIP LOCKED
    )
    RETURNING *
  `;
}

/**
 * Marks a webhook as successfully delivered.
 */
export async function markWebhookProcessed(
  context: RepositoryContext,
  id: string,
  leaseToken: string,
  now: Date
): Promise<void> {
  await context.sql`
    UPDATE ${context.sql(context.schema)}.webhook_outbox
    SET status = 'PROCESSED',
        lease_token = NULL,
        lease_expires_at = NULL,
        processed_at = ${now},
        updated_at = ${now}
    WHERE id = ${id}
      AND lease_token = ${leaseToken}::uuid
  `;
}

/**
 * Records a failed delivery attempt and schedules a retry.
 */
export async function markWebhookFailed(
  context: RepositoryContext,
  id: string,
  leaseToken: string,
  error: string,
  nextAttemptAt: Date,
  isPermanent: boolean,
  now: Date
): Promise<void> {
  await context.sql`
    UPDATE ${context.sql(context.schema)}.webhook_outbox
    SET status = ${isPermanent ? "FAILED" : "RETRYING"},
        attempt_count = attempt_count + 1,
        lease_token = NULL,
        lease_expires_at = NULL,
        last_error = ${error.slice(0, 1024)},
        next_attempt_at = ${nextAttemptAt},
        updated_at = ${now}
    WHERE id = ${id}
      AND lease_token = ${leaseToken}::uuid
  `;
}
