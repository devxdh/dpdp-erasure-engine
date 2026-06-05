import { fail } from "@/errors";
import { assertIdentifier } from "@/db";
import { sha256Hex, uuidV5 } from "./security";
import type { IngestWebhookInput, IngestWebhookResult, WebhookClient } from "./types";
import type { Sql } from "@/types";

const WEBHOOK_UUID_NAMESPACE = "67d7b5a2-9e2b-4d2d-a8de-73a6daef9c17";

interface PostgresErrorLike {
  code?: string;
  constraint_name?: string;
  constraint?: string;
}

interface ExistingWebhookIngestion {
  erasure_job_id: string | null;
  task_id: string | null;
  external_subject_hash: string;
  subject_opaque_id: string | null;
}

function isUniqueViolation(error: unknown): error is PostgresErrorLike {
  return typeof error === "object" && error !== null && (error as PostgresErrorLike).code === "23505";
}

/**
 * Loads a webhook target client by UUID.
 *
 * @param sql - Postgres connection pool.
 * @param controlSchema - Control-plane schema.
 * @param clientId - URL client id.
 * @returns Active/inactive client metadata or `null`.
 */
export async function getWebhookClient(
  sql: Sql,
  controlSchema: string,
  clientId: string
): Promise<WebhookClient | null> {
  const schema = assertIdentifier(controlSchema, "control schema");
  const [client] = await sql<WebhookClient[]>`
    SELECT
      id,
      organization_id,
      is_active,
      webhook_signing_secret,
      webhook_previous_signing_secret,
      webhook_previous_secret_expires_at
    FROM ${sql(schema)}.clients
    WHERE id = ${clientId}::uuid
  `;
  return client ?? null;
}

/**
 * Resolves subject mapping, inserts an erasure job, and enqueues a DAG compilation task atomically.
 *
 * Duplicate idempotency keys are intentionally surfaced as graceful duplicates so external
 * webhook providers do not retry forever after a successful first ingest.
 *
 * @param sql - Postgres connection pool.
 * @param controlSchema - Control-plane schema name.
 * @param input - Verified and normalized webhook job.
 * @returns Accepted ingestion result.
 */
export async function ingestWebhookTransaction(
  sql: Sql,
  controlSchema: string,
  input: IngestWebhookInput
): Promise<IngestWebhookResult> {
  const schema = assertIdentifier(controlSchema, "control schema");
  const providerSubjectHash = await sha256Hex(`${input.provider}\n${input.normalized.provider_subject_id}`);
  const idempotencyKey = await uuidV5(
    WEBHOOK_UUID_NAMESPACE,
    `${input.client.id}\n${input.provider}\n${input.normalized.external_reference_id}`
  );
  const jobId = globalThis.crypto.randomUUID();
  const taskId = globalThis.crypto.randomUUID();
  let resolvedSubjectId: string | null = null;
  let transactionResult: IngestWebhookResult | null = null;

  try {
    await sql.begin(async (tx) => {
      const [client] = await tx<WebhookClient[]>`
        SELECT
          id,
          organization_id,
          is_active,
          webhook_signing_secret,
          webhook_previous_signing_secret,
          webhook_previous_secret_expires_at
        FROM ${tx(schema)}.clients
        WHERE id = ${input.client.id}::uuid
        FOR UPDATE
      `;

      if (!client || !client.is_active) {
        fail({
          code: "API_WEBHOOK_CLIENT_INACTIVE",
          title: "Webhook client inactive",
          detail: "Webhook target client is inactive or missing.",
          status: 401,
          category: "authentication",
          retryable: false,
        });
      }

      const [mapping] = await tx<{ subject_opaque_id: string }[]>`
        SELECT subject_opaque_id
        FROM ${tx(schema)}.external_subject_mappings
        WHERE organization_id = ${client.organization_id}
          AND provider = ${input.provider}
          AND external_subject_hash = ${providerSubjectHash}
        FOR UPDATE
      `;

      if (!mapping) {
        fail({
          code: "API_WEBHOOK_SUBJECT_MAPPING_NOT_FOUND",
          title: "Webhook subject mapping not found",
          detail: "The provider subject id has not been mapped to an opaque subject id.",
          status: 404,
          category: "validation",
          retryable: false,
          context: {
            provider: input.provider,
            externalSubjectHash: providerSubjectHash,
          },
        });
      }
      resolvedSubjectId = mapping.subject_opaque_id;

      const [ingestion] = await tx<{ id: string }[]>`
        INSERT INTO ${tx(schema)}.webhook_ingestions (
          organization_id,
          client_id,
          provider,
          external_reference_id,
          external_subject_hash,
          idempotency_key,
          received_at
        )
        VALUES (
          ${client.organization_id},
          ${client.id},
          ${input.provider},
          ${input.normalized.external_reference_id},
          ${providerSubjectHash},
          ${idempotencyKey}::uuid,
          ${input.now}
        )
        ON CONFLICT (organization_id, client_id, provider, external_reference_id) DO NOTHING
        RETURNING id
      `;

      if (!ingestion) {
        const [existing] = await tx<ExistingWebhookIngestion[]>`
          SELECT
            wi.erasure_job_id,
            wi.task_id,
            wi.external_subject_hash,
            ej.subject_opaque_id
          FROM ${tx(schema)}.webhook_ingestions AS wi
          LEFT JOIN ${tx(schema)}.erasure_jobs AS ej
            ON ej.id = wi.erasure_job_id
          WHERE wi.organization_id = ${client.organization_id}
            AND wi.client_id = ${client.id}
            AND wi.provider = ${input.provider}
            AND wi.external_reference_id = ${input.normalized.external_reference_id}
          FOR UPDATE OF wi
        `;

        if (!existing || existing.external_subject_hash !== providerSubjectHash) {
          fail({
            code: "API_WEBHOOK_REPLAY_CONFLICT",
            title: "Conflicting webhook replay",
            detail: "The provider reference id was already ingested with a different subject fingerprint.",
            status: 409,
            category: "validation",
            retryable: false,
            context: {
              provider: input.provider,
              external_reference_id: input.normalized.external_reference_id,
            },
          });
        }

        transactionResult = {
          accepted: true,
          duplicate: true,
          erasure_job_id: existing.erasure_job_id,
          task_id: existing.task_id,
          subject_opaque_id: existing.subject_opaque_id ?? resolvedSubjectId,
        };
        return;
      }

      await tx`
        INSERT INTO ${tx(schema)}.erasure_jobs (
          id,
          organization_id,
          client_id,
          idempotency_key,
          subject_opaque_id,
          trigger_source,
          actor_opaque_id,
          legal_framework,
          request_timestamp,
          cooldown_days,
          shadow_mode,
          status,
          vault_due_at,
          created_at,
          updated_at
        )
        VALUES (
          ${jobId},
          ${client.organization_id},
          ${client.id},
          ${idempotencyKey}::uuid,
          ${resolvedSubjectId},
          ${input.normalized.trigger_source},
          ${`webhook:${input.provider}`},
          'DPDP',
          ${input.normalized.request_timestamp},
          0,
          FALSE,
          'WAITING_COOLDOWN',
          NOW() + MAKE_INTERVAL(days := 0),
          ${input.now},
          ${input.now}
        )
      `;

      await tx`
        INSERT INTO ${tx(schema)}.task_queue (
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
          ${taskId},
          ${client.organization_id},
          ${client.id},
          ${jobId},
          'COMPILE_DAG',
          ${tx.json({ erasure_job_id: jobId })},
          'QUEUED',
          0,
          ${input.now},
          ${input.now},
          ${input.now}
        )
      `;

      await tx`
        UPDATE ${tx(schema)}.webhook_ingestions
        SET erasure_job_id = ${jobId},
            task_id = ${taskId}
        WHERE organization_id = ${client.organization_id}
          AND client_id = ${client.id}
          AND provider = ${input.provider}
          AND external_reference_id = ${input.normalized.external_reference_id}
      `;
    });

    if (transactionResult) {
      return transactionResult;
    }

    return {
      accepted: true,
      duplicate: false,
      erasure_job_id: jobId,
      task_id: taskId,
      subject_opaque_id: resolvedSubjectId ?? undefined,
    };
  } catch (error) {
    if (isUniqueViolation(error)) {
      const [existing] = await sql<{
        id: string;
        subject_opaque_id: string;
        task_id: string | null;
      }[]>`
        SELECT ej.id,
               ej.subject_opaque_id,
               tq.id AS task_id
        FROM ${sql(schema)}.erasure_jobs AS ej
        LEFT JOIN ${sql(schema)}.task_queue AS tq
          ON tq.erasure_job_id = ej.id
         AND tq.task_type = 'COMPILE_DAG'
        WHERE ej.organization_id = ${input.client.organization_id}
          AND ej.idempotency_key = ${idempotencyKey}::uuid
        LIMIT 1
      `;

      return {
        accepted: true,
        duplicate: true,
        erasure_job_id: existing?.id ?? null,
        task_id: existing?.task_id ?? null,
        subject_opaque_id: existing?.subject_opaque_id,
      };
    }

    throw error;
  }
}
