import { fail } from "@/errors";
import type { OutboxRow } from "@/modules/network";
import type { SqlExecutor } from "@/types";
import { canonicalJsonStringify } from "@/utils";
import type postgres from "postgres";

const UNFINALIZED_PREVIOUS_HASH = "UNFINALIZED";
const UNFINALIZED_CURRENT_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

/**
 * Enqueues a tamper-evident outbox event inside the current transaction scope.
 *
 * The function is idempotent by `idempotency_key` and inserts an unfinalized chain record.
 * Hash-chain finalization is intentionally performed by the relay in a short read-committed
 * transaction after commit, avoiding repeatable-read snapshot forks under multi-worker load.
 *
 * @param sql - Postgres pool or transaction.
 * @param engineSchema - Worker engine schema.
 * @param userHash - Subject hash associated with the event.
 * @param eventType - Outbox event type.
 * @param payload - JSON-serializable event payload.
 * @param idempotencyKey - Global idempotency key for replay safety.
 * @param now - Event creation timestamp.
 * @returns Existing or newly inserted outbox row.
 * @throws {WorkerError} When payload is non-serializable or insert invariants are violated.
 */
export async function enqueueOutboxEvent(
  sql: SqlExecutor,
  engineSchema: string,
  userHash: string,
  eventType: string,
  payload: unknown,
  idempotencyKey: string,
  now: Date
): Promise<OutboxRow> {
  const jsonPayload = payload as postgres.JSONValue;
  try {
    canonicalJsonStringify(jsonPayload);
  } catch {
    fail({
      code: "OUTBOX_PAYLOAD_INVALID",
      title: "Invalid outbox payload",
      detail: "Outbox payload must be JSON-serializable.",
      category: "validation",
      retryable: false,
    });
  }

  const [existing] = await sql<OutboxRow[]>`
    SELECT *
    FROM ${sql(engineSchema)}.outbox
    WHERE idempotency_key = ${idempotencyKey}
    LIMIT 1
  `;

  if (existing) {
    return existing;
  }

  const [inserted] = await sql<OutboxRow[]>`
    INSERT INTO ${sql(engineSchema)}.outbox (
      idempotency_key,
      user_uuid_hash,
      event_type,
      payload,
      previous_hash,
      current_hash,
      chain_status,
      status,
      attempt_count,
      next_attempt_at,
      created_at,
      updated_at
    )
    VALUES (
      ${idempotencyKey},
      ${userHash},
      ${eventType},
      ${sql.json(jsonPayload)},
      ${UNFINALIZED_PREVIOUS_HASH},
      ${UNFINALIZED_CURRENT_HASH},
      'pending',
      'pending',
      0,
      ${now},
      ${now},
      ${now}
    )
    ON CONFLICT (idempotency_key) DO NOTHING
    RETURNING *
  `;

  if (inserted) {
    return inserted;
  }

  const [stored] = await sql<OutboxRow[]>`
    SELECT *
    FROM ${sql(engineSchema)}.outbox
    WHERE idempotency_key = ${idempotencyKey}
    LIMIT 1
  `;

  if (!stored) {
    fail({
      code: "OUTBOX_INSERT_INVARIANT_BROKEN",
      title: "Outbox insert invariant broken",
      detail: `Outbox insert for ${idempotencyKey} completed without returning a row.`,
      category: "database",
      retryable: false,
      fatal: true,
      context: { idempotencyKey },
    });
  }

  return stored;
}

