import { sha256HexDigest } from "@/lib";
import type { Sql, Tsql } from "@/types";
import { canonicalJsonStringify } from "@/utils";
import { asWorkerError, fail } from "@/errors";
import type { OutboxEvent } from "./types";
import { calculateRetryDelayMs } from "./shared";

const DEFAULT_CHAIN_FINALIZATION_LIMIT = 1000;

interface ChainTailRow {
  current_hash: string;
}

interface UnfinalizedOutboxRow {
  id: string;
  idempotency_key: string;
  payload: unknown;
}

async function finalizePendingOutboxChain(
  tx: Tsql,
  engineSchema: string,
  limit: number
): Promise<void> {
  const [tail] = await tx<ChainTailRow[]>`
    SELECT current_hash
    FROM ${tx(engineSchema)}.outbox
    WHERE chain_status = 'finalized'
    ORDER BY created_at DESC, id DESC
    LIMIT 1
  `;
  let previousHash = tail?.current_hash ?? "GENESIS";

  const rows = await tx<UnfinalizedOutboxRow[]>`
    SELECT id, idempotency_key, payload
    FROM ${tx(engineSchema)}.outbox
    WHERE chain_status = 'pending'
    ORDER BY created_at ASC, id ASC
    LIMIT ${limit}
    FOR UPDATE
  `;

  for (const row of rows) {
    const currentHash = await sha256HexDigest(
      `${previousHash}${canonicalJsonStringify(row.payload)}${row.idempotency_key}`
    );

    await tx`
      UPDATE ${tx(engineSchema)}.outbox
      SET previous_hash = ${previousHash},
          current_hash = ${currentHash},
          chain_status = 'finalized',
          updated_at = NOW()
      WHERE id = ${row.id}
    `;
    previousHash = currentHash;
  }
}

/**
 * Claims one contiguous WORM-chain batch of due outbox events.
 *
 * The dispatcher cannot reorder events without invalidating the Control Plane audit chain.
 * A short advisory lock serializes lease selection across worker containers, then the query
 * walks `previous_hash -> current_hash` from the last processed event.
 *
 * @param sql - Postgres pool owning the outbox table.
 * @param engineSchema - Worker engine schema.
 * @param batchSize - Maximum rows to claim.
 * @param leaseSeconds - Lease duration in seconds.
 * @param now - Lease anchor timestamp.
 * @returns Lease token plus claimed events.
 */
export async function claimOutboxBatch(
  sql: Sql,
  engineSchema: string,
  batchSize: number,
  leaseSeconds: number,
  now: Date
): Promise<{ leaseToken: string; events: OutboxEvent[] }> {
  return sql.begin(async (tx) => {
    const leaseToken = globalThis.crypto.randomUUID();
    const leaseExpiresAt = new Date(now.getTime() + leaseSeconds * 1000);
    const events: OutboxEvent[] = [];

    await tx`
      SELECT pg_advisory_xact_lock(hashtext(${`${engineSchema}.outbox.dispatch_chain`}))
    `;

    await finalizePendingOutboxChain(
      tx,
      engineSchema,
      Math.max(batchSize, DEFAULT_CHAIN_FINALIZATION_LIMIT)
    );

    const [activeLease] = await tx<{ count: string }[]>`
      SELECT COUNT(*)::TEXT AS count
      FROM ${tx(engineSchema)}.outbox
      WHERE status = 'leased'
        AND lease_expires_at IS NOT NULL
        AND lease_expires_at > ${now}
    `;
    if (Number(activeLease?.count ?? "0") > 0) {
      return {
        leaseToken,
        events,
      };
    }

    const [tail] = await tx<ChainTailRow[]>`
      SELECT current_hash
      FROM ${tx(engineSchema)}.outbox
      WHERE status = 'processed'
        AND chain_status = 'finalized'
      ORDER BY created_at DESC, id DESC
      LIMIT 1
    `;
    let expectedPreviousHash = tail?.current_hash ?? "GENESIS";

    for (let index = 0; index < batchSize; index += 1) {
      const [event] = await tx<OutboxEvent[]>`
        SELECT *
        FROM ${tx(engineSchema)}.outbox
        WHERE status IN ('pending', 'leased')
          AND chain_status = 'finalized'
          AND previous_hash = ${expectedPreviousHash}
          AND next_attempt_at <= ${now}
          AND (status = 'pending' OR lease_expires_at IS NULL OR lease_expires_at <= ${now})
        ORDER BY created_at ASC, id ASC
        LIMIT 1
        FOR UPDATE SKIP LOCKED
      `;

      if (!event) {
        break;
      }

      await tx`
        UPDATE ${tx(engineSchema)}.outbox
        SET status = 'leased',
            lease_token = ${leaseToken},
            lease_expires_at = ${leaseExpiresAt},
            updated_at = ${now}
        WHERE id = ${event.id}
      `;

      event.status = "leased";
      event.lease_token = leaseToken;
      event.lease_expires_at = leaseExpiresAt;
      event.updated_at = now;
      events.push(event);
      expectedPreviousHash = event.current_hash;
    }

    return {
      leaseToken,
      events,
    };
  });
}

/**
 * Marks a leased outbox event as processed.
 *
 * @param sql - Postgres pool owning the outbox table.
 * @param engineSchema - Worker engine schema.
 * @param eventId - Outbox event id.
 * @param leaseToken - Current lease token.
 * @param now - Update timestamp.
 */
export async function markOutboxEventProcessed(
  sql: Sql,
  engineSchema: string,
  eventId: string,
  leaseToken: string,
  now: Date
): Promise<void> {
  const updated = await sql`
    UPDATE ${sql(engineSchema)}.outbox
    SET status = 'processed',
        processed_at = ${now},
        lease_token = NULL,
        lease_expires_at = NULL,
        last_error = NULL,
        updated_at = ${now}
    WHERE id = ${eventId}
      AND lease_token = ${leaseToken}
      AND status = 'leased'
    RETURNING id
  `;

  if (updated.length === 0) {
    fail({
      code: "OUTBOX_LEASE_LOST",
      title: "Outbox lease lost",
      detail: `Outbox lease for event ${eventId} was lost before it could be marked processed.`,
      category: "concurrency",
      retryable: true,
      context: { eventId },
    });
  }
}

/**
 * Extends active leases for the current contiguous outbox batch.
 *
 * Long API/WORM append latency can make later events in a leased batch expire before
 * the owning worker reaches them. Renewing the remaining batch before every dispatch
 * prevents another worker from reclaiming the same chain segment and creating a
 * false previous-hash conflict.
 *
 * @param sql - Postgres pool owning the outbox table.
 * @param engineSchema - Worker engine schema.
 * @param eventIds - Remaining leased event ids in the current batch.
 * @param currentEventId - Event that is about to be dispatched.
 * @param leaseToken - Current lease token.
 * @param leaseExpiresAt - New lease expiry timestamp.
 * @param now - Update timestamp.
 */
export async function extendOutboxLeases(
  sql: Sql,
  engineSchema: string,
  eventIds: readonly string[],
  currentEventId: string,
  leaseToken: string,
  leaseExpiresAt: Date,
  now: Date
): Promise<void> {
  if (eventIds.length === 0) {
    return;
  }

  const rows = await sql<{ id: string }[]>`
    UPDATE ${sql(engineSchema)}.outbox
    SET lease_expires_at = ${leaseExpiresAt},
        updated_at = ${now}
    WHERE id = ANY(${eventIds})
      AND lease_token = ${leaseToken}
      AND status = 'leased'
    RETURNING id
  `;

  if (!rows.some((row) => row.id === currentEventId)) {
    fail({
      code: "OUTBOX_LEASE_LOST",
      title: "Outbox lease lost",
      detail: `Outbox lease for event ${currentEventId} was lost before dispatch.`,
      category: "concurrency",
      retryable: true,
      context: { eventId: currentEventId },
    });
  }
}

/**
 * Marks a leased outbox event as failed or dead-lettered.
 *
 * @param sql - Postgres pool owning the outbox table.
 * @param engineSchema - Worker engine schema.
 * @param event - Leased outbox event.
 * @param leaseToken - Current lease token.
 * @param now - Update timestamp.
 * @param maxAttempts - Retry ceiling before dead-lettering.
 * @param baseBackoffMs - Initial exponential backoff.
 * @param error - Original delivery error.
 * @returns Resulting queue state.
 */
export async function markOutboxEventFailed(
  sql: Sql,
  engineSchema: string,
  event: OutboxEvent,
  leaseToken: string,
  now: Date,
  maxAttempts: number,
  baseBackoffMs: number,
  error: unknown
): Promise<"pending" | "dead_letter"> {
  const nextAttemptCount = event.attempt_count + 1;
  const deadLetter = nextAttemptCount >= maxAttempts;
  const nextAttemptAt = new Date(
    now.getTime() + calculateRetryDelayMs(nextAttemptCount, baseBackoffMs)
  );
  const errorMessage = error instanceof Error ? error.message : String(error);

  const updated = await sql`
    UPDATE ${sql(engineSchema)}.outbox
    SET status = ${deadLetter ? "dead_letter" : "pending"},
        attempt_count = ${nextAttemptCount},
        lease_token = NULL,
        lease_expires_at = NULL,
        next_attempt_at = ${deadLetter ? now : nextAttemptAt},
        last_error = ${errorMessage.slice(0, 1024)},
        updated_at = ${now}
    WHERE id = ${event.id}
      AND lease_token = ${leaseToken}
      AND status = 'leased'
    RETURNING id
  `;

  if (updated.length === 0) {
    fail({
      code: "OUTBOX_LEASE_LOST",
      title: "Outbox lease lost",
      detail: `Outbox lease for event ${event.id} was lost before it could be retried.`,
      category: "concurrency",
      retryable: true,
      context: { eventId: event.id },
    });
  }

  return deadLetter ? "dead_letter" : "pending";
}

/**
 * Releases a leased outbox event back to pending state after a fatal delivery failure.
 *
 * @param sql - Postgres pool owning the outbox table.
 * @param engineSchema - Worker engine schema.
 * @param eventId - Outbox event id.
 * @param leaseToken - Current lease token.
 * @param now - Update timestamp.
 * @param error - Fatal delivery error.
 */
export async function releaseOutboxLease(
  sql: Sql,
  engineSchema: string,
  eventId: string,
  leaseToken: string,
  now: Date,
  error: unknown
): Promise<void> {
  const normalized = asWorkerError(error);

  const updated = await sql`
    UPDATE ${sql(engineSchema)}.outbox
    SET status = 'pending',
        lease_token = NULL,
        lease_expires_at = NULL,
        next_attempt_at = ${now},
        last_error = ${normalized.detail.slice(0, 1024)},
        updated_at = ${now}
    WHERE id = ${eventId}
      AND lease_token = ${leaseToken}
      AND status = 'leased'
    RETURNING id
  `;

  if (updated.length === 0) {
    fail({
      code: "OUTBOX_LEASE_LOST",
      title: "Outbox lease lost",
      detail: `Outbox lease for event ${eventId} was lost before it could be released.`,
      category: "concurrency",
      retryable: true,
      context: { eventId },
    });
  }
}
