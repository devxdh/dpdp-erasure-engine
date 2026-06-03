import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sql } from "@/types";
import { workerError } from "@/errors";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import { runMigrations } from "@modules/db";
import { processOutbox, type OutboxEvent } from "@modules/network";
import { enqueueOutboxEvent } from "@modules/engine";
import { calculateRetryDelayMs } from "@modules/network/outbox/shared";

describe("Network Outbox Relay", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function prepare() {
    const engineSchema = uniqueSchema("outbox_engine");
    schemasToDrop.push(engineSchema);
    await dropSchemas(sql, engineSchema);
    await runMigrations(sql, engineSchema);
    return { engineSchema };
  }

  function toHex(buffer: ArrayBuffer): string {
    return Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");
  }

  async function seedEvent(
    engineSchema: string,
    idempotencyKey: string,
    userHash: string,
    eventType: string,
    nextAttemptAt: Date = new Date(),
    createdAt: Date = new Date(),
    previousHash: string = "GENESIS"
  ) {
    await sql`
      INSERT INTO ${sql(engineSchema)}.outbox (
        idempotency_key,
        user_uuid_hash,
        event_type,
        payload,
        previous_hash,
        current_hash,
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
        '{}'::jsonb,
        ${previousHash},
        ${`${idempotencyKey}-hash`},
        'pending',
        0,
        ${nextAttemptAt},
        ${createdAt},
        ${createdAt}
      )
    `;
  }

  it("processes due events and marks them as processed", async () => {
    const { engineSchema } = await prepare();
    const baseTime = new Date("2026-04-15T00:00:00.000Z");
    const laterTime = new Date("2026-04-15T00:00:01.000Z");
    await seedEvent(engineSchema, "event-1", "user1", "TEST_EVENT", baseTime, baseTime);
    await seedEvent(engineSchema, "event-2", "user2", "TEST_EVENT", baseTime, laterTime, "event-1-hash");

    const result = await processOutbox(sql, async () => true, { engineSchema, batchSize: 10 });
    expect(result).toEqual({
      claimed: 2,
      processed: 2,
      failed: 0,
      deadLettered: 0,
    });

    const rows = await sql`SELECT status, processed_at FROM ${sql(engineSchema)}.outbox ORDER BY idempotency_key ASC`;
    expect(rows.every((row) => row.status === "processed")).toBe(true);
    expect(rows.every((row) => row.processed_at !== null)).toBe(true);
  });

  it("preserves WORM order instead of prioritizing terminal events ahead of predecessors", async () => {
    const { engineSchema } = await prepare();
    const baseTime = new Date("2026-04-15T00:00:00.000Z");
    const laterTime = new Date("2026-04-15T00:00:01.000Z");

    await seedEvent(
      engineSchema,
      "vault-old",
      "user-old",
      "USER_VAULTED",
      baseTime,
      baseTime
    );
    await seedEvent(
      engineSchema,
      "shred-new",
      "user-new",
      "SHRED_SUCCESS",
      baseTime,
      laterTime,
      "vault-old-hash"
    );

    const delivered: string[] = [];
    const result = await processOutbox(
      sql,
      async (event) => {
        delivered.push(event.idempotency_key);
        return true;
      },
      { engineSchema, batchSize: 2, now: laterTime }
    );

    expect(result.processed).toBe(2);
    expect(delivered).toEqual(["vault-old", "shred-new"]);
  });

  it("chains outbox events with tamper-evident hashes", async () => {
    const { engineSchema } = await prepare();
    const now = new Date("2026-04-15T00:00:00.000Z");
    const next = new Date("2026-04-15T00:00:01.000Z");

    await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-1",
        "USER_VAULTED",
        { rootId: "1", state: "vaulted" },
        "vault:tenant:users:1",
        now
      )
    );

    await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-2",
        "NOTIFICATION_SENT",
        { rootId: "2", state: "notified" },
        "notice:tenant:users:2",
        next
      )
    );

    await processOutbox(sql, async () => true, { engineSchema, batchSize: 10, now: next });

    const expectedFirstBuffer = await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        `GENESIS${JSON.stringify({ rootId: "1", state: "vaulted" })}vault:tenant:users:1`
      )
    );
    const expectedFirstHash = toHex(expectedFirstBuffer);
    const expectedSecondBuffer = await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(
        `${expectedFirstHash}${JSON.stringify({ rootId: "2", state: "notified" })}notice:tenant:users:2`
      )
    );
    const expectedSecondHash = toHex(expectedSecondBuffer);

    const rows = await sql`
      SELECT idempotency_key, previous_hash, current_hash, chain_status
      FROM ${sql(engineSchema)}.outbox
      ORDER BY created_at ASC, id ASC
    `;

    expect(rows).toEqual([
      {
        idempotency_key: "vault:tenant:users:1",
        previous_hash: "GENESIS",
        current_hash: expectedFirstHash,
        chain_status: "finalized",
      },
      {
        idempotency_key: "notice:tenant:users:2",
        previous_hash: expectedFirstHash,
        current_hash: expectedSecondHash,
        chain_status: "finalized",
      },
    ]);
  });

  it("returns the existing finalized row on idempotent replay without mutating the chain", async () => {
    const { engineSchema } = await prepare();
    const now = new Date("2026-04-15T00:00:00.000Z");

    const first = await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-1",
        "USER_VAULTED",
        { rootId: "1", state: "vaulted" },
        "vault:tenant:users:1",
        now
      )
    );

    await processOutbox(sql, async () => true, { engineSchema, batchSize: 10, now });

    const replay = await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-1",
        "USER_VAULTED",
        { rootId: "1", state: "mutated" },
        "vault:tenant:users:1",
        new Date("2026-04-15T00:00:30.000Z")
      )
    );

    expect(replay.id).toBe(first.id);
    expect(replay.previous_hash).toBe("GENESIS");
    expect(replay.chain_status).toBe("finalized");

    const rows = await sql`
      SELECT payload, previous_hash, current_hash, chain_status
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = 'vault:tenant:users:1'
    `;

    expect(rows).toHaveLength(1);
    expect(rows[0]?.payload).toEqual({ rootId: "1", state: "vaulted" });
    expect(rows[0]?.previous_hash).toBe("GENESIS");
    expect(rows[0]?.current_hash).toBe(replay.current_hash);
    expect(rows[0]?.chain_status).toBe("finalized");
  });

  it("produces identical hashes for semantically equivalent payloads with different key order", async () => {
    const { engineSchema } = await prepare();
    const now = new Date("2026-04-15T00:00:00.000Z");

    const first = await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-1",
        "USER_VAULTED",
        { b: "second", a: "first", nested: { y: 2, x: 1 } },
        "vault:tenant:users:ordered",
        now
      )
    );
    await processOutbox(sql, async () => true, { engineSchema, batchSize: 10, now });
    const replay = await sql.begin((tx) =>
      enqueueOutboxEvent(
        tx,
        engineSchema,
        "user-hash-1",
        "USER_VAULTED",
        { nested: { x: 1, y: 2 }, a: "first", b: "second" },
        "vault:tenant:users:ordered",
        new Date("2026-04-15T00:00:30.000Z")
      )
    );

    expect(replay.id).toBe(first.id);
    expect(replay.chain_status).toBe("finalized");
  });

  it("requeues failed events with backoff and error context", async () => {
    const { engineSchema } = await prepare();
    const now = new Date("2026-04-15T00:00:00.000Z");
    await seedEvent(engineSchema, "event-3", "user3", "FAIL_EVENT", now);

    const result = await processOutbox(
      sql,
      async () => {
        throw new Error("Network Error");
      },
      {
        engineSchema,
        batchSize: 10,
        now,
        baseBackoffMs: 500,
        maxAttempts: 3,
      }
    );

    expect(result).toEqual({
      claimed: 1,
      processed: 0,
      failed: 1,
      deadLettered: 0,
    });

    const [row] = await sql`
      SELECT status, attempt_count, next_attempt_at, last_error
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = 'event-3'
    `;

    expect(row?.status).toBe("pending");
    expect(row?.attempt_count).toBe(1);
    expect(row?.last_error).toContain("Network Error");
    expect(new Date(row!.next_attempt_at).getTime()).toBe(now.getTime() + calculateRetryDelayMs(1, 500));
  });

  it("moves an event to dead_letter after the maximum retry count is reached", async () => {
    const { engineSchema } = await prepare();
    await seedEvent(engineSchema, "event-4", "user4", "FAIL_EVENT");

    const result = await processOutbox(
      sql,
      async () => {
        throw new Error("Permanent Failure");
      },
      {
        engineSchema,
        batchSize: 10,
        maxAttempts: 1,
      }
    );

    expect(result).toEqual({
      claimed: 1,
      processed: 0,
      failed: 1,
      deadLettered: 1,
    });

    const [row] = await sql`
      SELECT status, attempt_count, last_error
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = 'event-4'
    `;

    expect(row?.status).toBe("dead_letter");
    expect(row?.attempt_count).toBe(1);
    expect(row?.last_error).toContain("Permanent Failure");
  });

  it("releases the lease and rethrows fatal delivery errors without burning retry attempts", async () => {
    const { engineSchema } = await prepare();
    await seedEvent(engineSchema, "event-fatal", "user-fatal", "AUTH_FAIL");

    await expect(
      processOutbox(
        sql,
        async () => {
          throw workerError({
            code: "OUTBOX_AUTH_REJECTED",
            title: "Control Plane authentication rejected outbox event",
            detail: "Brain API responded with HTTP 401.",
            category: "configuration",
            retryable: false,
            fatal: true,
          });
        },
        {
          engineSchema,
          batchSize: 10,
        }
      )
    ).rejects.toMatchObject({
      code: "OUTBOX_AUTH_REJECTED",
      fatal: true,
    });

    const [row] = await sql`
      SELECT status, attempt_count, lease_token, lease_expires_at, last_error
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = 'event-fatal'
    `;

    expect(row?.status).toBe("pending");
    expect(row?.attempt_count).toBe(0);
    expect(row?.lease_token).toBeNull();
    expect(row?.lease_expires_at).toBeNull();
    expect(row?.last_error).toContain("HTTP 401");
  });

  it("handles concurrent workers without duplicating event delivery", async () => {
    const { engineSchema } = await prepare();
    await enqueueOutboxEvent(sql, engineSchema, "user5", "CONCURRENT", {}, "event-5", new Date());
    await enqueueOutboxEvent(sql, engineSchema, "user6", "CONCURRENT", {}, "event-6", new Date());
    await enqueueOutboxEvent(sql, engineSchema, "user7", "CONCURRENT", {}, "event-7", new Date());

    const deliveredIds = new Set<string>();

    const syncFn = async (event: OutboxEvent) => {
      await new Promise((resolve) => setTimeout(resolve, 50));
      if (deliveredIds.has(event.id)) {
        throw new Error(`Duplicate delivery for ${event.id}`);
      }
      deliveredIds.add(event.id);
      return true;
    };

    let processed = 0;
    for (let round = 0; round < 10 && processed < 3; round += 1) {
      const results = await Promise.all([
        processOutbox(sql, syncFn, { engineSchema, batchSize: 1 }),
        processOutbox(sql, syncFn, { engineSchema, batchSize: 1 }),
        processOutbox(sql, syncFn, { engineSchema, batchSize: 1 }),
      ]);
      processed += results.reduce((sum, result) => sum + result.processed, 0);
    }

    expect(processed).toBe(3);
    expect(deliveredIds.size).toBe(3);

    const forkedLinks = await sql`
      SELECT previous_hash, COUNT(*)::INT AS count
      FROM ${sql(engineSchema)}.outbox
      WHERE status = 'processed'
      GROUP BY previous_hash
      HAVING COUNT(*) > 1
    `;
    expect(forkedLinks).toHaveLength(0);
  });

  it("reclaims an event whose lease has already expired", async () => {
    const { engineSchema } = await prepare();

    await sql`
      INSERT INTO ${sql(engineSchema)}.outbox (
        idempotency_key,
        user_uuid_hash,
        event_type,
        payload,
        previous_hash,
        current_hash,
        status,
        attempt_count,
        lease_token,
        lease_expires_at,
        next_attempt_at,
        created_at,
        updated_at
      )
      VALUES (
        'event-8',
        'user8',
        'LEASED_EVENT',
        '{}'::jsonb,
        'GENESIS',
        'event-8-hash',
        'leased',
        2,
        gen_random_uuid(),
        NOW() - INTERVAL '10 minutes',
        NOW() - INTERVAL '10 minutes',
        NOW(),
        NOW()
      )
    `;

    const result = await processOutbox(sql, async () => true, { engineSchema, batchSize: 10 });
    expect(result.processed).toBe(1);

    const [row] = await sql`
      SELECT status, processed_at
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = 'event-8'
    `;

    expect(row?.status).toBe("processed");
    expect(row?.processed_at).toBeDefined();
  });
});
