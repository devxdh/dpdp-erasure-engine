import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { migrateApiSchema } from "@/db";
import { computeWormHash } from "@modules/control-plane";
import { ControlPlaneRepository } from "@modules/control-plane";
import { createTestSql, dropSchemas, uniqueSchema } from "../helpers";
import type { Sql } from "@/types";

describe("Audit ledger verification", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function setup() {
    const schema = uniqueSchema("api_audit_verify");
    schemasToDrop.push(schema);
    await dropSchemas(sql, schema);
    await migrateApiSchema(sql, schema);
    const repository = new ControlPlaneRepository(sql, schema, 60, 10, 1000);
    const [client] = await sql<{ id: string; organization_id: string }[]>`
      INSERT INTO ${sql(schema)}.clients (name, worker_api_key_hash)
      VALUES (${`worker-${schema}`}, ${"hash".repeat(16)})
      RETURNING id, organization_id
    `;

    return {
      schema,
      repository,
      clientId: client!.id,
      organizationId: client!.organization_id,
    };
  }

  it("recomputes a valid WORM chain and identifies the first corrupted event", async () => {
    const { schema, repository, clientId, organizationId } = await setup();
    const firstPayload = { request_id: crypto.randomUUID(), action: "vaulted" };
    const firstKey = `evt:${crypto.randomUUID()}`;
    const firstHash = await computeWormHash("GENESIS", firstPayload, firstKey);

    expect(await repository.insertAuditLedgerEvent({
      organizationId,
      clientId,
      idempotencyKey: firstKey,
      eventType: "USER_VAULTED",
      payload: firstPayload,
      previousHash: "GENESIS",
      currentHash: firstHash,
      now: new Date("2026-05-01T00:00:00.000Z"),
    })).toBe(true);

    await repository.insertWorkerConfigHeartbeat({
      organizationId,
      clientId,
      configHash: "ab".repeat(32),
      configVersion: "v1",
      dpoIdentifier: "dpo@example.com",
      now: new Date("2026-05-01T00:00:01.000Z"),
    });

    const secondPayload = { request_id: crypto.randomUUID(), action: "notice_sent" };
    const secondKey = `evt:${crypto.randomUUID()}`;
    const secondHash = await computeWormHash(firstHash, secondPayload, secondKey);
    expect(await repository.insertAuditLedgerEvent({
      organizationId,
      clientId,
      idempotencyKey: secondKey,
      eventType: "NOTIFICATION_SENT",
      payload: secondPayload,
      previousHash: firstHash,
      currentHash: secondHash,
      now: new Date("2026-05-01T00:00:02.000Z"),
    })).toBe(true);

    await expect(repository.verifyAuditLedgerChain({ organizationId })).resolves.toEqual(expect.objectContaining({
      valid: true,
      checked: 3,
      head: secondHash,
      firstInvalid: null,
    }));

    await sql`
      UPDATE ${sql(schema)}.audit_ledger
      SET current_hash = ${"ff".repeat(32)}
      WHERE worker_idempotency_key = ${secondKey}
    `;

    const corrupted = await repository.verifyAuditLedgerChain({ organizationId });
    expect(corrupted.valid).toBe(false);
    expect(corrupted.firstInvalid).toEqual(
      expect.objectContaining({
        reason: "current_hash_mismatch",
        actual_current_hash: "ff".repeat(32),
      })
    );
  });

  it("verifies tenant-wide audit ledgers as independent per-client chains", async () => {
    const { schema, repository, clientId, organizationId } = await setup();
    const [secondClient] = await sql<{ id: string }[]>`
      INSERT INTO ${sql(schema)}.clients (organization_id, name, worker_api_key_hash)
      VALUES (${organizationId}, ${`worker-secondary-${schema}`}, ${"hash".repeat(16)})
      RETURNING id
    `;
    const secondClientId = secondClient!.id;

    const firstPayload = { request_id: crypto.randomUUID(), action: "vaulted-primary" };
    const firstKey = `evt:${crypto.randomUUID()}`;
    const firstHash = await computeWormHash("GENESIS", firstPayload, firstKey);
    await repository.insertAuditLedgerEvent({
      organizationId,
      clientId,
      idempotencyKey: firstKey,
      eventType: "USER_VAULTED",
      payload: firstPayload,
      previousHash: "GENESIS",
      currentHash: firstHash,
      now: new Date("2026-05-01T00:00:00.000Z"),
    });

    const secondPayload = { request_id: crypto.randomUUID(), action: "vaulted-secondary" };
    const secondKey = `evt:${crypto.randomUUID()}`;
    const secondHash = await computeWormHash("GENESIS", secondPayload, secondKey);
    await repository.insertAuditLedgerEvent({
      organizationId,
      clientId: secondClientId,
      idempotencyKey: secondKey,
      eventType: "USER_VAULTED",
      payload: secondPayload,
      previousHash: "GENESIS",
      currentHash: secondHash,
      now: new Date("2026-05-01T00:00:01.000Z"),
    });

    const result = await repository.verifyAuditLedgerChain({ organizationId });

    expect(result.valid).toBe(true);
    expect(result.checked).toBe(2);
    expect(result.head).toBe("MULTI_CLIENT");
    expect(result.heads).toEqual({
      [clientId]: firstHash,
      [secondClientId]: secondHash,
    });
  });
});
