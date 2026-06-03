import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { vaultUser } from "@modules/engine";
import {
  TEST_SECRETS,
  createTestSql,
  dropSchemas,
  insertUser,
  prepareWorkerSchemas,
  uniqueSchema,
} from "./helpers";
import type { Sql } from "@/types";

describe("Vault Engine compiled DAG execution", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  it("mutates a deep compiled target through precompiled joins instead of same-column satellite lookup", async () => {
    const appSchema = uniqueSchema("vault_compiled_app");
    const engineSchema = uniqueSchema("vault_compiled_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await prepareWorkerSchemas(sql, appSchema, engineSchema, {
      withDependencies: true,
      withDeepDependencies: true,
    });

    const userId = await insertUser(sql, appSchema, "compiled@example.com", "Compiled User");
    const [order] = await sql<{ id: number }[]>`
      INSERT INTO ${sql(appSchema)}.orders (user_id, amount)
      VALUES (${userId}, 500)
      RETURNING id
    `;
    await sql`
      INSERT INTO ${sql(appSchema)}.shipping_addresses (order_id, street, city)
      VALUES (${order!.id}, '221B Baker Street', 'Mumbai')
    `;

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      now: new Date("2026-01-10T00:00:00.000Z"),
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC",
        full_name: "STATIC_MASK",
      },
      satelliteTargets: [],
      compiledTargets: [
        { table: `${appSchema}.users`, pii_columns: ["email", "full_name"] },
        {
          table: `${appSchema}.orders`,
          parent: `${appSchema}.users`,
          parent_columns: ["id"],
          child_columns: ["user_id"],
          pii_columns: [],
        },
        {
          table: `${appSchema}.shipping_addresses`,
          parent: `${appSchema}.orders`,
          parent_columns: ["id"],
          child_columns: ["order_id"],
          pii_columns: ["street", "city"],
          action: "redact",
          mutation_rules: {
            street: "STATIC_MASK",
            city: "STATIC_MASK",
          },
        },
      ],
    });

    expect(result.action).toBe("vaulted");
    expect(result.dependencyCount).toBe(2);

    const [address] = await sql<{ street: string | null; city: string | null }[]>`
      SELECT street, city
      FROM ${sql(appSchema)}.shipping_addresses
      WHERE order_id = ${order!.id}
    `;
    expect(address).toEqual({
      street: "[REDACTED]",
      city: "[REDACTED]",
    });

    const [outbox] = await sql<{ payload: { satellite_mutations: Array<{ table: string; affectedRows: number }> } }[]>`
      SELECT payload
      FROM ${sql(engineSchema)}.outbox
      WHERE event_type = 'USER_VAULTED'
    `;
    expect(outbox?.payload.satellite_mutations).toContainEqual({
      table: `${appSchema}.shipping_addresses`,
      action: "redact",
      affectedRows: 1,
    });
  });

  it("uses all configured primary key columns when mutating compiled targets", async () => {
    const appSchema = uniqueSchema("vault_compiled_pk_app");
    const engineSchema = uniqueSchema("vault_compiled_pk_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await prepareWorkerSchemas(sql, appSchema, engineSchema);

    await sql`
      CREATE TABLE ${sql(appSchema)}.devices (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ${sql(appSchema)}.users(id)
      )
    `;
    await sql`
      CREATE TABLE ${sql(appSchema)}.device_events (
        device_id INTEGER NOT NULL REFERENCES ${sql(appSchema)}.devices(id),
        event_seq INTEGER NOT NULL,
        payload TEXT NOT NULL,
        PRIMARY KEY (device_id, event_seq)
      )
    `;

    const userId = await insertUser(sql, appSchema, "compiled-pk@example.com", "Compiled PK User");
    const [device] = await sql<{ id: number }[]>`
      INSERT INTO ${sql(appSchema)}.devices (user_id)
      VALUES (${userId})
      RETURNING id
    `;
    await sql`
      INSERT INTO ${sql(appSchema)}.device_events (device_id, event_seq, payload)
      VALUES
        (${device!.id}, 1, 'first pii payload'),
        (${device!.id}, 2, 'second pii payload')
    `;

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      now: new Date("2026-01-10T00:00:00.000Z"),
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC",
        full_name: "STATIC_MASK",
      },
      satelliteTargets: [],
      compiledTargets: [
        { table: `${appSchema}.users`, pii_columns: ["email", "full_name"] },
        {
          table: `${appSchema}.devices`,
          parent: `${appSchema}.users`,
          parent_columns: ["id"],
          child_columns: ["user_id"],
          pii_columns: [],
        },
        {
          table: `${appSchema}.device_events`,
          parent: `${appSchema}.devices`,
          parent_columns: ["id"],
          child_columns: ["device_id"],
          primary_key_columns: ["device_id", "event_seq"],
          pii_columns: ["payload"],
          action: "redact",
          mutation_rules: {
            payload: "STATIC_MASK",
          },
        },
      ],
    });

    expect(result.action).toBe("vaulted");
    const rows = await sql<{ event_seq: number; payload: string }[]>`
      SELECT event_seq, payload
      FROM ${sql(appSchema)}.device_events
      WHERE device_id = ${device!.id}
      ORDER BY event_seq ASC
    `;
    expect(rows).toEqual([
      { event_seq: 1, payload: "[REDACTED]" },
      { event_seq: 2, payload: "[REDACTED]" },
    ]);
  });

  it("treats compiled DAG targets as authoritative when legacy satellite targets are also present", async () => {
    const appSchema = uniqueSchema("vault_compiled_authority_app");
    const engineSchema = uniqueSchema("vault_compiled_authority_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await prepareWorkerSchemas(sql, appSchema, engineSchema, { withDependencies: true });

    const userId = await insertUser(sql, appSchema, "authority@example.com", "Authority User");
    await sql`
      INSERT INTO ${sql(appSchema)}.orders (user_id, amount)
      VALUES (${userId}, 700)
    `;

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      now: new Date("2026-01-10T00:00:00.000Z"),
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC",
        full_name: "STATIC_MASK",
      },
      satelliteTargets: [
        {
          table: "legacy_target_that_must_not_run",
          lookup_column: "user_id",
          action: "redact",
          masking_rules: {
            payload: "STATIC_MASK",
          },
        },
      ],
      compiledTargets: [
        { table: `${appSchema}.users`, pii_columns: ["email", "full_name"] },
        {
          table: `${appSchema}.orders`,
          parent: `${appSchema}.users`,
          parent_columns: ["id"],
          child_columns: ["user_id"],
          pii_columns: [],
        },
      ],
    });

    expect(result.action).toBe("vaulted");
    expect(result.dependencyCount).toBe(1);

    const [outbox] = await sql<{ payload: { execution_plan_source: string; satellite_mutations: unknown[] } }[]>`
      SELECT payload
      FROM ${sql(engineSchema)}.outbox
      WHERE event_type = 'USER_VAULTED'
    `;
    expect(outbox?.payload.execution_plan_source).toBe("compiled");
    expect(outbox?.payload.satellite_mutations).toEqual([]);
  });
});
