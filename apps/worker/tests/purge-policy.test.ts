import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { selectPurgeCandidates } from "@modules/engine/vault/purge";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import type { Sql } from "@/types";

describe("DPO-attested purge policy", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function createUsers(schema: string): Promise<void> {
    schemasToDrop.push(schema);
    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;
    await sql`
      CREATE TABLE ${sql(schema)}.users (
        id TEXT PRIMARY KEY,
        purge_eligible BOOLEAN NOT NULL DEFAULT FALSE,
        account_state TEXT NOT NULL DEFAULT 'active',
        disabled_at TIMESTAMPTZ
      )
    `;
    await sql`
      INSERT INTO ${sql(schema)}.users (id, purge_eligible, account_state, disabled_at)
      VALUES
        ('usr_001', true, 'deleted', '2026-01-01T00:00:00.000Z'),
        ('usr_002', false, 'active', NULL),
        ('usr_003', true, 'deleted', '2026-01-02T00:00:00.000Z'),
        ('usr_004', false, 'closed', '2026-04-01T00:00:00.000Z')
    `;
  }

  it("selects purge candidates only through the configured boolean selector", async () => {
    const schema = uniqueSchema("purge_bool");
    await createUsers(schema);

    await expect(
      selectPurgeCandidates(sql, {
        appSchema: schema,
        rootTable: "users",
        rootIdColumn: "id",
        purgePolicy: {
          enabled: true,
          selector: {
            kind: "boolean_column",
            column: "purge_eligible",
            value: true,
          },
          max_batch_size: 100,
          actor_opaque_id: "system:purge",
          legal_framework: "DPDP_2023",
        },
      })
    ).resolves.toEqual(["usr_001", "usr_003"]);
  });

  it("supports enum and timestamp selectors without scanning unbounded rows in application code", async () => {
    const schema = uniqueSchema("purge_selectors");
    await createUsers(schema);

    const enumCandidates = await selectPurgeCandidates(sql, {
      appSchema: schema,
      rootTable: "users",
      rootIdColumn: "id",
      purgePolicy: {
        enabled: true,
        selector: {
          kind: "enum_column",
          column: "account_state",
          values: ["closed", "deleted"],
        },
        max_batch_size: 2,
        actor_opaque_id: "system:purge",
        legal_framework: "DPDP_2023",
      },
    });
    expect(enumCandidates).toEqual(["usr_001", "usr_003"]);

    const timestampCandidates = await selectPurgeCandidates(sql, {
      appSchema: schema,
      rootTable: "users",
      rootIdColumn: "id",
      purgePolicy: {
        enabled: true,
        selector: {
          kind: "timestamp_before",
          column: "disabled_at",
          before: "2026-03-01T00:00:00.000Z",
        },
        max_batch_size: 100,
        actor_opaque_id: "system:purge",
        legal_framework: "DPDP_2023",
      },
    });
    expect(timestampCandidates).toEqual(["usr_001", "usr_003"]);
  });

  it("fails closed when purge automation is disabled", async () => {
    const schema = uniqueSchema("purge_disabled");
    await createUsers(schema);

    await expect(
      selectPurgeCandidates(sql, {
        appSchema: schema,
        rootTable: "users",
        rootIdColumn: "id",
        purgePolicy: {
          enabled: false,
          max_batch_size: 100,
          actor_opaque_id: "system:purge",
          legal_framework: "DPDP_2023",
        },
      })
    ).rejects.toThrow(/without an enabled purge_policy selector/i);
  });
});
