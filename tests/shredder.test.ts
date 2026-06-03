import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { dispatchPreErasureNotice, shredUser, vaultUser } from "@modules/engine";
import {
  TEST_SECRETS,
  createTestSql,
  dropSchemas,
  insertUser,
  prepareWorkerSchemas,
  uniqueSchema,
} from "./helpers";
import type { Sql } from "@/types";

describe("Crypto-Shredder Engine", () => {
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
    const appSchema = uniqueSchema("shred_app");
    const engineSchema = uniqueSchema("shred_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await prepareWorkerSchemas(sql, appSchema, engineSchema, { withDependencies: true });
    return { appSchema, engineSchema };
  }

  async function seedUser(appSchema: string, engineSchema: string) {
    const userId = await insertUser(sql, appSchema, "shred.me@example.com", "Shred Me");
    await vaultUser(sql, userId, TEST_SECRETS, {
      appSchema,
      engineSchema,
      now: new Date("2020-01-01T00:00:00.000Z"),
      defaultRetentionYears: 1,
      noticeWindowHours: 48,
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
          join: `${appSchema}.users.id = ${appSchema}.orders.user_id`,
          pii_columns: [],
        },
      ],
    });
    return userId;
  }

  async function sendNotice(appSchema: string, engineSchema: string, userId: number) {
    await dispatchPreErasureNotice(
      sql,
      userId,
      TEST_SECRETS,
      {
        sendEmail: vi.fn().mockResolvedValue(undefined),
      },
      {
        appSchema,
        engineSchema,
        now: new Date("2020-12-30T00:00:00.000Z"),
      }
    );
  }

  it("shreds the key after retention expiry and replaces the vault payload with a destroyed sentinel", async () => {
    const { appSchema, engineSchema } = await prepare();
    const userId = await seedUser(appSchema, engineSchema);
    await sendNotice(appSchema, engineSchema, userId);

    const result = await shredUser(sql, userId, {
      appSchema,
      engineSchema,
      now: new Date("2021-01-02T00:00:00.000Z"),
    });

    expect(result.action).toBe("shredded");

    const keysAfter = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.user_keys
      WHERE user_uuid_hash = ${result.userHash}
    `;
    const [vaultAfter] = await sql`
      SELECT encrypted_pii, shredded_at
      FROM ${sql(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = 'users'
        AND root_id = ${userId.toString()}
    `;
    const outboxRows = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`shred:${appSchema}:users:${userId}`}
    `;

    expect(keysAfter).toHaveLength(0);
    expect(vaultAfter?.encrypted_pii).toEqual({ v: 1, destroyed: true });
    expect(vaultAfter?.shredded_at).toBeDefined();
    expect(outboxRows).toHaveLength(1);
    expect(outboxRows[0]?.event_type).toBe("SHRED_SUCCESS");
  });

  it("refuses to shred before the retention expiry", async () => {
    const { appSchema, engineSchema } = await prepare();
    const userId = await seedUser(appSchema, engineSchema);
    await sendNotice(appSchema, engineSchema, userId);

    await expect(
      shredUser(sql, userId, {
        appSchema,
        engineSchema,
        now: new Date("2020-12-31T00:00:00.000Z"),
      })
    ).rejects.toThrow(/before retention expiry/i);
  });

  it("refuses to shred if the pre-erasure notice has not been sent", async () => {
    const { appSchema, engineSchema } = await prepare();
    const userId = await seedUser(appSchema, engineSchema);

    await expect(
      shredUser(sql, userId, {
        appSchema,
        engineSchema,
        now: new Date("2021-01-02T00:00:00.000Z"),
      })
    ).rejects.toThrow(/notice has been sent/i);
  });

  it("is idempotent when the same shred request is replayed", async () => {
    const { appSchema, engineSchema } = await prepare();
    const userId = await seedUser(appSchema, engineSchema);
    await sendNotice(appSchema, engineSchema, userId);

    const first = await shredUser(sql, userId, {
      appSchema,
      engineSchema,
      now: new Date("2021-01-02T00:00:00.000Z"),
    });
    const second = await shredUser(sql, userId, {
      appSchema,
      engineSchema,
      now: new Date("2021-01-03T00:00:00.000Z"),
    });

    expect(first.action).toBe("shredded");
    expect(second.action).toBe("already_shredded");
    expect(second.userHash).toBe(first.userHash);
  });
});
