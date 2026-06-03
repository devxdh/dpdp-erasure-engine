import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  TEST_SECRETS,
  createTestSql,
  dropSchemas,
  insertUser,
  prepareWorkerSchemas,
  uniqueSchema,
} from "./helpers";
import type { Sql } from "@/types";
import { createUserHash, vaultUser } from "@modules/engine";
import { decryptGCM, unwrapKey } from "@modules/crypto";

describe("Vault Engine (Atomic State Machine)", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function prepare(options: { withDependencies?: boolean } = {}) {
    const appSchema = uniqueSchema("vault_app");
    const engineSchema = uniqueSchema("vault_engine");
    schemasToDrop.push(appSchema, engineSchema);

    await prepareWorkerSchemas(sql, appSchema, engineSchema, options);
    return { appSchema, engineSchema };
  }

  function buildVaultOptions(
    appSchema: string,
    engineSchema: string,
    now?: Date,
    withCompiledDependencies = true
  ) {
    return {
      appSchema,
      engineSchema,
      now,
      rootTable: "users",
      rootIdColumn: "id",
      rootPiiColumns: {
        email: "HMAC" as const,
        full_name: "STATIC_MASK" as const,
      },
      satelliteTargets: [],
      compiledTargets: withCompiledDependencies
        ? [
          { table: `${appSchema}.users`, pii_columns: ["email", "full_name"] },
          {
            table: `${appSchema}.orders`,
            parent: `${appSchema}.users`,
            join: `${appSchema}.users.id = ${appSchema}.orders.user_id`,
            pii_columns: [],
          },
          {
            table: `${appSchema}.profiles`,
            parent: `${appSchema}.users`,
            join: `${appSchema}.users.id = ${appSchema}.profiles.user_id`,
            pii_columns: [],
          },
        ]
        : [],
    };
  }

  it("vaults, pseudonymizes, and keeps the original PII decryptable with the KEK", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: true });
    const now = new Date("2026-01-10T00:00:00.000Z");
    const userId = await insertUser(sql, appSchema, "john.doe@example.com", "John Doe");

    const result = await vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema, now));
    expect(result.action).toBe("vaulted");
    expect(result.userHash).toHaveLength(64);
    expect(result.pseudonym).toMatch(/@dpdp\.invalid$/);
    expect(result.dependencyCount).toBe(2);

    const [publicUser] = await sql<{ email: string; full_name: string }[]>`
      SELECT email, full_name
      FROM ${sql(appSchema)}.users
      WHERE id = ${userId}
    `;

    expect(publicUser?.email).toMatch(/^[0-9a-f]{64}$/);
    expect(publicUser?.full_name).toBe("[REDACTED]");

    const [vaultRow] = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = 'users'
        AND root_id = ${userId.toString()}
    `;
    const [keyRow] = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.user_keys
      WHERE user_uuid_hash = ${result.userHash}
    `;
    const [outboxRow] = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`vault:${appSchema}:users:id:${userId}`}
    `;

    expect(vaultRow?.user_uuid_hash).toBe(result.userHash);
    expect(vaultRow?.dependency_count).toBe(2);
    expect(vaultRow?.pseudonym).toBe(result.pseudonym);
    expect(vaultRow?.notification_due_at).toBeDefined();
    expect(keyRow?.encrypted_dek).toBeDefined();
    expect(outboxRow?.event_type).toBe("USER_VAULTED");
    expect(outboxRow?.status).toBe("pending");

    expect(keyRow).toBeDefined();
    expect(vaultRow).toBeDefined();
    const dek = await unwrapKey(new Uint8Array(keyRow!.encrypted_dek), TEST_SECRETS.kek);
    const encryptedPayload = new Uint8Array(Buffer.from((vaultRow!.encrypted_pii as { data: string }).data, "base64"));
    const decryptedPii = await decryptGCM(encryptedPayload, dek);

    expect(JSON.parse(decryptedPii)).toEqual({
      email: "john.doe@example.com",
      full_name: "John Doe",
    });
  });

  it("hard deletes the user when the root table has no dependent tables", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: false });
    const userId = await insertUser(sql, appSchema, "delete.me@example.com", "Delete Me");

    const result = await vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema, undefined, false));
    expect(result.action).toBe("hard_deleted");
    expect(result.dependencyCount).toBe(0);

    const remainingUsers = await sql`SELECT * FROM ${sql(appSchema)}.users WHERE id = ${userId}`;
    const vaultRows = await sql`SELECT * FROM ${sql(engineSchema)}.pii_vault WHERE root_id = ${userId.toString()}`;
    const [outboxRow] = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`hard-delete:${appSchema}:users:id:${userId}`}
    `;

    expect(remainingUsers).toHaveLength(0);
    expect(vaultRows).toHaveLength(0);
    expect(outboxRow?.event_type).toBe("USER_HARD_DELETED");
  });

  it("supports dry-run mode without mutating any state", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: true });
    const userId = await insertUser(sql, appSchema, "preview@example.com", "Preview User");

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      ...buildVaultOptions(appSchema, engineSchema, new Date("2026-01-10T00:00:00.000Z")),
      dryRun: true,
    });

    expect(result.action).toBe("dry_run");
    expect(result.plan?.summary).toContain(`root row ${userId}`);

    const [publicUser] = await sql`SELECT email, full_name FROM ${sql(appSchema)}.users WHERE id = ${userId}`;
    const vaultRows = await sql`SELECT * FROM ${sql(engineSchema)}.pii_vault WHERE root_id = ${userId.toString()}`;
    const outboxRows = await sql`SELECT * FROM ${sql(engineSchema)}.outbox`;

    expect(publicUser?.email).toBe("preview@example.com");
    expect(vaultRows).toHaveLength(0);
    expect(outboxRows).toHaveLength(0);
  });

  it("supports shadow mode by validating the full pipeline and rolling back all writes", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: true });
    const userId = await insertUser(sql, appSchema, "shadow@example.com", "Shadow User");

    const result = await vaultUser(sql, userId, TEST_SECRETS, {
      ...buildVaultOptions(appSchema, engineSchema, new Date("2026-01-10T00:00:00.000Z")),
      shadowMode: true,
    });

    expect(result.action).toBe("vaulted");
    expect(result.dryRun).toBe(false);

    const [publicUser] = await sql<{ email: string; full_name: string }[]>`
      SELECT email, full_name
      FROM ${sql(appSchema)}.users
      WHERE id = ${userId}
    `;
    const vaultRows = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = 'users'
        AND root_id = ${userId.toString()}
    `;
    const outboxRows = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`vault:${appSchema}:users:id:${userId}`}
    `;

    expect(publicUser?.email).toBe("shadow@example.com");
    expect(publicUser?.full_name).toBe("Shadow User");
    expect(vaultRows).toHaveLength(0);
    expect(outboxRows).toHaveLength(0);
  });

  it("rolls back cleanly when the vault insert collides with an existing hash", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: true });
    const userId = await insertUser(sql, appSchema, "jane.smith@example.com", "Jane Smith");
    const conflictingHash = await createUserHash(userId, appSchema, "users", TEST_SECRETS.hmacKey);

    await sql`
      INSERT INTO ${sql(engineSchema)}.pii_vault (
        user_uuid_hash,
        root_schema,
        root_table,
        root_id,
        pseudonym,
        encrypted_pii,
        salt,
        dependency_count,
        retention_expiry,
        notification_due_at,
        created_at,
        updated_at
      )
      VALUES (
        ${conflictingHash},
        ${appSchema},
        'users',
        '999999',
        'conflict@dpdp.invalid',
        ${sql.json({ v: 1, data: "AA==" })},
        'conflictsalt',
        1,
        NOW(),
        NOW(),
        NOW(),
        NOW()
      )
    `;

    await expect(vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema))).rejects.toThrow();

    const [publicUser] = await sql`SELECT email, full_name FROM ${sql(appSchema)}.users WHERE id = ${userId}`;
    const keyRows = await sql`SELECT * FROM ${sql(engineSchema)}.user_keys WHERE user_uuid_hash = ${conflictingHash}`;
    const outboxRows = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`vault:${appSchema}:users:id:${userId}`}
    `;

    expect(publicUser?.email).toBe("jane.smith@example.com");
    expect(publicUser?.full_name).toBe("Jane Smith");
    expect(keyRows).toHaveLength(0);
    expect(outboxRows).toHaveLength(0);
  });

  it("returns an idempotent already_vaulted result when the same user is processed twice", async () => {
    const { appSchema, engineSchema } = await prepare({ withDependencies: true });
    const userId = await insertUser(sql, appSchema, "repeat@example.com", "Repeat User");

    const first = await vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema));
    const second = await vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema));

    expect(first.action).toBe("vaulted");
    expect(second.action).toBe("already_vaulted");
    expect(second.userHash).toBe(first.userHash);

    const outboxRows = await sql`
      SELECT *
      FROM ${sql(engineSchema)}.outbox
      WHERE idempotency_key = ${`vault:${appSchema}:users:id:${userId}`}
    `;
    expect(outboxRows).toHaveLength(1);
  });
});
