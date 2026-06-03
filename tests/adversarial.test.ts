import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";

const getDependencyGraphMock = vi.hoisted(() => vi.fn<() => Promise<unknown[]>>(() => Promise.resolve([])));
vi.mock("@modules/db/graph", () => ({
  getDependencyGraph: getDependencyGraphMock,
}));

import {
  TEST_SECRETS,
  createTestSql,
  dropSchemas,
  insertUser,
  uniqueSchema,
} from "./helpers";
import { readWorkerConfig } from "@modules/config";
import { runMigrations } from "@modules/db";
import { vaultUser } from "@modules/engine";
import type { Sql } from "@/types";
import { decryptGCM, unwrapKey } from "@modules/crypto";
import { processOutbox } from "@modules/network";
import { calculateRetryDelayMs } from "@modules/network/outbox/shared";


const masterKeyHex = "42".repeat(32);
const hmacKeyBase64 = Buffer.from(new Uint8Array(32).fill(0x24)).toString("base64");

async function writeTempYaml(contents: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "adversarial-config-"));
  const path = join(directory, "compliance.worker.yml");
  await writeFile(path, contents, "utf8");
  return path;
}

async function deleteTempYaml(path: string) {
  await rm(path, { force: true });
  await rm(dirname(path), { recursive: true, force: true });
}

function buildVaultOptions(appSchema: string, engineSchema: string, now?: Date) {
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
    compiledTargets: [
      { table: `${appSchema}.users`, pii_columns: ["email", "full_name"] },
      {
        table: `${appSchema}.orders`,
        parent: `${appSchema}.users`,
        join: `${appSchema}.users.id = ${appSchema}.orders.user_id`,
        pii_columns: [],
      },
    ],
  };
}

describe("Adversarial Worker Suite", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];
  const configPathsToDelete: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    for (const path of configPathsToDelete.splice(0, configPathsToDelete.length)) {
      await deleteTempYaml(path);
    }
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  it("Vector 1: fails closed on toxic config and quoted identifier injection attempts", async () => {
    const nullRetentionPath = await writeTempYaml(`
version: "1.0"
database:
  app_schema: tenant_app
  engine_schema: tenant_engine
compliance_policy:
  default_retention_years: null
  notice_window_hours: 48
  retention_rules:
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: users
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
satellite_targets:
  - table: marketing_leads
    lookup_column: email
    action: redact
    masking_rules:
      email: HMAC
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 1000
security:
  notification_lease_seconds: 120
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"1".repeat(64)}"
legal_attestation:
  dpo_identifier: "dpo-name@client.com"
  configuration_version: "v1.2.0"
  legal_review_date: "2026-04-20"
  acknowledgment: "I confirm this configuration accurately reflects our obligations."
`);
    configPathsToDelete.push(nullRetentionPath);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        nullRetentionPath
      )
    ).rejects.toThrow(/default_retention_years/i);

    const injectionPath = await writeTempYaml(`
version: "1.0"
database:
  app_schema: tenant_app
  engine_schema: tenant_engine
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules:
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: "users; DROP TABLE clients;--"
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
satellite_targets:
  - table: marketing_leads
    lookup_column: email
    action: redact
    masking_rules:
      email: HMAC
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 1000
security:
  notification_lease_seconds: 120
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"1".repeat(64)}"
legal_attestation:
  dpo_identifier: "dpo-name@client.com"
  configuration_version: "v1.2.0"
  legal_review_date: "2026-04-20"
  acknowledgment: "I confirm this configuration accurately reflects our obligations."
`);
    configPathsToDelete.push(injectionPath);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        injectionPath
      )
    ).rejects.toThrow(/invalid graph root table/i);

    const injectionSchema = uniqueSchema("adversarial_identifier");
    schemasToDrop.push(injectionSchema);
    await dropSchemas(sql, injectionSchema);
    await sql`CREATE SCHEMA ${sql(injectionSchema)}`;
    await sql`CREATE TABLE ${sql(injectionSchema)}.clients (id SERIAL PRIMARY KEY)`;

    await expect(
      sql`
        SELECT 1
        FROM ${sql(injectionSchema)}.${sql("users; DROP TABLE clients;--")}
      `
    ).rejects.toThrow();

    const [tableCheck] = await sql<{ regclass: string | null }[]>`
      SELECT to_regclass(${`${injectionSchema}.clients`}) AS regclass
    `;
    expect(tableCheck?.regclass).toBe(`${injectionSchema}.clients`);
  });

  it("Vector 2: prevents TOCTOU partial mutation under static-plan execution and concurrent FK insert", async () => {
    const appSchema = uniqueSchema("adversarial_toctou_app");
    const engineSchema = uniqueSchema("adversarial_toctou_engine");
    schemasToDrop.push(appSchema, engineSchema);

    await dropSchemas(sql, appSchema, engineSchema);
    await sql`CREATE SCHEMA ${sql(appSchema)}`;
    await sql`CREATE TABLE ${sql(appSchema)}.users (id SERIAL PRIMARY KEY, email TEXT NOT NULL, full_name TEXT NOT NULL)`;
    await sql`
      CREATE TABLE ${sql(appSchema)}.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES ${sql(appSchema)}.users(id),
        amount NUMERIC NOT NULL
      )
    `;
    await sql.unsafe(`
      CREATE FUNCTION "${appSchema}".slow_user_update()
      RETURNS trigger
      LANGUAGE plpgsql
      AS $$
      BEGIN
        PERFORM pg_sleep(1);
        RETURN NEW;
      END;
      $$;
      CREATE TRIGGER slow_user_update
      BEFORE UPDATE ON "${appSchema}".users
      FOR EACH ROW EXECUTE FUNCTION "${appSchema}".slow_user_update();
    `);
    await runMigrations(sql, engineSchema);

    const userId = await insertUser(sql, appSchema, "race@example.com", "Race User");
    getDependencyGraphMock.mockClear();
    getDependencyGraphMock.mockResolvedValue([]);

    const vaultPromise = vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema, new Date()));
    await new Promise((resolve) => setTimeout(resolve, 120));

    const insertPromise = sql`
      INSERT INTO ${sql(appSchema)}.orders (user_id, amount)
      VALUES (${userId}, 10.5)
      RETURNING id
    `;
    const earlyOutcome = await Promise.race([
      insertPromise.then(() => "done"),
      new Promise<"blocked">((resolve) => setTimeout(() => resolve("blocked"), 200)),
    ]);

    expect(earlyOutcome).toBe("blocked");
    const vaultResult = await vaultPromise;
    expect(vaultResult.action).toBe("vaulted");
    expect(getDependencyGraphMock).not.toHaveBeenCalled();

    const insertOutcome = await insertPromise.then(
      () => "inserted",
      () => "failed"
    );
    expect(["inserted", "failed"]).toContain(insertOutcome);

    const [vaultRow] = await sql`
      SELECT user_uuid_hash
      FROM ${sql(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = 'users'
        AND root_id = ${userId.toString()}
    `;
    expect(vaultRow?.user_uuid_hash).toBe(vaultResult.userHash);
  });

  it("Vector 3: terminates cyclic traversal and trips depth circuit breaker at >32", async () => {
    const { getDependencyGraph } = await vi.importActual<typeof import("@modules/db/graph")>("@modules/db/graph");
    const cycleSchema = uniqueSchema("adversarial_cycle");
    schemasToDrop.push(cycleSchema);

    await dropSchemas(sql, cycleSchema);
    await sql`CREATE SCHEMA ${sql(cycleSchema)}`;
    await sql`CREATE TABLE ${sql(cycleSchema)}.circ_a (id SERIAL PRIMARY KEY)`;
    await sql`
      CREATE TABLE ${sql(cycleSchema)}.circ_b (
        id SERIAL PRIMARY KEY,
        a_id INTEGER REFERENCES ${sql(cycleSchema)}.circ_a(id)
      )
    `;
    await sql`ALTER TABLE ${sql(cycleSchema)}.circ_a ADD COLUMN b_id INTEGER REFERENCES ${sql(cycleSchema)}.circ_b(id)`;

    const cyclicGraph = await getDependencyGraph(sql, cycleSchema, "circ_a", { maxDepth: 32 });
    const circBRows = cyclicGraph.filter((row) => row.table_name === `${cycleSchema}.circ_b`);
    expect(circBRows).toHaveLength(1);

    const deepSchema = uniqueSchema("adversarial_depth");
    schemasToDrop.push(deepSchema);
    await dropSchemas(sql, deepSchema);
    await sql`CREATE SCHEMA ${sql(deepSchema)}`;
    await sql`CREATE TABLE ${sql(deepSchema)}.users (id SERIAL PRIMARY KEY)`;

    let parentTable = "users";
    for (let depth = 1; depth <= 33; depth += 1) {
      const table = `level_${depth}`;
      await sql`
        CREATE TABLE ${sql(deepSchema)}.${sql(table)} (
          id SERIAL PRIMARY KEY,
          parent_id INTEGER REFERENCES ${sql(deepSchema)}.${sql(parentTable)}(id)
        )
      `;
      parentTable = table;
    }

    await expect(getDependencyGraph(sql, deepSchema, "users", { maxDepth: 32 })).rejects.toThrow(/safety limit/i);
  });

  it("Vector 4: rejects corrupted AES-GCM auth tags and halts decryption", async () => {
    const appSchema = uniqueSchema("adversarial_crypto_app");
    const engineSchema = uniqueSchema("adversarial_crypto_engine");
    schemasToDrop.push(appSchema, engineSchema);

    await dropSchemas(sql, appSchema, engineSchema);
    await sql`CREATE SCHEMA ${sql(appSchema)}`;
    await sql`CREATE TABLE ${sql(appSchema)}.users (id SERIAL PRIMARY KEY, email TEXT NOT NULL, full_name TEXT NOT NULL)`;
    await sql`
      CREATE TABLE ${sql(appSchema)}.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES ${sql(appSchema)}.users(id),
        amount NUMERIC NOT NULL
      )
    `;
    await runMigrations(sql, engineSchema);

    getDependencyGraphMock.mockClear();
    getDependencyGraphMock.mockResolvedValue([
      {
        table_schema: appSchema,
        table_name: `${appSchema}.orders`,
        column_name: "user_id",
        parent_table: `${appSchema}.users`,
        depth: 1,
      },
    ]);

    const userId = await insertUser(sql, appSchema, "cipher@example.com", "Cipher User");
    const result = await vaultUser(sql, userId, TEST_SECRETS, buildVaultOptions(appSchema, engineSchema, new Date()));
    expect(result.action).toBe("vaulted");

    const [vaultRow] = await sql`
      SELECT encrypted_pii
      FROM ${sql(engineSchema)}.pii_vault
      WHERE user_uuid_hash = ${result.userHash}
    `;
    const [keyRow] = await sql`
      SELECT encrypted_dek
      FROM ${sql(engineSchema)}.user_keys
      WHERE user_uuid_hash = ${result.userHash}
    `;

    const wrappedDek = new Uint8Array(keyRow!.encrypted_dek);
    const dek = await unwrapKey(wrappedDek, TEST_SECRETS.kek);
    const payload = vaultRow!.encrypted_pii as { data: string };
    const encryptedBytes = new Uint8Array(Buffer.from(payload.data, "base64"));
    if (encryptedBytes.length === 0) {
      throw new Error("Encrypted payload unexpectedly empty.");
    }
    const tagByteIndex = encryptedBytes.length - 1;
    encryptedBytes[tagByteIndex] = encryptedBytes[tagByteIndex]! ^ 0xff;

    await expect(decryptGCM(encryptedBytes, dek)).rejects.toThrow();
  });

  it("Vector 5: retries with exponential backoff and dead-letters after 10 consecutive 500s", async () => {
    const engineSchema = uniqueSchema("adversarial_outbox_engine");
    schemasToDrop.push(engineSchema);

    await dropSchemas(sql, engineSchema);
    await runMigrations(sql, engineSchema);

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
        'adversarial:event:1',
        'user-hash-1',
        'USER_VAULTED',
        ${sql.json({ rootId: "1" })},
        'GENESIS',
        'hash-1',
        'pending',
        0,
        ${new Date("2026-04-18T00:00:00.000Z")},
        NOW(),
        NOW()
      )
    `;

    let now = new Date("2026-04-18T00:00:00.000Z");
    let deliveryCalls = 0;
    const baseBackoffMs = 250;

    for (let attempt = 1; attempt <= 10; attempt += 1) {
      const result = await processOutbox(
        sql,
        async () => {
          deliveryCalls += 1;
          throw new Error("Brain API responded with HTTP 500.");
        },
        {
          engineSchema,
          batchSize: 1,
          maxAttempts: 10,
          baseBackoffMs,
          now,
        }
      );

      const [row] = await sql<{
        status: "pending" | "dead_letter";
        attempt_count: number;
        next_attempt_at: Date;
        last_error: string | null;
      }[]>`
        SELECT status, attempt_count, next_attempt_at, last_error
        FROM ${sql(engineSchema)}.outbox
        WHERE idempotency_key = 'adversarial:event:1'
      `;

      expect(result.failed).toBe(1);
      expect(row?.attempt_count).toBe(attempt);
      expect(row?.last_error).toContain("HTTP 500");

      if (attempt < 10) {
        expect(result.deadLettered).toBe(0);
        expect(row?.status).toBe("pending");
        const expectedDelay = calculateRetryDelayMs(attempt, baseBackoffMs);
        expect(new Date(row!.next_attempt_at).getTime()).toBe(now.getTime() + expectedDelay);
        now = new Date(now.getTime() + expectedDelay);
      } else {
        expect(result.deadLettered).toBe(1);
        expect(row?.status).toBe("dead_letter");
      }
    }

    expect(deliveryCalls).toBe(10);
  });
});
