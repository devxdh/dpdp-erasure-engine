import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { WorkerConfig } from "@modules/config";
import { assertIndexPreflight, collectIndexRequirements } from "@modules/bootstrap";
import type { Sql } from "@/types";
import { createTestSql, dropSchemas, uniqueSchema, TEST_SECRETS } from "./helpers";

describe("Worker index preflight", () => {
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
    const schema = uniqueSchema("idx_preflight");
    schemasToDrop.push(schema);
    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;
    await sql`
      CREATE TABLE ${sql(schema)}.users (
        id TEXT PRIMARY KEY,
        tenant_id TEXT,
        email TEXT NOT NULL,
        full_name TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.transactions (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        amount NUMERIC NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.support_tickets (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT NOT NULL,
        requester_email TEXT
      )
    `;

    return schema;
  }

  function buildConfig(appSchema: string): WorkerConfig {
    return {
      version: "1",
      database: {
        app_schema: appSchema,
        engine_schema: "engine",
      },
      compliance_policy: {
        default_retention_years: 0,
        notice_window_hours: 48,
        retention_rules: [
          {
            rule_name: "PMLA_FINANCIAL",
            legal_citation: "PMLA Sec 12",
            if_has_data_in: ["transactions"],
            retention_years: 10,
          },
        ],
      },
      graph: {
        root_table: "users",
        root_id_column: "id",
        max_depth: 32,
        root_pii_columns: {
          email: "HMAC",
          full_name: "STATIC_MASK",
        },
      },
      satellite_targets: [
        {
          table: "support_tickets",
          lookup_column: "user_id",
          action: "redact",
          masking_rules: {
            requester_email: "HMAC",
          },
        },
      ],
      blob_targets: [],
      rules: [
        {
          id: "dpdp_static",
          targets: [
            {
              table: `${appSchema}.users`,
              parent_columns: [],
              child_columns: [],
              primary_key_columns: ["id"],
              pii_columns: ["email"],
            },
            {
              table: `${appSchema}.support_tickets`,
              parent: `${appSchema}.users`,
              parent_columns: ["id"],
              child_columns: ["user_id"],
              primary_key_columns: ["id"],
              action: "redact",
              mutation_rules: {
                requester_email: "HMAC",
              },
              pii_columns: ["requester_email"],
            },
          ],
        },
      ],
      outbox: {
        batch_size: 10,
        lease_seconds: 30,
        max_attempts: 3,
        base_backoff_ms: 1000,
      },
      security: {
        notification_lease_seconds: 120,
        master_key_env: "DPDP_MASTER_KEY",
        hmac_key_env: "DPDP_HMAC_KEY",
      },
      integrity: {
        expected_schema_hash: "ab".repeat(32),
      },
      legal_attestation: {
        dpo_identifier: "dpo@example.com",
        configuration_version: "v1",
        legal_review_date: "2026-05-01",
        schema_hash: "ab".repeat(32),
        acknowledgment: "Reviewed",
      },
      masterKey: TEST_SECRETS.kek,
      hmacKey: TEST_SECRETS.hmacKey,
    };
  }

  it("collects every runtime lookup that must be index-backed", async () => {
    const schema = await setup();
    const requirements = collectIndexRequirements(buildConfig(schema));
    expect(requirements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ table: "users", columns: ["id"] }),
        expect.objectContaining({ table: "transactions", columns: ["id"] }),
        expect.objectContaining({ table: "support_tickets", columns: ["id"] }),
        expect.objectContaining({ table: "support_tickets", columns: ["user_id"] }),
      ])
    );
  });

  it("fails closed when evidence or satellite lookups would table-scan", async () => {
    const schema = await setup();
    const config = buildConfig(schema);

    await expect(assertIndexPreflight(sql, config)).rejects.toThrow(/missing index requirement/i);

    await sql`CREATE INDEX ${sql(`${schema}_support_tickets_user_id_idx`)} ON ${sql(schema)}.support_tickets (user_id)`;

    await expect(assertIndexPreflight(sql, config)).resolves.toEqual({
      checked: expect.any(Number),
      missing: [],
    });
  });
});
