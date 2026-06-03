import { afterAll, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { assertConfigSchemaCompatibility, readWorkerConfig } from "@modules/config";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import type { Sql } from "@/types";

const masterKeyHex = "42".repeat(32);
const hmacKeyBase64 = Buffer.from(new Uint8Array(32).fill(0x24)).toString("base64");

async function writeYaml(contents: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "worker-compat-"));
  const path = join(directory, "compliance.worker.yml");
  await writeFile(path, contents, "utf8");
  return path;
}

async function removeYaml(path: string) {
  await rm(path, { force: true });
  await rm(dirname(path), { recursive: true, force: true });
}

describe("Worker config schema compatibility", () => {
  const sql: Sql = createTestSql();
  const schemasToDrop: string[] = [];
  const pathsToDelete: string[] = [];

  afterAll(async () => {
    for (const path of pathsToDelete.splice(0, pathsToDelete.length)) {
      await removeYaml(path);
    }
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function createCompatibleSchema(schema: string, includeRootLookupColumn: boolean) {
    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;
    await sql`
      CREATE TABLE ${sql(schema)}.users (
        id TEXT PRIMARY KEY,
        ${includeRootLookupColumn ? sql`user_identifier TEXT NOT NULL,` : sql``}
        email TEXT NOT NULL,
        full_name TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.marketing_leads (
        id BIGSERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        name TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.system_audit_logs (
        id BIGSERIAL PRIMARY KEY,
        user_identifier TEXT NOT NULL,
        message TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.transactions (
        id TEXT NOT NULL,
        transaction_ref TEXT PRIMARY KEY,
        amount NUMERIC(18,2) NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.invoices (
        id TEXT NOT NULL,
        invoice_ref TEXT PRIMARY KEY,
        total NUMERIC(18,2) NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.kyc_documents (
        id TEXT NOT NULL,
        document_ref TEXT PRIMARY KEY
      )
    `;
  }

  async function loadConfig(appSchema: string, engineSchema: string) {
    const path = await writeYaml(`
version: "1.0"
database:
  app_schema: ${appSchema}
  engine_schema: ${engineSchema}
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules:
    - rule_name: PMLA_FINANCIAL
      legal_citation: "Prevention of Money Laundering Act, 2002, Sec 12"
      if_has_data_in:
        - transactions
        - invoices
      retention_years: 10
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: users
  root_id_column: id
  max_depth: 32
  notice_email_column: email
  notice_name_column: full_name
  root_pii_columns:
    email: HMAC
    full_name: STATIC_MASK
satellite_targets:
  - table: marketing_leads
    lookup_column: email
    action: redact
    masking_rules:
      email: HMAC
      name: STATIC_MASK
  - table: system_audit_logs
    lookup_column: user_identifier
    action: hard_delete
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
    pathsToDelete.push(path);

    return await readWorkerConfig(
      {
        DPDP_MASTER_KEY: masterKeyHex,
        DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
      },
      path
    );
  }

  it("accepts a schema that satisfies every configured root, satellite, and evidence reference", async () => {
    const appSchema = uniqueSchema("compat_ok_app");
    const engineSchema = uniqueSchema("compat_ok_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await createCompatibleSchema(appSchema, true);

    const config = await loadConfig(appSchema, engineSchema);
    await expect(assertConfigSchemaCompatibility(sql, config)).resolves.toBeUndefined();
  });

  it("fails closed when a satellite lookup column is missing from the root table", async () => {
    const appSchema = uniqueSchema("compat_bad_app");
    const engineSchema = uniqueSchema("compat_bad_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await createCompatibleSchema(appSchema, false);

    const config = await loadConfig(appSchema, engineSchema);
    await expect(assertConfigSchemaCompatibility(sql, config)).rejects.toThrow(
      new RegExp(`missing root column ${appSchema}\\.users\\.user_identifier`, "i")
    );
  });

  it("fails closed when enabled purge policy references a missing root column", async () => {
    const appSchema = uniqueSchema("compat_purge_bad_app");
    const engineSchema = uniqueSchema("compat_purge_bad_engine");
    schemasToDrop.push(appSchema, engineSchema);
    await createCompatibleSchema(appSchema, true);

    const path = await writeYaml(`
version: "1.0"
database:
  app_schema: ${appSchema}
  engine_schema: ${engineSchema}
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
  root_table: users
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
    full_name: STATIC_MASK
purge_policy:
  enabled: true
  selector:
    kind: boolean_column
    column: purge_eligible
    value: true
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
    pathsToDelete.push(path);

    const config = await readWorkerConfig(
      {
        DPDP_MASTER_KEY: masterKeyHex,
        DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
      },
      path
    );
    await expect(assertConfigSchemaCompatibility(sql, config)).rejects.toThrow(
      new RegExp(`missing root column ${appSchema}\\.users\\.purge_eligible`, "i")
    );
  });
});
