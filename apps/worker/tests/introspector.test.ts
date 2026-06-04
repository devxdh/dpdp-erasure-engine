import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { writeFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
import {
  classifyLeaf,
  compileStaticDag,
  extractLeafValues,
  runIntrospector,
  sampleS3ObjectChunk,
  sampleS3ObjectForClassification,
  validateAadhaar,
  validateGstin,
  validateLuhn,
  validatePan,
  verifySchemaIntegrity,
} from "@modules/introspector";
import { detectSchemaDrift } from "@modules/db";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import type { Sql } from "@/types";

async function gzipBytes(bytes: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);

  if (typeof Bun !== "undefined") {
    return Bun.gzipSync(copy);
  }

  const stream = new Blob([copy.buffer]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });

  if (typeof Bun !== "undefined") {
    await Bun.write(path, value);
  } else {
    await writeFile(path, value, "utf8");
  }
}

async function readText(path: string): Promise<string> {
  let content: string;

  if (typeof Bun !== "undefined") {
    content = await Bun.file(path).text();
  } else {
    const { readFile } = await import("node:fs/promises");
    content = await readFile(path, "utf8");
  }

  return content.trim();
}

describe("Offline Introspector", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  }, 60_000);

  async function prepareSchema() {
    const schema = uniqueSchema("introspector");
    schemasToDrop.push(schema);
    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;
    await sql`
      CREATE TABLE ${sql(schema)}.users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        full_name TEXT NOT NULL,
        upi_id TEXT NOT NULL,
        card_number TEXT NOT NULL,
        gstin TEXT NOT NULL,
        random_digits TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.profiles (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ${sql(schema)}.users(id),
        pan TEXT NOT NULL,
        aadhaar_payload JSONB NOT NULL,
        nested_payload JSONB NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ${sql(schema)}.users(id),
        receipt_code TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.kyc_reviews (
        id SERIAL PRIMARY KEY,
        profile_id INTEGER NOT NULL REFERENCES ${sql(schema)}.profiles(id),
        reviewer_note TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.support_events (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL,
        event_name TEXT NOT NULL
      )
    `;
    await sql`
      INSERT INTO ${sql(schema)}.users (email, phone, full_name, upi_id, card_number, gstin, random_digits)
      VALUES
        ('alpha@example.com', '+91-9876543210', 'Alpha User', 'alpha.user@upi', '4111 1111 1111 1111', '27ABCPE1234F1Z5', '123456789012'),
        ('beta@example.com', '9876543211', 'Beta User', 'beta.user@upi', '5555 5555 5555 4444', '27PQRPT9876Z1Z5', '987654321234')
    `;
    await sql`
      INSERT INTO ${sql(schema)}.profiles (user_id, pan, aadhaar_payload, nested_payload)
      VALUES
        (1, 'ABCPE1234F', ${sql.json({ government_id: "2345 6789 1238" })}, ${sql.json({ profile: { contact_email: "redacted" } })}),
        (2, 'PQRPT9876Z', ${sql.json({ nested: { aadhaar: "3456 7891 2342" } })}, ${sql.json({ pii: { phone_number: "not-collected" } })})
    `;
    await sql`
      INSERT INTO ${sql(schema)}.orders (user_id, receipt_code)
      VALUES (1, 'R-100'), (2, 'R-200')
    `;
    await sql`
      INSERT INTO ${sql(schema)}.kyc_reviews (profile_id, reviewer_note)
      VALUES (1, 'verified'), (2, 'verified')
    `;
    await sql`
      INSERT INTO ${sql(schema)}.support_events (user_id, event_name)
      VALUES (1, 'ticket_opened'), (2, 'ticket_closed')
    `;
    return schema;
  }

  it("uses checksum-backed signatures and iterative JSON flattening to reduce false positives", () => {
    expect(validateAadhaar("2345 6789 1238")).toBe(true);
    expect(validateAadhaar("2345 6789 1234")).toBe(false);
    expect(validateAadhaar("9999 9999 9999")).toBe(false);
    expect(validateLuhn("4111 1111 1111 1111")).toBe(true);
    expect(validateLuhn("4111 1111 1111 1112")).toBe(false);
    expect(validatePan("ABCPE1234F")).toBe(true);
    expect(validatePan("ABCDE1234F")).toBe(false);
    expect(validateGstin("27ABCPE1234F1Z5")).toBe(true);
    expect(validateGstin("27ABCDE1234F1Z5")).toBe(false);

    expect(classifyLeaf("2345 6789 1234")).not.toContain("aadhaar");
    expect(classifyLeaf("2345 6789 1238")).toContain("aadhaar");
    expect(classifyLeaf("4111 1111 1111 1112")).not.toContain("credit_card");
    expect(classifyLeaf("123456789012")).not.toContain("bank_account");
    expect(classifyLeaf("123456789012", "bank_account_number")).toContain("bank_account");
    expect(classifyLeaf("Alpha User")).toEqual([]);

    const deepPayload = { a: { b: { c: { d: { e: { f: { g: { h: { i: { j: { k: "too-deep@example.com" } } } } } } } } } } };
    expect(extractLeafValues(deepPayload, "jsonb")).toEqual([]);
  });

  it("compiles a static FK DAG from the root table with bounded depth", async () => {
    const schema = await prepareSchema();

    const dag = await compileStaticDag({
      sql,
      rootTable: `${schema}.users`,
      maxDepth: 32,
    });

    expect(dag.map((target) => `${target.depth}:${target.table.schema}.${target.table.table}`)).toEqual([
      `0:${schema}.users`,
      `1:${schema}.orders`,
      `1:${schema}.profiles`,
      `2:${schema}.kyc_reviews`,
    ]);
    expect(dag.find((target) => target.table.table === "profiles")?.fkCondition).toBe(
      `${schema}.users.id = ${schema}.profiles.user_id`
    );
  }, 60_000);

  it("classifies PII with metadata plus bounded content sampling and renders a draft YAML", async () => {
    const schema = await prepareSchema();

    const { draft, yaml } = await runIntrospector({
      sql,
      rootTable: `${schema}.users`,
      samplePercent: 100,
      sampleLimit: 100,
      threshold: 0.75,
      generatedAt: new Date("2026-04-27T00:00:00.000Z"),
    });

    const users = draft.targets.find((target) => target.table.table === "users");
    const profiles = draft.targets.find((target) => target.table.table === "profiles");
    const orders = draft.targets.find((target) => target.table.table === "orders");

    expect(users?.piiColumns.map((column) => column.column).sort()).toEqual([
      "card_number",
      "email",
      "gstin",
      "phone",
      "upi_id",
    ]);
    expect(profiles?.piiColumns.map((column) => column.column).sort()).toEqual([
      "aadhaar_payload",
      "nested_payload",
      "pan",
    ]);
    expect(orders?.piiColumns).toEqual([]);
    expect(yaml).toContain("rules:");
    expect(yaml).toContain(`root_table: ${schema}.users`);
    expect(yaml).toContain(`table: ${schema}.profiles`);
    expect(yaml).toContain("pii_columns: [pan, aadhaar_payload, nested_payload]");
    expect(yaml).not.toContain("full_name");
    expect(yaml).toContain("schema_hash:");
    expect(yaml).toContain("generated_by: compliance-introspector-v1");
    expect(yaml).toContain("legal_disclaimer:");
    expect(yaml).toContain("[Potential Logical Link]");
    expect(yaml).toContain(`${schema}.orders.user_id <-> ${schema}.support_events.user_id`);
    expect(yaml).toContain("# REVIEW REQUIRED");
  }, 60_000);

  it("uses a bounded S3 Range request for object-store sampling", async () => {
    const body = new Uint8Array([65, 66, 67]);
    const calls: Array<{ url: string; range: string | null; authorization: string | null }> = [];
    const fetchFn = (async (url, init) => {
      const headers = new Headers(init?.headers);
      calls.push({
        url: String(url),
        range: headers.get("range"),
        authorization: headers.get("authorization"),
      });
      return new Response(body.slice(), { status: 206 });
    }) as typeof fetch;

    const chunk = await sampleS3ObjectChunk({
      bucket: "client-vault",
      key: "kyc/user-1.pdf",
      region: "ap-south-1",
      maxBytes: 1024,
      fetchFn,
      credentials: {
        accessKeyId: "AKIA_TEST",
        secretAccessKey: "secret",
      },
    });

    try {
      expect(new TextDecoder().decode(chunk)).toBe("ABC");
      expect(calls).toHaveLength(1);
      expect(calls[0]?.range).toBe("bytes=0-1023");
      expect(calls[0]?.authorization).toContain("AWS4-HMAC-SHA256");
      expect(calls[0]?.url).toBe("https://client-vault.s3.ap-south-1.amazonaws.com/kyc/user-1.pdf");
    } finally {
      chunk.fill(0);
    }
  });

  it("decompresses gzip prefixes and flags binary structured formats before regex scanning", async () => {
    const gzipped = await gzipBytes(new TextEncoder().encode("alpha@example.com"));
    const gzipFetch = (async () =>
      new Response(gzipped.slice(), {
        status: 206,
        headers: { "content-type": "application/gzip" },
      })) as unknown as typeof fetch;

    const gzipSample = await sampleS3ObjectForClassification({
      bucket: "client-vault",
      key: "logs/users.json.gz",
      region: "ap-south-1",
      fetchFn: gzipFetch,
      credentials: {
        accessKeyId: "AKIA_TEST",
        secretAccessKey: "secret",
      },
    });

    try {
      expect(gzipSample.decompressed).toBe(true);
      expect(new TextDecoder().decode(gzipSample.bytes)).toBe("alpha@example.com");
    } finally {
      gzipSample.bytes.fill(0);
    }

    const parquetFetch = (async () =>
      new Response(new Uint8Array([0x50, 0x41, 0x52, 0x31, 0x00]).slice(), { status: 206 })) as unknown as typeof fetch;
    const parquetSample = await sampleS3ObjectForClassification({
      bucket: "client-vault",
      key: "warehouse/users.parquet",
      region: "ap-south-1",
      fetchFn: parquetFetch,
      credentials: {
        accessKeyId: "AKIA_TEST",
        secretAccessKey: "secret",
      },
    });

    expect(parquetSample.binaryFormat).toBe("parquet");
    expect(parquetSample.bytes).toHaveLength(0);
    expect(parquetSample.warnings).toContain("BINARY_FORMAT_DETECTED: Structural Metadata Scan Required.");
  });

  it("verifies legal-attested schema hashes for CI/CD gates", async () => {
    const schema = await prepareSchema();
    const liveHash = await detectSchemaDrift(sql, schema);
    const path = `/tmp/compliance-introspector-${crypto.randomUUID()}.yml`;
    await writeText(
      path,
      `
version: "1.0"
database:
  app_schema: ${schema}
  engine_schema: dpdp_engine
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules: []
graph:
  root_table: users
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
satellite_targets:
  - table: support_events
    lookup_column: user_id
    action: hard_delete
blob_targets: []
rules:
  - id: dpdp_standard
    root_table: ${schema}.users
    targets:
      - table: ${schema}.users
        pii_columns: [email]
      - table: ${schema}.orders
        parent: ${schema}.users
        join: "${schema}.users.id = ${schema}.orders.user_id"
        pii_columns: []
      - table: ${schema}.profiles
        parent: ${schema}.users
        join: "${schema}.users.id = ${schema}.profiles.user_id"
        pii_columns: [pan, aadhaar_payload, nested_payload]
      - table: ${schema}.kyc_reviews
        parent: ${schema}.profiles
        join: "${schema}.profiles.id = ${schema}.kyc_reviews.profile_id"
        pii_columns: []
      - table: ${schema}.support_events
        pii_columns: []
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 3
security:
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"0".repeat(64)}"
legal_attestation:
  dpo_identifier: dpo@example.com
  configuration_version: v-test
  legal_review_date: "2026-04-20"
  schema_hash: "${liveHash}"
  generated_by: compliance-introspector-v1
  acknowledgment: reviewed
`
    );

    const result = await verifySchemaIntegrity({
      sql,
      configPath: path,
      env: {
        DPDP_MASTER_KEY: "0".repeat(64),
        DPDP_HMAC_KEY: "0".repeat(64),
      },
    });
    expect(result).toBe(liveHash);

    await writeText(path, (await readText(path)).replace(liveHash, "1".repeat(64)));
    await expect(
      verifySchemaIntegrity({
        sql,
        configPath: path,
        env: {
          DPDP_MASTER_KEY: "0".repeat(64),
          DPDP_HMAC_KEY: "0".repeat(64),
        },
      })
    ).rejects.toThrow(/does not match legal attestation hash/i);
  });
});
