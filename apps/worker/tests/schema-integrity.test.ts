import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Sql } from "@/types";
import { createTestSql, dropSchemas, uniqueSchema } from "./helpers";
import { detectSchemaDrift } from "@modules/db";
import { assertSchemaIntegrity } from "@modules/bootstrap";

describe("Schema Drift Detection", () => {
  let sql: Sql;
  const schemasToDrop: string[] = [];

  beforeAll(() => {
    sql = createTestSql();
  });

  afterAll(async () => {
    await dropSchemas(sql, ...schemasToDrop);
    await sql.end();
  });

  async function createSchema() {
    const schema = uniqueSchema("drift_app");
    schemasToDrop.push(schema);

    await dropSchemas(sql, schema);
    await sql`CREATE SCHEMA ${sql(schema)}`;
    await sql`
      CREATE TABLE ${sql(schema)}.users (
        id SERIAL PRIMARY KEY,
        email TEXT NOT NULL,
        full_name TEXT NOT NULL
      )
    `;
    await sql`
      CREATE TABLE ${sql(schema)}.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES ${sql(schema)}.users(id),
        amount NUMERIC NOT NULL
      )
    `;

    return schema;
  }

  it("returns a deterministic digest and changes when the schema changes", async () => {
    const schema = await createSchema();

    const first = await detectSchemaDrift(sql, schema);
    const second = await detectSchemaDrift(sql, schema);
    expect(second).toBe(first);

    await sql`ALTER TABLE ${sql(schema)}.users ADD COLUMN phone TEXT`;

    const third = await detectSchemaDrift(sql, schema);
    expect(third).not.toBe(first);
  });

  it("fails closed when the manifest hash does not match the live schema digest", async () => {
    const schema = await createSchema();
    const liveHash = await detectSchemaDrift(sql, schema);

    await expect(assertSchemaIntegrity(sql, schema, liveHash)).resolves.toBe(liveHash);
    await expect(assertSchemaIntegrity(sql, schema, "0".repeat(64))).rejects.toThrow(/schema drift detected/i);
  });
});
