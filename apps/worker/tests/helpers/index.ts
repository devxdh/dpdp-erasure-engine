import postgres from "postgres";
import { runMigrations } from "@modules/db";
import type { Sql } from "@/types";

export const TEST_DATABASE_URL = process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

export const TEST_SECRETS = {
  kek: new Uint8Array(32).fill(0x42),
  hmacKey: new Uint8Array(32).fill(0x24),
};

export function createTestSql(): Sql {
  return postgres(TEST_DATABASE_URL);
}

export function uniqueSchema(prefix: string): string {
  return `${prefix}_${globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

export async function dropSchemas(sql: Sql, ...schemas: string[]) {
  for (const schema of schemas) {
    await sql`DROP SCHEMA IF EXISTS ${sql(schema)} CASCADE`;
  }
}

export async function createAppSchema(
  sql: Sql,
  schema: string,
  options: { withDependencies?: boolean; withDeepDependencies?: boolean } = {}
) {
  await sql`CREATE SCHEMA ${sql(schema)}`;
  await sql`
    CREATE TABLE ${sql(schema)}.users (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      full_name TEXT NOT NULL
    )
  `;

  if (!options.withDependencies) {
    return;
  }

  await sql`
    CREATE TABLE ${sql(schema)}.orders (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES ${sql(schema)}.users(id),
      amount DECIMAL NOT NULL
    )
  `;

  await sql`
    CREATE TABLE ${sql(schema)}.profiles (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES ${sql(schema)}.users(id),
      bio TEXT
    )
  `;

  if (!options.withDeepDependencies) {
    return;
  }

  await sql`
    CREATE TABLE ${sql(schema)}.shipping_addresses (
      id SERIAL PRIMARY KEY,
      order_id INTEGER REFERENCES ${sql(schema)}.orders(id),
      street TEXT NOT NULL,
      city TEXT NOT NULL
    )
  `;

  await sql`
    CREATE TABLE ${sql(schema)}.address_verification_logs (
      id SERIAL PRIMARY KEY,
      address_id INTEGER REFERENCES ${sql(schema)}.shipping_addresses(id),
      verified_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;
}

export async function insertUser(sql: Sql, schema: string, email: string, fullName: string): Promise<number> {
  const rows = await sql<{ id: number }[]>`
    INSERT INTO ${sql(schema)}.users (email, full_name)
    VALUES (${email}, ${fullName})
    RETURNING id
  `;

  return rows[0]!.id;
}

export async function prepareWorkerSchemas(
  sql: Sql,
  appSchema: string,
  engineSchema: string,
  options: { withDependencies?: boolean; withDeepDependencies?: boolean } = {}
) {
  await dropSchemas(sql, appSchema, engineSchema);
  await createAppSchema(sql, appSchema, options);
  await runMigrations(sql, engineSchema);
}
