import postgres from "postgres";

export const TEST_DATABASE_URL =
  process.env.TEST_DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

export function createTestSql(): postgres.Sql {
  return postgres(TEST_DATABASE_URL);
}

export function uniqueSchema(prefix: string): string {
  return `${prefix}_${globalThis.crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
}

export async function dropSchemas(sql: postgres.Sql, ...schemas: string[]) {
  const uniqueSchemas = Array.from(new Set(schemas));
  const concurrency = 4;

  for (let index = 0; index < uniqueSchemas.length; index += concurrency) {
    const batch = uniqueSchemas.slice(index, index + concurrency);
    await Promise.all(batch.map((schema) => sql`DROP SCHEMA IF EXISTS ${sql(schema)} CASCADE`));
  }
}
