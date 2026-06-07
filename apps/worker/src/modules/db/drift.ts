import type { Sql } from "@/types";
import { assertIdentifier } from "@/utils";
import { sha256HexDigest } from "@/lib";

interface SchemaColumnRow {
  table_name: string;
  column_name: string;
  data_type: string;
}

/**
 * Computes a deterministic SHA-256 fingerprint of the live application schema.
 *
 * The signature is built from ordered `table_name + column_name + data_type` tuples.
 *
 * @param sql - Postgres pool or transaction used for metadata query.
 * @param appSchema - Application schema to fingerprint.
 * @returns Hex-encoded SHA-256 schema hash.
 * @throws {WorkerError} When `appSchema` is not a safe SQL identifier.
 */
export async function detectSchemaDrift(sql: Sql, appSchema: string): Promise<string> {
  const safeAppSchema = assertIdentifier(appSchema, "application schema name");

  const columns = await sql<SchemaColumnRow[]>`
    SELECT table_name, column_name, data_type
    FROM information_schema.columns
    WHERE table_schema = ${safeAppSchema}
    ORDER BY table_name ASC, ordinal_position ASC, column_name ASC
  `;

  const signature = columns.map(
    (column) => `${column.table_name}${column.column_name}${column.data_type}`)
    .join("");

  return sha256HexDigest(signature)
}