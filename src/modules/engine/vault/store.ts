import type { SqlExecutor } from "@/types";
import type { VaultRecord } from "../helpers";

/**
 * Fetches a vault row by root identity tuple.
 *
 * Lookup uses `(root_schema, root_table, root_id, tenant_id)` to avoid cross-tenant collisions.
 *
 * @param sql - Postgres pool or transaction.
 * @param engineSchema - Worker engine schema.
 * @param appSchema - Source application schema.
 * @param userId - Source root identifier.
 * @param rootTable - Source root table name.
 * @param tenantId - Optional tenant discriminator.
 * @returns Matching vault row or `null` when not yet vaulted.
 */
export async function getVaultRecordByUserId(
  sql: SqlExecutor,
  engineSchema: string,
  appSchema: string,
  userId: string | number,
  rootTable: string = "users",
  tenantId?: string
): Promise<VaultRecord | null> {
  const rows = await sql<VaultRecord[]>`
    SELECT *
    FROM ${sql(engineSchema)}.pii_vault
    WHERE root_schema = ${appSchema}
      AND root_table = ${rootTable}
      AND root_id = ${userId.toString()}
      AND tenant_id = ${tenantId ?? ""}
  `;
  return rows[0] ?? null;
}