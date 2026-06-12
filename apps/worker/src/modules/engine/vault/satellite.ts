import { fail } from "@/errors";
import type { Tsql } from "@/types";
import { assertIdentifier } from "@/utils";

interface SatelliteRowId {
  ctid: string;
}

async function yieldWorkerEventLoop(): Promise<void> {
  if (typeof globalThis.Bun !== "undefined" && typeof globalThis.Bun.sleep === "function") {
    await globalThis.Bun.sleep(0);
    return;
  }

  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

function parseQualifiedTableName(tableName: string) {
  const [schema, table, ...rest] = tableName.split(".");
  if (!schema || !table || rest.length > 0) {
    fail({
      code: "SATELLITE_TABLE_INVALID",
      title: "Invalid satellite table name",
      detail: `Invalid table name "${tableName}". Expected "schema.table".`,
      category: "validation",
      retryable: false,
      context: { tableName },
    });
  }

  return {
    schema: assertIdentifier(schema, "schema name"),
    table: assertIdentifier(table, "table name"),
  };
}

/**
 * Redacts satellite table rows in cursor-sized batches using `FOR UPDATE SKIP LOCKED`.
 *
 * The function is designed for large tables and concurrent workers:
 * each iteration locks and updates only one batch, yields back to Bun's event loop, then
 * continues until no rows remain.
 *
 * @param tx - Active worker transaction.
 * @param tableName - Qualified table name in `schema.table` form.
 * @param lookupColumn - Column used to locate rows that reference the root subject.
 * @param lookupValue - Value to match in `lookupColumn`.
 * @param newHmacValue - Replacement value written during redaction.
 * @param batchSize - Maximum rows processed per loop iteration.
 * @param tenantId - Optional tenant discriminator.
 * @returns Total number of rows redacted.
 * @throws {WorkerError} When identifiers are invalid or batch sizing is unsafe.
 */
export async function redactSatelliteTable(
  tx: Tsql,
  tableName: string,
  lookupColumn: string,
  lookupValue: string,
  newHmacValue: string,
  batchSize: number = 1000,
  tenantId?: string
): Promise<number> {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    fail({
      code: "SATELLITE_BATCH_SIZE_INVALID",
      title: "Invalid satellite batch size",
      detail: "batchSize must be an integer greater than 0.",
      category: "validation",
      retryable: false,
    });
  }

  const { schema, table } = parseQualifiedTableName(tableName);
  const safeLookupColumn = assertIdentifier(lookupColumn, "lookup column");
  let totalRedacted = 0;

  while (true) {
    const tenantFilter = tenantId ? tx` AND tenant_id = ${tenantId}` : tx``;
    const updatedRows = await tx<SatelliteRowId[]>`
      WITH batch AS (
        SELECT ctid
        FROM ${tx(schema)}.${tx(table)}
        WHERE ${tx(safeLookupColumn)} = ${lookupValue}
        ${tenantFilter}
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      UPDATE ${tx(schema)}.${tx(table)}
      SET ${tx(safeLookupColumn)} = ${newHmacValue}
      WHERE ctid IN (SELECT ctid FROM batch)
      RETURNING ctid
    `;

    if (updatedRows.length === 0) {
      break;
    }

    totalRedacted += updatedRows.length;
    await yieldWorkerEventLoop();
  }

  return totalRedacted;
}
