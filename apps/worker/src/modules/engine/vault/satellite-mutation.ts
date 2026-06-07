import type { Tsql } from "@/types";
import { fail } from "@/errors";
import { quoteQualifiedIdentifier } from "@/utils";
import { generateHMACWithKey } from "@modules/crypto";
import type { SatelliteTarget } from "@modules/config";
import { normalizeRootRowValue, type RootMutationContext } from "./context";
import { redactSatelliteTable } from "./satellite";

const DEFAULT_SATELLITE_BATCH_SIZE = 1000;

/**
 * Summary of a single satellite-table mutation.
 */
export interface SatelliteMutationResult {
  table: string;
  action: "redact" | "hard_delete";
  affectedRows: number;
}

/**
 * Yields the Bun event loop between large mutation batches to keep heartbeats responsive.
 */
export async function yieldWorkerEventLoop(): Promise<void> {
  if (typeof globalThis.Bun !== "undefined" && typeof globalThis.Bun.sleep === "function") {
    await globalThis.Bun.sleep(0);
    return;
  }

  await new Promise<void>((resolve) => setTimeout(resolve, 0));
}

async function hardDeleteSatelliteRows(
  tx: Tsql,
  appSchema: string,
  tableName: string,
  lookupColumn: string,
  lookupValue: string,
  tenantId?: string,
  batchSize: number = DEFAULT_SATELLITE_BATCH_SIZE
): Promise<number> {
  if (!Number.isInteger(batchSize) || batchSize < 1) {
    fail({
      code: "SATELLITE_BATCH_SIZE_INVALID",
      title: "Invalid satellite batch size",
      detail: "satellite batchSize must be an integer greater than 0.",
      category: "validation",
      retryable: false,
    });
  }

  let totalDeleted = 0;

  while (true) {
    const tenantFilter = tenantId ? tx` AND tenant_id = ${tenantId}` : tx``;
    const deletedRows = await tx<{ id: string | number }[]>`
      WITH batch AS (
        SELECT id
        FROM ${tx(appSchema)}.${tx(tableName)}
        WHERE ${tx(lookupColumn)} = ${lookupValue}
        ${tenantFilter}
        LIMIT ${batchSize}
        FOR UPDATE SKIP LOCKED
      )
      DELETE FROM ${tx(appSchema)}.${tx(tableName)}
      WHERE id IN (SELECT id FROM batch)
      RETURNING id
    `;

    if (deletedRows.length === 0) {
      break;
    }

    totalDeleted += deletedRows.length;
    await yieldWorkerEventLoop();
  }

  return totalDeleted;
}

async function mutateSatelliteTarget(
  tx: Tsql,
  appSchema: string,
  target: SatelliteTarget,
  lockedRootRow: Record<string, unknown>,
  hmacKey: CryptoKey,
  tenantId?: string
): Promise<SatelliteMutationResult> {
  const lookupValue = normalizeRootRowValue(lockedRootRow[target.lookup_column]);
  if (lookupValue === null) {
    return {
      table: `${appSchema}.${target.table}`,
      action: target.action,
      affectedRows: 0,
    };
  }

  const tableCheck = quoteQualifiedIdentifier(appSchema, target.table);
  const colCheck = await tx.unsafe(`SELECT * FROM ${tableCheck} LIMIT 0`);
  const existingCols = new Set((colCheck.columns ?? []).map((c) => c.name));
  if (!existingCols.has(target.lookup_column)) {
    fail({
      code: "SATELLITE_COLUMN_MISSING",
      title: "Satellite lookup column missing from database schema",
      detail: `Lookup column "${target.lookup_column}" does not exist in target table "${appSchema}.${target.table}".`,
      category: "database",
      retryable: false,
      fatal: false,
    });
  }

  if (target.action === "redact") {
    const newHmacValue = await generateHMACWithKey(
      `${appSchema}:${target.table}:${target.lookup_column}:${lookupValue}`,
      hmacKey
    );
    const affectedRows = await redactSatelliteTable(
      tx,
      `${appSchema}.${target.table}`,
      target.lookup_column,
      lookupValue,
      newHmacValue,
      DEFAULT_SATELLITE_BATCH_SIZE,
      tenantId
    );

    return {
      table: `${appSchema}.${target.table}`,
      action: target.action,
      affectedRows,
    };
  }

  const affectedRows = await hardDeleteSatelliteRows(
    tx,
    appSchema,
    target.table,
    target.lookup_column,
    lookupValue,
    tenantId
  );

  return {
    table: `${appSchema}.${target.table}`,
    action: target.action,
    affectedRows,
  };
}

/**
 * Applies all configured satellite mutations inside the active vault transaction.
 *
 * @param tx - Active repeatable-read transaction.
 * @param appSchema - Client application schema.
 * @param rootContext - Validated root and satellite configuration.
 * @param lockedRootRow - Locked root row snapshot.
 * @param hmacKey - Pre-imported worker HMAC key.
 * @param tenantId - Optional tenant discriminator.
 * @returns One result entry per configured satellite target.
 */
export async function mutateSatelliteTargets(
  tx: Tsql,
  appSchema: string,
  rootContext: RootMutationContext,
  lockedRootRow: Record<string, unknown>,
  hmacKey: CryptoKey,
  tenantId?: string
): Promise<SatelliteMutationResult[]> {
  const settled = await Promise.allSettled(
    rootContext.satelliteTargets.map(async (target) => {
      const result = await mutateSatelliteTarget(
        tx,
        appSchema,
        target,
        lockedRootRow,
        hmacKey,
        tenantId
      );
      await yieldWorkerEventLoop();
      return result;
    })
  );

  const rejected = settled.find(
    (result): result is PromiseRejectedResult => result.status === "rejected"
  );
  if (rejected) {
    throw rejected.reason;
  }

  return settled.map(
    (result) => (result as PromiseFulfilledResult<SatelliteMutationResult>).value
  );
}