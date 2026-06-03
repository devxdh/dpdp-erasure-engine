import { type PurgePolicy } from "@modules/config";
import { fail } from "@/errors";
import { assertIdentifier } from "@/utils";
import type { SqlExecutor } from "@/types";

export interface PurgeCandidateQuery {
  appSchema: string;
  rootTable: string;
  rootIdColumn: string;
  purgePolicy: PurgePolicy;
  limit?: number;
  now?: Date;
}

/**
 * Selects root subjects that are legally eligible for an administrator-triggered purge.
 *
 * The selector is intentionally limited to simple indexed predicates so large-tenant purge
 * discovery remains bounded, explainable, and safe to run before submitting jobs to the
 * Control Plane.
 *
 * @param sql - postgres.js connection or transaction.
 * @param input - DPO-attested purge selector and root-table metadata.
 * @returns Opaque subject identifiers to submit as `ADMIN_PURGE` erasure jobs.
 * @throws {WorkerError} When purge automation is disabled or identifiers are unsafe.
 */
export async function selectPurgeCandidates(
  sql: SqlExecutor,
  input: PurgeCandidateQuery
): Promise<string[]> {
  if (!input.purgePolicy.enabled || !input.purgePolicy.selector) {
    fail({
      code: "PURGE_POLICY_DISABLED",
      title: "Purge policy disabled",
      detail: "Refusing to discover purge candidates without an enabled purge_policy selector.",
      category: "configuration",
      retryable: false,
      fatal: false,
    });
  }

  const appSchema = assertIdentifier(input.appSchema, "application schema name");
  const rootTable = assertIdentifier(input.rootTable, "purge root table");
  const rootIdColumn = assertIdentifier(input.rootIdColumn, "purge root id column");
  const selector = input.purgePolicy.selector;
  const selectorColumn = assertIdentifier(selector.column, "purge selector column");
  const effectiveLimit = Math.min(input.limit ?? input.purgePolicy.max_batch_size, input.purgePolicy.max_batch_size);

  if (selector.kind === "boolean_column") {
    const rows = await sql<{ subject_opaque_id: string }[]>`
      SELECT ${sql(rootIdColumn)}::text AS subject_opaque_id
      FROM ${sql(appSchema)}.${sql(rootTable)}
      WHERE ${sql(selectorColumn)} = ${selector.value}
      ORDER BY ${sql(rootIdColumn)}
      LIMIT ${effectiveLimit}
    `;
    return rows.map((row) => row.subject_opaque_id);
  }

  if (selector.kind === "enum_column") {
    const rows = await sql<{ subject_opaque_id: string }[]>`
      SELECT ${sql(rootIdColumn)}::text AS subject_opaque_id
      FROM ${sql(appSchema)}.${sql(rootTable)}
      WHERE ${sql(selectorColumn)} = ANY(${selector.values}::text[])
      ORDER BY ${sql(rootIdColumn)}
      LIMIT ${effectiveLimit}
    `;
    return rows.map((row) => row.subject_opaque_id);
  }

  const cutoff = selector.before
    ? new Date(selector.before)
    : new Date((input.now ?? new Date()).getTime() - selector.older_than_days! * 24 * 60 * 60 * 1000);
  const rows = await sql<{ subject_opaque_id: string }[]>`
    SELECT ${sql(rootIdColumn)}::text AS subject_opaque_id
    FROM ${sql(appSchema)}.${sql(rootTable)}
    WHERE ${sql(selectorColumn)} < ${cutoff}
    ORDER BY ${sql(rootIdColumn)}
    LIMIT ${effectiveLimit}
  `;
  return rows.map((row) => row.subject_opaque_id);
}
