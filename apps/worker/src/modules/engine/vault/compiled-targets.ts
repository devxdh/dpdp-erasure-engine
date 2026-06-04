import type { CompiledExecutionTargetInput, MutationRule } from "@modules/config";
import type { Tsql } from "@/types";
import { assertIdentifier, quoteIdentifier, quoteQualifiedIdentifier } from "@/utils";
import { fail } from "@/errors";
import { yieldWorkerEventLoop, type SatelliteMutationResult } from "./satellite-mutation";
import { computeMutationValue } from "./context";

const DEFAULT_COMPILED_TARGET_BATCH_SIZE = 1000;

interface QualifiedTarget {
  schema: string;
  table: string;
}

interface ParsedCompiledTarget {
  key: string;
  schema: string;
  table: string;
  parentKey: string | null;
  parentColumns: string[];
  childColumns: string[];
  primaryKeyColumns: string[];
  action?: "redact" | "hard_delete";
  mutationRules: Record<string, MutationRule>;
  depth: number;
}

interface CompiledTargetRow {
  row_ctid: string;
  row_key: string;
  [column: string]: unknown;
}

interface BulkMutationRow {
  rowCtid: string;
  rowKey: string;
  mutationValues: Record<string, string | null>;
}

function targetKey(target: QualifiedTarget): string {
  return `${target.schema}.${target.table}`;
}

function parseQualifiedTable(value: string, defaultSchema: string): QualifiedTarget {
  const parts = value.split(".");
  if (parts.length === 1) {
    return {
      schema: defaultSchema,
      table: assertIdentifier(parts[0]!, "compiled DAG target table"),
    };
  }

  if (parts.length === 2) {
    return {
      schema: assertIdentifier(parts[0]!, "compiled DAG target schema"),
      table: assertIdentifier(parts[1]!, "compiled DAG target table"),
    };
  }

  fail({
    code: "COMPILED_DAG_TABLE_INVALID",
    title: "Invalid compiled DAG table",
    detail: `Invalid compiled DAG table reference "${value}". Expected table or schema.table.`,
    category: "configuration",
    retryable: false,
    fatal: true,
  });
}

function parseQualifiedColumn(fragment: string): { table?: string; column: string } {
  const cleaned = fragment.trim().replace(/"/g, "");
  const parts = cleaned.split(".").map((part) => part.trim()).filter(Boolean);
  const column = assertIdentifier(parts.at(-1) ?? "", "compiled DAG join column");
  const table = parts.length >= 2 ? assertIdentifier(parts.at(-2)!, "compiled DAG join table") : undefined;
  return { table, column };
}

function parseRowKeyValues(rowKey: string, expectedLength: number, targetKey: string): string[] {
  try {
    const parsed = JSON.parse(rowKey);
    if (!Array.isArray(parsed) || parsed.length !== expectedLength || parsed.some((value) => typeof value !== "string")) {
      throw new Error("invalid row key shape");
    }
    return parsed;
  } catch (error) {
    fail({
      code: "COMPILED_DAG_ROW_KEY_INVALID",
      title: "Compiled DAG row key invalid",
      detail: `Compiled target ${targetKey} produced an invalid row identity.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: { cause: error instanceof Error ? error.message : String(error) },
    });
  }
}

function resolveJoinColumns(
  target: CompiledExecutionTargetInput,
  parent: QualifiedTarget,
  child: QualifiedTarget
): { parentColumns: string[]; childColumns: string[] } {
  const parentColumns = target.parent_columns ?? [];
  const childColumns = target.child_columns ?? [];
  if (parentColumns.length > 0 || childColumns.length > 0) {
    if (parentColumns.length !== childColumns.length || parentColumns.length === 0) {
      fail({
        code: "COMPILED_DAG_JOIN_COLUMNS_INVALID",
        title: "Invalid compiled DAG join columns",
        detail: `Compiled target ${target.table} must declare matching parent_columns and child_columns.`,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    return {
      parentColumns: parentColumns.map((column) => assertIdentifier(column, "compiled DAG parent column")),
      childColumns: childColumns.map((column) => assertIdentifier(column, "compiled DAG child column")),
    };
  }

  const join = target.join ?? target.fk_condition;
  if (!join || !join.includes("=")) {
    fail({
      code: "COMPILED_DAG_JOIN_MISSING",
      title: "Compiled DAG join missing",
      detail: `Compiled target ${target.table} must declare parent_columns/child_columns or a simple equality join.`,
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  const [leftRaw, rightRaw] = join.split("=", 2);
  const left = parseQualifiedColumn(leftRaw!);
  const right = parseQualifiedColumn(rightRaw!);

  if (left.table === parent.table && right.table === child.table) {
    return { parentColumns: [left.column], childColumns: [right.column] };
  }
  if (left.table === child.table && right.table === parent.table) {
    return { parentColumns: [right.column], childColumns: [left.column] };
  }

  return { parentColumns: [left.column], childColumns: [right.column] };
}

function buildChain(target: ParsedCompiledTarget, byKey: Map<string, ParsedCompiledTarget>): ParsedCompiledTarget[] {
  const chain: ParsedCompiledTarget[] = [];
  let cursor: ParsedCompiledTarget | undefined = target;
  while (cursor) {
    chain.push(cursor);
    cursor = cursor.parentKey ? byKey.get(cursor.parentKey) : undefined;
  }
  return chain;
}

function buildFromClause(chain: readonly ParsedCompiledTarget[]): string {
  const [target] = chain;
  if (!target) {
    fail({
      code: "COMPILED_DAG_CHAIN_EMPTY",
      title: "Compiled DAG chain empty",
      detail: "Compiled DAG target chain unexpectedly resolved to zero tables.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  const clauses = [
    `FROM ${quoteQualifiedIdentifier(target.schema, target.table)} AS t0`,
  ];

  for (let index = 0; index < chain.length - 1; index += 1) {
    const child = chain[index]!;
    const parent = chain[index + 1]!;
    const conditions = child.childColumns.map((childColumn, columnIndex) => {
      const parentColumn = child.parentColumns[columnIndex]!;
      return `t${index + 1}.${quoteIdentifier(parentColumn)} = t${index}.${quoteIdentifier(childColumn)}`;
    });

    clauses.push(
      `JOIN ${quoteQualifiedIdentifier(parent.schema, parent.table)} AS t${index + 1} ON ${conditions.join(" AND ")}`
    );
  }

  return clauses.join("\n");
}

function buildRowKeyExpression(alias: string, primaryKeyColumns: readonly string[]): string {
  return `jsonb_build_array(${primaryKeyColumns
    .map((column) => `${alias}.${quoteIdentifier(column)}::text`)
    .join(", ")})::text`;
}

function parseCompiledTargets(
  appSchema: string,
  rootTable: string,
  targets: readonly CompiledExecutionTargetInput[]
): Map<string, ParsedCompiledTarget> {
  const rootKey = targetKey({ schema: appSchema, table: rootTable });
  const parsed = new Map<string, ParsedCompiledTarget>();

  parsed.set(rootKey, {
    key: rootKey,
    schema: appSchema,
    table: rootTable,
    parentKey: null,
    parentColumns: [],
    childColumns: [],
    primaryKeyColumns: [],
    mutationRules: {},
    depth: 0,
  });

  for (const target of targets) {
    const child = parseQualifiedTable(target.table, appSchema);
    const key = targetKey(child);
    const parent = target.parent ? parseQualifiedTable(target.parent, appSchema) : null;
    const columns = parent ? resolveJoinColumns(target, parent, child) : { parentColumns: [], childColumns: [] };
    const mutationRules = target.mutation_rules ?? {};
    const primaryKeyColumns = (target.primary_key_columns ?? ["id"]).map((column) =>
      assertIdentifier(column, "compiled DAG primary key column")
    );

    const piiColumns = target.pii_columns ?? [];
    if (key !== rootKey && piiColumns.length > 0 && !target.action) {
      fail({
        code: "COMPILED_DAG_ACTION_MISSING",
        title: "Compiled DAG mutation action missing",
        detail: `Compiled target ${key} contains PII columns but has no mutation action.`,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    if (target.action === "redact" && Object.keys(mutationRules).length === 0) {
      fail({
        code: "COMPILED_DAG_MUTATION_RULES_MISSING",
        title: "Compiled DAG mutation rules missing",
        detail: `Compiled target ${key} declares redact action but no mutation_rules.`,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    parsed.set(key, {
      key,
      schema: child.schema,
      table: child.table,
      parentKey: parent ? targetKey(parent) : null,
      parentColumns: columns.parentColumns,
      childColumns: columns.childColumns,
      primaryKeyColumns,
      action: target.action,
      mutationRules,
      depth: 0,
    });
  }

  for (const target of parsed.values()) {
    const visited = new Set<string>();
    let depth = 0;
    let cursor: ParsedCompiledTarget | undefined = target;
    while (cursor?.parentKey) {
      if (visited.has(cursor.key)) {
        fail({
          code: "COMPILED_DAG_CYCLE",
          title: "Compiled DAG cycle detected",
          detail: `Compiled DAG target ${target.key} forms a parent cycle.`,
          category: "configuration",
          retryable: false,
          fatal: true,
        });
      }
      visited.add(cursor.key);
      depth += 1;
      cursor = parsed.get(cursor.parentKey);
      if (!cursor) {
        fail({
          code: "COMPILED_DAG_PARENT_MISSING",
          title: "Compiled DAG parent missing",
          detail: `Compiled DAG target ${target.key} references missing parent ${target.parentKey}.`,
          category: "configuration",
          retryable: false,
          fatal: true,
        });
      }
    }
    target.depth = depth;
  }

  return parsed;
}

function buildValuesPlaceholders(
  rowCount: number,
  columnCount: number,
  casts: Partial<Record<number, string>> = {}
): string {
  return Array.from({ length: rowCount }, (_, rowIndex) => {
    const offset = rowIndex * columnCount;
    const placeholders = Array.from({ length: columnCount }, (__, columnIndex) => {
      const cast = casts[columnIndex] ?? "";
      return `$${offset + columnIndex + 1}${cast}`;
    });
    return `(${placeholders.join(", ")})`;
  }).join(", ");
}

async function markProcessedRows(
  tx: Tsql,
  targetKeyValue: string,
  rows: readonly { rowKey: string }[]
): Promise<void> {
  if (rows.length === 0) {
    return;
  }

  const columnCount = 2;
  const values = buildValuesPlaceholders(rows.length, columnCount);
  const parameters = rows.flatMap((row) => [targetKeyValue, row.rowKey]);

  await tx.unsafe(
    `
      INSERT INTO pg_temp.compliance_compiled_target_rows (target_key, row_key)
      VALUES ${values}
      ON CONFLICT DO NOTHING
    `,
    parameters
  );
}

async function executeBulkHardDelete(
  tx: Tsql,
  target: ParsedCompiledTarget,
  rows: readonly CompiledTargetRow[]
): Promise<void> {
  if (rows.length === 0) {
    return;
  }

  const values = buildValuesPlaceholders(rows.length, 1, { 0: "::tid" });
  const parameters = rows.map((row) => row.row_ctid);

  await tx.unsafe(
    `
      DELETE FROM ${quoteQualifiedIdentifier(target.schema, target.table)} AS target
      USING (VALUES ${values}) AS source(row_ctid)
      WHERE target.ctid = source.row_ctid
    `,
    parameters
  );
  await markProcessedRows(
    tx,
    target.key,
    rows.map((row) => ({ rowKey: row.row_key }))
  );
}

async function executeBulkRedact(
  tx: Tsql,
  target: ParsedCompiledTarget,
  rows: readonly BulkMutationRow[],
  valueMutationColumns: readonly string[],
  nullifyColumns: readonly string[]
): Promise<void> {
  if (rows.length === 0 || (valueMutationColumns.length === 0 && nullifyColumns.length === 0)) {
    return;
  }

  const sourceColumns = ["row_ctid", "row_key", ...valueMutationColumns];
  const columnCount = sourceColumns.length;
  const values = buildValuesPlaceholders(rows.length, columnCount, { 0: "::tid" });
  const parameters = rows.flatMap((row) => [
    row.rowCtid,
    row.rowKey,
    ...valueMutationColumns.map((column) => row.mutationValues[column] ?? null),
  ]);
  const setClause = [
    ...valueMutationColumns.map((column) => `${quoteIdentifier(column)} = source.${quoteIdentifier(column)}`),
    ...nullifyColumns.map((column) => `${quoteIdentifier(column)} = NULL`),
  ].join(", ");
  const sourceAlias = sourceColumns.map((column) => quoteIdentifier(column)).join(", ");

  await tx.unsafe(
    `
      UPDATE ${quoteQualifiedIdentifier(target.schema, target.table)} AS target
      SET ${setClause}
      FROM (VALUES ${values}) AS source(${sourceAlias})
      WHERE target.ctid = source.row_ctid
    `,
    parameters
  );
  await markProcessedRows(tx, target.key, rows);
}

/**
 * Executes DPO-attested compiled DAG mutations without live recursive graph traversal.
 *
 * Each target is addressed through the precompiled parent/child join chain back to the locked
 * root row. The function selects bounded batches, mutates by transaction-local `ctid`, and
 * yields between batches so worker heartbeats and outbox dispatch are not starved.
 *
 * @param tx - Active repeatable-read transaction.
 * @param appSchema - Client application schema.
 * @param rootTable - Root table name.
 * @param rootIdColumn - Root identifier column.
 * @param subjectId - Locked root subject id.
 * @param compiledTargets - DPO-attested static execution targets.
 * @param hmacKey - Pre-imported worker HMAC key.
 * @param tenantId - Optional tenant discriminator applied to the root table.
 * @returns Mutation summaries for compiled targets that declare an action.
 */
export async function mutateCompiledTargets(
  tx: Tsql,
  appSchema: string,
  rootTable: string,
  rootIdColumn: string,
  subjectId: string | number,
  compiledTargets: readonly CompiledExecutionTargetInput[],
  hmacKey: CryptoKey,
  tenantId?: string
): Promise<SatelliteMutationResult[]> {
  if (compiledTargets.length === 0) {
    return [];
  }
  const byKey = parseCompiledTargets(appSchema, rootTable, compiledTargets);
  const rootKey = targetKey({ schema: appSchema, table: rootTable });
  const executableTargets = Array.from(byKey.values())
    .filter((target) => target.key !== rootKey && target.action)
    .sort((left, right) => right.depth - left.depth || left.key.localeCompare(right.key));
  if (executableTargets.length > 0) {
    await tx.unsafe(`
      CREATE TEMP TABLE IF NOT EXISTS pg_temp.compliance_compiled_target_rows (
        target_key TEXT NOT NULL,
        row_key TEXT NOT NULL,
        PRIMARY KEY (target_key, row_key)
      ) ON COMMIT DROP
    `);
  }

  const results: SatelliteMutationResult[] = [];
  for (const target of executableTargets) {
    const action = target.action;
    if (!action) {
      continue;
    }

    const chain = buildChain(target, byKey);
    const rootAlias = `t${chain.length - 1}`;
    const fromClause = buildFromClause(chain);
    const mutationColumns = Object.keys(target.mutationRules);
    const nullifyColumns = mutationColumns.filter((column) => target.mutationRules[column] === "NULLIFY");
    const valueMutationColumns = mutationColumns.filter((column) => target.mutationRules[column] !== "NULLIFY");
    if (target.primaryKeyColumns.length === 0) {
      fail({
        code: "COMPILED_DAG_PRIMARY_KEY_MISSING",
        title: "Compiled DAG primary key missing",
        detail: `Compiled target ${target.key} must define at least one primary_key_columns entry for bounded mutation.`,
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }
    const rowKeyExpression = buildRowKeyExpression("t0", target.primaryKeyColumns);
    let affectedRows = 0;

    while (true) {
      const selectColumns = mutationColumns.length > 0
        ? `, ${mutationColumns.map((column) => `t0.${quoteIdentifier(column)} AS ${quoteIdentifier(column)}`).join(", ")}`
        : "";
      const tenantFilter = tenantId ? ` AND ${rootAlias}.${quoteIdentifier("tenant_id")} = $2` : "";
      const targetKeyParameter = tenantId ? "$3" : "$2";
      const sqlText = `
        SELECT t0.ctid::text AS row_ctid, ${rowKeyExpression} AS row_key${selectColumns}
        ${fromClause}
        WHERE ${rootAlias}.${quoteIdentifier(rootIdColumn)} = $1${tenantFilter}
          AND NOT EXISTS (
            SELECT 1
            FROM pg_temp.compliance_compiled_target_rows AS processed
            WHERE processed.target_key = ${targetKeyParameter}
              AND processed.row_key = ${rowKeyExpression}
          )
        LIMIT ${DEFAULT_COMPILED_TARGET_BATCH_SIZE}
        FOR UPDATE OF t0 SKIP LOCKED
      `;
      const parameters = tenantId ? [subjectId, tenantId, target.key] : [subjectId, target.key];
      const rows = await tx.unsafe<CompiledTargetRow[]>(sqlText, parameters);

      if (rows.length === 0) {
        break;
      }

      if (action === "hard_delete") {
        for (const row of rows) {
          parseRowKeyValues(row.row_key, target.primaryKeyColumns.length, target.key);
        }
        await executeBulkHardDelete(tx, target, rows);
      } else {
        const mutationRows: BulkMutationRow[] = [];
        for (const row of rows) {
          const mutationValues: Record<string, string | null> = {};
          for (const [column, mutation] of Object.entries(target.mutationRules)) {
            mutationValues[column] = await computeMutationValue(
              mutation,
              row[column],
              appSchema,
              target.table,
              column,
              hmacKey
            );
          }

          parseRowKeyValues(row.row_key, target.primaryKeyColumns.length, target.key);
          mutationRows.push({
            rowCtid: row.row_ctid,
            rowKey: row.row_key,
            mutationValues,
          });
        }
        await executeBulkRedact(tx, target, mutationRows, valueMutationColumns, nullifyColumns);
      }

      affectedRows += rows.length;
      await yieldWorkerEventLoop();
    }

    results.push({
      table: `${target.schema}.${target.table}`,
      action,
      affectedRows,
    });
  }

  return results;
}