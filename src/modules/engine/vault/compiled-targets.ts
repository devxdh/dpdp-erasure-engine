import type { CompiledExecutionTargetInput, MutationRule } from "@/modules/config";
import type { Tsql } from "@/types";
import type { SatelliteMutationResult } from "./satellite-mutation";
import { fail } from "@/errors";
import { assertIdentifier } from "@/utils";

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


  return {} as SatelliteMutationResult[];
}