/**
 * Dependency-graph discovery using PostgreSQL catalog metadata and recursive CTE traversal.
 */

import { assertIdentifier, quoteQualifiedIdentifier } from "@/utils";
import { fail } from "@/errors";
import type { SqlExecutor } from "@/types";

export interface DependencyNode {
  table_schema: string;
  table_name: string;
  column_name: string;
  parent_table: string;
  delete_action: "NO_ACTION" | "RESTRICT" | "CASCADE" | "SET_NULL" | "SET_DEFAULT" | "UNKNOWN";
  depth: number;
}

export interface DependencyGraphOptions {
  maxDepth?: number;
  failOnUnsafeDeleteAction?: boolean;
}

const DEFAULT_MAX_DEPTH = 32;
const UNSAFE_DELETE_ACTIONS = new Set(["CASCADE", "SET_NULL", "SET_DEFAULT"]);

function normalizeDeleteAction(value: string): DependencyNode["delete_action"] {
  switch (value) {
    case "a":
      return "NO_ACTION";
    case "r":
      return "RESTRICT";
    case "c":
      return "CASCADE";
    case "n":
      return "SET_NULL";
    case "d":
      return "SET_DEFAULT";
    default:
      return "UNKNOWN";
  }
}

function resolveMaxDepth(input?: number): number {
  if (input === undefined) {
    return DEFAULT_MAX_DEPTH;
  }

  if (!Number.isInteger(input) || input < 1) {
    fail({
      code: "DPDP_GRAPH_MAX_DEPTH_INVALID",
      title: "Invalid graph max depth",
      detail: "maxDepth must be an integer greater than 0.",
      category: "validation",
      retryable: false,
    });
  }

  return input;
}

/**
 * Discovers the transitive foreign-key dependency graph for a root table.
 *
 * The recursive CTE tracks visited OIDs to prevent cyclic loops, fails closed when the configured
 * depth limit is reached, and rejects FK actions that would silently delete or rewrite dependent
 * records outside the worker's explicit vault/redaction logic.
 *
 * @param sql - Postgres pool or active transaction.
 * @param schema - Root table schema.
 * @param rootTable - Root table name.
 * @param options - Optional traversal controls.
 * @returns Ordered dependency nodes containing table/column lineage metadata.
 * @throws {WorkerError} When root table is missing, depth is invalid, unsafe FK actions are present,
 * or the traversal depth limit is reached.
 */
export async function getDependencyGraph(
  sql: SqlExecutor,
  schema: string,
  rootTable: string,
  options: DependencyGraphOptions = {}
): Promise<DependencyNode[]> {
  const safeSchema = assertIdentifier(schema, "schema name");
  const safeRootTable = assertIdentifier(rootTable, "table name");
  const maxDepth = resolveMaxDepth(options.maxDepth);
  const qualifiedRoot = quoteQualifiedIdentifier(safeSchema, safeRootTable);

  const [rootExists] = await sql<{ oid: string | null }[]>`
    SELECT to_regclass(${qualifiedRoot})::text AS oid
  `;

  if (!rootExists?.oid) {
    fail({
      code: "DPDP_GRAPH_ROOT_TABLE_MISSING",
      title: "Root table not found",
      detail: `Root table ${safeSchema}.${safeRootTable} does not exist.`,
      category: "validation",
      retryable: false,
      context: { schema: safeSchema, rootTable: safeRootTable },
    });
  }

  const result = await sql<
    Array<
      Omit<DependencyNode, "delete_action"> & {
        delete_action_code: string;
        table_oid: number;
        reached_limit: boolean;
      }
    >
  >`
    WITH RECURSIVE dependency_tree AS (
      SELECT
        connamespace::regnamespace::text AS table_schema,
        conrelid::regclass::text AS table_name,
        a.attname AS column_name,
        confrelid::regclass::text AS parent_table,
        c.confdeltype::text AS delete_action_code,
        conrelid::oid AS table_oid,
        ARRAY[confrelid::oid, conrelid::oid] AS path,
        1 AS depth,
        FALSE AS reached_limit
      FROM pg_constraint c
      JOIN pg_attribute a
        ON a.attrelid = c.conrelid
       AND a.attnum = ANY(c.conkey)
      WHERE c.contype = 'f'
        AND c.confrelid = to_regclass(${qualifiedRoot})

      UNION ALL

      SELECT
        child.connamespace::regnamespace::text AS table_schema,
        child.conrelid::regclass::text AS table_name,
        a.attname AS column_name,
        child.confrelid::regclass::text AS parent_table,
        child.confdeltype::text AS delete_action_code,
        child.conrelid::oid AS table_oid,
        dt.path || child.conrelid::oid AS path,
        dt.depth + 1 AS depth,
        dt.depth + 1 >= ${maxDepth} AS reached_limit
      FROM pg_constraint child
      JOIN pg_attribute a
        ON a.attrelid = child.conrelid
       AND a.attnum = ANY(child.conkey)
      JOIN dependency_tree dt
        ON child.confrelid = dt.table_oid
      WHERE child.contype = 'f'
        AND dt.depth < ${maxDepth}
        AND NOT child.conrelid::oid = ANY(dt.path)
    )
    SELECT DISTINCT ON (table_name, column_name)
      table_schema,
      table_name,
      column_name,
      parent_table,
      delete_action_code,
      depth,
      table_oid,
      reached_limit
    FROM dependency_tree
    ORDER BY table_name, column_name, depth ASC
  `;

  const graph = result.map(({ table_oid: _tableOid, reached_limit: _reachedLimit, delete_action_code, ...node }) => ({
    ...node,
    delete_action: normalizeDeleteAction(delete_action_code),
  }));

  if (options.failOnUnsafeDeleteAction !== false) {
    const unsafe = graph.find((node) => UNSAFE_DELETE_ACTIONS.has(node.delete_action));
    if (unsafe) {
      fail({
        code: "DPDP_GRAPH_UNSAFE_DELETE_ACTION",
        title: "Unsafe foreign-key delete action detected",
        detail: `Foreign key ${unsafe.table_name}.${unsafe.column_name} uses ON DELETE ${unsafe.delete_action}; the worker refuses to run because Postgres could mutate dependent data outside the explicit erasure plan.`,
        category: "integrity",
        retryable: false,
        fatal: true,
        context: {
          schema: safeSchema,
          rootTable: safeRootTable,
          table: unsafe.table_name,
          column: unsafe.column_name,
          deleteAction: unsafe.delete_action,
        },
      });
    }
  }

  if (result.some((row) => row.depth >= maxDepth || row.reached_limit)) {
    fail({
      code: "DPDP_GRAPH_DEPTH_LIMIT_REACHED",
      title: "Dependency graph depth limit reached",
      detail: `Dependency graph for ${safeSchema}.${safeRootTable} reached the safety limit of ${maxDepth}. Increase maxDepth before running destructive operations.`,
      category: "integrity",
      retryable: false,
      fatal: true,
      context: { schema: safeSchema, rootTable: safeRootTable, maxDepth },
    });
  }

  return graph;
}
