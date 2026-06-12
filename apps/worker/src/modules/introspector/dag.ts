import { MAX_DEPTH } from "@/constants";
import type { CompileDagOptions, DagTarget, PotentialLogicalLink, QualifiedTable } from "./types";
import { fail } from "@/errors";
import { formatJoinCondition, parseQualifiedTable } from "./naming";
import { parseBuildCommand } from "typescript";

interface DagRow {
  constraint_schema: string;
  constraint_name: string;
  child_schema: string;
  child_table: string;
  parent_schema: string;
  parent_table: string;
  child_columns: string[];
  parent_columns: string[];
  depth: number;
}

interface ColumnRow {
  table_schema: string;
  table_name: string;
  column_name: string;
}

function toQualifiedTable(schema: string, table: string): QualifiedTable {
  return { schema, table };
}

function rootTarget(root: QualifiedTable): DagTarget {
  return {
    table: root,
    parentTable: null,
    constraintName: null,
    childColumns: [],
    parentColumns: [],
    depth: 0,
    fkCondition: "ROOT",
  };
}

/**
 * Compiles foreign-key dependencies from `information_schema` into a static DAG target list.
 *
 * The query is read-only, bounded by `maxDepth`, and scoped to the root table schema so
 * unrelated tenant/test schemas cannot slow or block compilation. Composite foreign keys are
 * preserved by aligning `key_column_usage.position_in_unique_constraint` with the referenced key columns.
 *
 * @param options - Database handle, root table, default schema, and recursion breaker.
 * @returns Root target plus dependent satellite tables with explicit join predicates.
 * @throws {WorkerError} If the depth breaker is invalid.
 */
export async function compileStaticDag(options: CompileDagOptions): Promise<DagTarget[]> {
  const maxDepth = options.maxDepth ?? MAX_DEPTH;
  if (!Number.isInteger(maxDepth) || maxDepth < 1 || maxDepth > MAX_DEPTH) {
    fail({
      code: "INTROSPECTOR_DEPTH_INVALID",
      title: "Invalid introspector depth",
      detail: "Static DAG maxDepth must be an integer between 1 and 32.",
      category: "validation",
      retryable: false,
      fatal: true,
      context: { maxDepth }
    });
  }

  const root = parseQualifiedTable(options.rootTable, options.defaultSchema);
  const rows = await options.sql<DagRow[]>`
    WITH RECURSIVE fk_columns AS (
      SELECT
        tc.constraint_schema,
        tc.constraint_name,
        kcu.table_schema AS child_schema,
        kcu.table_name AS child_table,
        pk.table_schema AS parent_schema,
        pk.table_name AS parent_table,
        kcu.column_name AS child_column,
        pk.column_name AS parent_column,
        kcu.ordinal_position
      FROM information_schema.table_constraints AS tc
      JOIN information_schema.key_column_usage AS kcu
        ON kcu.constraint_schema = tc.constraint_schema
       AND kcu.constraint_name = tc.constraint_name
       AND kcu.table_schema = tc.table_schema
       AND kcu.table_name = tc.table_name
      JOIN information_schema.referential_constraints AS rc
        ON rc.constraint_schema = tc.constraint_schema
       AND rc.constraint_name = tc.constraint_name
      JOIN information_schema.key_column_usage AS pk
        ON pk.constraint_schema = rc.unique_constraint_schema
       AND pk.constraint_name = rc.unique_constraint_name
       AND pk.ordinal_position = kcu.position_in_unique_constraint
      JOIN information_schema.constraint_column_usage AS ccu
        ON ccu.constraint_schema = tc.constraint_schema
       AND ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND kcu.table_schema = ${root.schema}
        AND ccu.table_schema = pk.table_schema
        AND ccu.table_name = pk.table_name
    ),
    fk_edges AS (
      SELECT
        constraint_schema,
        constraint_name,
        child_schema,
        child_table,
        parent_schema,
        parent_table,
        array_agg(child_column ORDER BY ordinal_position) AS child_columns,
        array_agg(parent_column ORDER BY ordinal_position) AS parent_columns
      FROM fk_columns
      GROUP BY
        constraint_schema,
        constraint_name,
        child_schema,
        child_table,
        parent_schema,
        parent_table
    ),
    graph AS (
      SELECT
        constraint_schema,
        constraint_name,
        child_schema,
        child_table,
        parent_schema,
        parent_table,
        child_columns,
        parent_columns,
        1 AS depth,
        ARRAY[parent_schema || '.' || parent_table, child_schema || '.' || child_table] AS visited
      FROM fk_edges
      WHERE parent_schema = ${root.schema}
        AND parent_table = ${root.table}

      UNION ALL

      SELECT
        edge.constraint_schema,
        edge.constraint_name,
        edge.child_schema,
        edge.child_table,
        edge.parent_schema,
        edge.parent_table,
        edge.child_columns,
        edge.parent_columns,
        graph.depth + 1 AS depth,
        graph.visited || (edge.child_schema || '.' || edge.child_table)
      FROM fk_edges AS edge
      JOIN graph
        ON edge.parent_schema = graph.child_schema
       AND edge.parent_table = graph.child_table
      WHERE graph.depth < ${maxDepth}
        AND NOT (edge.child_schema || '.' || edge.child_table) = ANY(graph.visited)
    )
    SELECT
      constraint_schema,
      constraint_name,
      child_schema,
      child_table,
      parent_schema,
      parent_table,
      child_columns,
      parent_columns,
      depth
    FROM graph
    ORDER BY depth ASC, child_schema ASC, child_table ASC, constraint_name ASC
  `;

  const targets = new Map<string, DagTarget>();
  targets.set(`${root.schema}.${root.table}`, rootTarget(root));

  for (const row of rows) {
    const table = toQualifiedTable(row.child_schema, row.child_table);
    const parentTable = toQualifiedTable(row.parent_schema, row.parent_table);
    const key = `${table.schema}.${table.table}:${row.constraint_schema}.${row.constraint_name}`;
    targets.set(key, {
      table,
      parentTable,
      constraintName: row.constraint_name,
      childColumns: row.child_columns,
      parentColumns: row.parent_columns,
      depth: row.depth,
      fkCondition: formatJoinCondition(parentTable, row.parent_columns, table, row.child_columns),
    });
  }

  return Array.from(targets.values()).sort((left, right) => {
    const byDepth = left.depth - right.depth;
    if (byDepth !== 0) {
      return byDepth;
    }
    return `${left.table.schema}.${left.table.table}`.localeCompare(`${right.table.schema}.${right.table.table}`);
  });
}

function physicalLinkKey(left: QualifiedTable, right: QualifiedTable, column: string): string {
  const [first, second] = [`${left.schema}.${left.table}`, `${right.schema}.${right.table}`].sort();
  return `${first}|${second}|${column}`;
}

/**
 * Finds likely unmodeled relationships by intersecting high-signal identifier column names.
 *
 * This pass is metadata-only. It does not mutate state and does not prove a relationship exists;
 * it surfaces tables that commonly act as ORM-managed or microservice-managed satellites without
 * physical foreign keys.
 *
 * @param options - Database handle, root table, and default schema.
 * @param physicalDag - FK DAG used to suppress already-modeled relationships.
 * @returns Potential logical links for human review in the generated YAML.
 */
export async function discoverPotentialLogicalLinks(
  options: Pick<CompileDagOptions, "sql" | "rootTable" | "defaultSchema">,
  physicalDag: readonly DagTarget[],
): Promise<PotentialLogicalLink[]> {
  const root = parseQualifiedTable(options.rootTable, options.defaultSchema);
  const rows = await options.sql<ColumnRow[]>`
    SELECT table_schema, table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = ${root.schema}
      AND table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY table_name ASC, ordinal_position ASC
  `;

  const physicalLinks = new Set<string>();
  for (const target of physicalDag) {
    if (!target.parentTable) {
      continue;
    }

    for (const column of [...target.childColumns, ...target.parentColumns]) {
      physicalLinks.add(physicalLinkKey(target.parentTable, target.table, column))
    }
  }

  const byColumn = new Map<string, QualifiedTable[]>();
  for (const row of rows) {
    const normalized = row.column_name.toLowerCase();
    if (!/^(?:user_id|account_id|customer_id|client_id|actor_id|user_uuid|member_id|subject_id|.*_user_id|target_email|user_email)$/.test(normalized)) {
      continue;
    }

    const existing = byColumn.get(row.column_name) ?? [];
    existing.push(toQualifiedTable(row.table_schema, row.table_name));
    byColumn.set(row.column_name, existing);
  }

  const links: PotentialLogicalLink[] = [];
  const emitted = new Set<string>();

  for (const [column, tables] of byColumn.entries()) {
    for (const table of tables) {
      // Explicitly link any orphan table that has an identity-like column to the root table
      if (table.schema === root.schema && table.table === root.table) {
        continue;
      }
      const key = physicalLinkKey(root, table, column);
      if (!physicalLinks.has(key) && !emitted.has(key)) {
        emitted.add(key);
        links.push({
          sourceTable: root,
          targetTable: table,
          column,
          reason: `Table exposes ${column} which conceptually maps to the root entity.`,
        });
      }
    }
    
    if (tables.length < 2) {
      continue;
    }

    for (let leftIndex = 0; leftIndex < tables.length; leftIndex += 1) {
      for (let rightIndex = leftIndex + 1; rightIndex < tables.length; rightIndex += 1) {
        const left = tables[leftIndex]!;
        const right = tables[rightIndex]!;
        const key = physicalLinkKey(left, right, column);
        if (physicalLinks.has(key) || emitted.has(key)) {
          continue;
        }

        emitted.add(key);
        links.push({
          sourceTable: left,
          targetTable: right,
          column,
          reason: `Both tables expose ${column} but no physical foreign key was found.`,
        });
      }
    }
  }

  return links;
}