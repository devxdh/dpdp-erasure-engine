import type { Sql } from "@/types";
import { assertIdentifier } from "@/utils";
import type { CompiledExecutionTarget, WorkerConfig } from "@modules/config/validation";
import { fail } from "@/errors";

export interface IndexRequirement {
  schema: string;
  table: string;
  columns: string[];
  reason: string;
}

export interface IndexPreflightResult {
  checked: number,
  missing: IndexRequirement[]
}

interface IndexPrefixRow {
  exists: boolean;
}

interface ColumnExistsRow {
  exists: boolean;
}

function qualifiedTable(value: string, defaultSchema: string): { schema: string; table: string } {
  const parts = value.split(".");
  if (parts.length === 1) {
    return {
      schema: defaultSchema,
      table: assertIdentifier(parts[0]!, "table name"),
    };
  }

  if (parts.length === 2) {
    return {
      schema: assertIdentifier(parts[0]!, "table schema"),
      table: assertIdentifier(parts[1]!, "table name"),
    };
  }

  fail({
    code: "INDEX_PREFLIGHT_TABLE_INVALID",
    title: "Invalid index preflight table reference",
    detail: `Expected table or schema.table, received "${value}".`,
    category: "configuration",
    retryable: false,
    fatal: true,
  });
}

function addRequirement(
  requirements: Map<string, IndexRequirement>,
  requirement: IndexRequirement
): void {
  const safeRequirement: IndexRequirement = {
    schema: assertIdentifier(requirement.schema, "index requirement schema"),
    table: assertIdentifier(requirement.table, "index requirement schema"),
    columns: requirement.columns.map((column) => assertIdentifier(column, "index requirement schema")),
    reason: requirement.reason,
  }
  const key = `${safeRequirement.schema}.${safeRequirement.table}:${safeRequirement.columns.join(",")}`;
  requirements.set(key, safeRequirement);
}

function addCompiledTargetRequirements(
  requirements: Map<string, IndexRequirement>,
  target: CompiledExecutionTarget,
  defaultSchema: string
): void {
  const child = qualifiedTable(target.table, defaultSchema);
  if (target.child_columns.length > 0) {
    addRequirement(requirements, {
      ...child,
      columns: target.child_columns,
      reason: `compiled DAG child join for ${target.table}`,
    });
  }

  const primaryKeyColumns = target.primary_key_columns.length > 0 ? target.primary_key_columns : ["id"];
  addRequirement(requirements, {
    ...child,
    columns: primaryKeyColumns,
    reason: `compiled DAG bounded mutation identity for ${target.table}`,
  });

  if (!target.parent || target.parent_columns.length === 0) {
    return;
  }

  const parent = qualifiedTable(target.parent, defaultSchema);
  addRequirement(requirements, {
    ...parent,
    columns: target.parent_columns,
    reason: `compiled DAG parent join for ${target.table}`,
  });
}

/**
 * Builds the exact lookup/index contract required for safe runtime execution.
 *
 * @param config - DPO-attested worker configuration.
 * @returns Deduplicated index requirements for root, evidence, satellite, blob, and compiled-DAG lookups.
 */
export function collectIndexRequirements(config: WorkerConfig): IndexRequirement[] {
  const requirements = new Map<string, IndexRequirement>();
  const appSchema = config.database.app_schema;

  addRequirement(requirements, {
    schema: appSchema,
    table: config.graph.root_table,
    columns: [config.graph.root_id_column],
    reason: "root row lock and task subject lookup",
  });

  for (const rule of config.compliance_policy.retention_rules) {
    for (const table of rule.if_has_data_in) {
      addRequirement(requirements, {
        schema: appSchema,
        table,
        columns: [config.graph.root_id_column],
        reason: `retention evidence rule ${rule.rule_name}`,
      });
    }
  }

  for (const target of config.satellite_targets) {
    addRequirement(requirements, {
      schema: appSchema,
      table: target.table,
      columns: [target.lookup_column],
      reason: `satellite ${target.action} lookup`,
    });
  }

  for (const target of config.blob_targets) {
    if (target.lookup_column) {
      addRequirement(requirements, {
        schema: appSchema,
        table: target.table,
        columns: [target.lookup_column],
        reason: `blob target lookup for ${target.table}.${target.column}`,
      });
    }
  }

  for (const rule of config.rules ?? []) {
    for (const target of rule.targets) {
      addCompiledTargetRequirements(requirements, target, appSchema);
    }
  }

  return Array.from(requirements.values()).sort((left, right) =>
    `${left.schema}.${left.table}.${left.columns.join(".")}`.localeCompare(
      `${right.schema}.${right.table}.${right.columns.join(".")}`
    )
  );
}

async function hasIndexPrefix(
  sql: Sql,
  requirement: IndexRequirement
): Promise<boolean> {
  const [row] = await sql<IndexPrefixRow[]>`
    SELECT EXISTS (
      SELECT 1
      FROM pg_index AS idx
      JOIN pg_class AS table_class
        ON table_class.oid = idx.indrelid
      JOIN pg_namespace AS table_namespace
        ON table_namespace.oid = table_class.relnamespace
      JOIN LATERAL unnest(idx.indkey) WITH ORDINALITY AS indexed(attnum, ordinality)
        ON indexed.ordinality <= ${requirement.columns.length}
      JOIN pg_attribute AS attribute
        ON attribute.attrelid = table_class.oid
       AND attribute.attnum = indexed.attnum
      WHERE table_namespace.nspname = ${requirement.schema}
        AND table_class.relname = ${requirement.table}
        AND idx.indisvalid
        AND idx.indisready
        AND idx.indpred IS NULL
      GROUP BY idx.indexrelid
      HAVING array_agg(attribute.attname ORDER BY indexed.ordinality) = ${requirement.columns}
         OR array_agg(attribute.attname ORDER BY attribute.attname) = ${[...requirement.columns].sort()}
    ) AS exists
  `;

  return row?.exists ?? false;
}

async function tableHasColumn(
  sql: Sql,
  schema: string,
  table: string,
  column: string
): Promise<boolean> {
  const [row] = await sql<ColumnExistsRow[]>`
    SELECT EXISTS (
      SELECT 1
      FROM information_schema.columns
      WHERE table_schema = ${schema}
        AND table_name = ${table}
        AND column_name = ${column}
    ) AS exists
  `;
  return row?.exists ?? false;
}

async function collectTenantScopedRequirements(
  sql: Sql,
  requirements: IndexRequirement[]
): Promise<IndexRequirement[]> {
  const tenantRequirements: IndexRequirement[] = [];
  const seenTables = new Map<string, boolean>();

  for (const requirement of requirements) {
    if (requirement.columns.includes("tenant_id")) {
      continue;
    }
    if (
      requirement.reason.startsWith("root row lock") ||
      requirement.reason.startsWith("compiled DAG parent join")
    ) {
      continue;
    }

    const key = `${requirement.schema}.${requirement.table}`;
    let hasTenantId = seenTables.get(key);
    if (hasTenantId === undefined) {
      hasTenantId = await tableHasColumn(sql, requirement.schema, requirement.table, "tenant_id");
      seenTables.set(key, hasTenantId);
    }

    if (hasTenantId) {
      tenantRequirements.push({
        ...requirement,
        columns: [...requirement.columns, "tenant_id"],
        reason: `${requirement.reason} with tenant isolation`,
      });
    }
  }

  return tenantRequirements;
}

/**
 * Verifies that configured runtime lookups are backed by usable non-partial indexes.
 *
 * The worker can mutate safely only when root locks, retention evidence probes, satellite
 * batches, and compiled-DAG joins are index-backed. This preflight prevents a bad YAML from
 * creating table scans or broad lock pressure against very large tenant databases.
 *
 * @param sql - Postgres pool used for catalog inspection.
 * @param config - Parsed worker configuration.
 * @returns Requirement summary when every lookup is index-backed.
 * @throws {WorkerError} When one or more required indexes are missing.
 */
export async function assertIndexPreflight(
  sql: Sql,
  config: WorkerConfig
): Promise<IndexPreflightResult> {
  const baseRequirements = collectIndexRequirements(config);
  const requirements = [
    ...baseRequirements,
    ...await collectTenantScopedRequirements(sql, baseRequirements),
  ];
  const missing: IndexRequirement[] = [];

  for (const requirement of requirements) {
    if (!await hasIndexPrefix(sql, requirement)) {
      missing.push(requirement);
    }
  }

  if (missing.length > 0) {
    fail({
      code: "INDEX_PREFLIGHT_FAILED",
      title: "Required lookup indexes are missing",
      detail: `Detected ${missing.length} missing index requirement(s): ${missing
        .map((item) => `${item.schema}.${item.table}(${item.columns.join(", ")}) for ${item.reason}`)
        .join("; ")}`,
      category: "configuration",
      retryable: false,
      fatal: true,
      context: {
        checked: requirements.length,
        missing,
      },
    });
  }

  return {
    checked: requirements.length,
    missing,
  };
}