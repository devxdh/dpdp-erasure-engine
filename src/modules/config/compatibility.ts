import type { WorkerConfig } from "./validation";
import { fail } from "@/errors";
import type { Sql } from "@/types";

interface SchemaColumnRow {
  table_name: string;
  column_name: string;
}

interface SchemaTableRow {
  table_name: string;
}

function formatColumn(tableName: string, columnName: string): string {
  return `${tableName}.${columnName}`;
}

function tableNameFromReference(reference: string, appSchema: string): string {
  const parts = reference.split(".");
  if (parts.length === 1) {
    return parts[0]!;
  }

  if (parts[0] !== appSchema) {
    return "";
  }

  return parts[1]!;
}

/**
 * Verifies that the live application schema satisfies every column/table reference in the
 * worker configuration before any task execution begins.
 *
 * This catches configuration drift such as missing root columns, satellite lookup columns,
 * masking-rule targets, and retention evidence tables at boot time instead of failing after
 * the worker has already leased work.
 *
 * @param sql - Postgres pool used for metadata inspection.
 * @param config - Parsed worker configuration.
 * @throws {WorkerError} When the application schema does not satisfy the worker configuration.
 */
export async function assertConfigSchemaCompatibility(
  sql: Sql,
  config: WorkerConfig
): Promise<void> {
  const rows = await sql<SchemaColumnRow[]>`
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = ${config.database.app_schema}
    ORDER BY table_name ASC, ordinal_position ASC
  `;
  const tableRows = await sql<SchemaTableRow[]>`
    SELECT table_name
    FROM information_schema.tables
    WHERE table_schema = ${config.database.app_schema}
      AND table_type = 'BASE TABLE'
    ORDER BY table_name ASC
  `;

  const columnsByTable = new Map<string, Set<string>>();
  for (const row of rows) {
    const existing = columnsByTable.get(row.table_name) ?? new Set<string>();
    existing.add(row.column_name);
    columnsByTable.set(row.table_name, existing);
  }

  const violations: string[] = [];
  const rootTable = config.graph.root_table;
  const rootColumns = columnsByTable.get(rootTable);

  if (!rootColumns) {
    violations.push(`missing root table ${config.database.app_schema}.${rootTable}`);
  } else {
    const requiredRootColumns = new Set<string>([
      config.graph.root_id_column,
      ...Object.keys(config.graph.root_pii_columns),
      ...config.satellite_targets.map((target) => target.lookup_column),
    ]);

    if (config.graph.notice_email_column) {
      requiredRootColumns.add(config.graph.notice_email_column);
    }

    if (config.graph.notice_name_column) {
      requiredRootColumns.add(config.graph.notice_name_column);
    }

    for (const column of requiredRootColumns) {
      if (!rootColumns.has(column)) {
        violations.push(
          `missing root column ${formatColumn(`${config.database.app_schema}.${rootTable}`, column)}`
        );
      }
    }
  }

  for (const target of config.satellite_targets) {
    const targetColumns = columnsByTable.get(target.table);
    if (!targetColumns) {
      violations.push(`missing satellite table ${config.database.app_schema}.${target.table}`);
      continue;
    }

    if (!targetColumns.has(target.lookup_column)) {
      violations.push(
        `missing satellite lookup column ${formatColumn(
          `${config.database.app_schema}.${target.table}`,
          target.lookup_column
        )}`
      );
    }

    for (const column of Object.keys(target.masking_rules ?? {})) {
      if (!targetColumns.has(column)) {
        violations.push(
          `missing satellite masking column ${formatColumn(
            `${config.database.app_schema}.${target.table}`,
            column
          )}`
        );
      }
    }
  }

  for (const rule of config.compliance_policy.retention_rules) {
    for (const tableName of rule.if_has_data_in) {
      if (!columnsByTable.has(tableName)) {
        violations.push(`missing retention evidence table ${config.database.app_schema}.${tableName}`);
      }
    }
  }

  const compiledRules = config.rules ?? [];
  if (compiledRules.length > 0) {
    const dagTables = new Set<string>();
    for (const rule of compiledRules) {
      for (const target of rule.targets) {
        const tableName = tableNameFromReference(target.table, config.database.app_schema);
        if (!tableName) {
          violations.push(`compiled DAG target ${target.table} is outside ${config.database.app_schema}`);
          continue;
        }

        dagTables.add(tableName);
        const targetColumns = columnsByTable.get(tableName);
        if (!targetColumns) {
          violations.push(`compiled DAG references missing table ${config.database.app_schema}.${tableName}`);
          continue;
        }

        for (const column of target.pii_columns) {
          if (!targetColumns.has(column)) {
            violations.push(
              `compiled DAG references missing PII column ${formatColumn(
                `${config.database.app_schema}.${tableName}`,
                column
              )}`
            );
          }
        }

        for (const column of Object.keys(target.mutation_rules ?? {})) {
          if (!targetColumns.has(column)) {
            violations.push(
              `compiled DAG references missing mutation column ${formatColumn(
                `${config.database.app_schema}.${tableName}`,
                column
              )}`
            );
          }
        }

        for (const column of target.child_columns) {
          if (!targetColumns.has(column)) {
            violations.push(
              `compiled DAG references missing child join column ${formatColumn(
                `${config.database.app_schema}.${tableName}`,
                column
              )}`
            );
          }
        }

        for (const column of target.primary_key_columns) {
          if (!targetColumns.has(column)) {
            violations.push(
              `compiled DAG references missing primary key column ${formatColumn(
                `${config.database.app_schema}.${tableName}`,
                column
              )}`
            );
          }
        }

        if (tableName !== config.graph.root_table && target.pii_columns.length > 0 && !target.action) {
          violations.push(
            `compiled DAG target ${config.database.app_schema}.${tableName} contains PII columns but has no mutation action`
          );
        }

        if (target.action === "redact" && (!target.mutation_rules || Object.keys(target.mutation_rules).length === 0)) {
          violations.push(
            `compiled DAG target ${config.database.app_schema}.${tableName} has redact action but no mutation_rules`
          );
        }

        if (tableName !== config.graph.root_table) {
          if (!target.parent) {
            violations.push(`compiled DAG target ${config.database.app_schema}.${tableName} is missing parent`);
          } else {
            const parentTableName = tableNameFromReference(target.parent, config.database.app_schema);
            const parentColumns = parentTableName ? columnsByTable.get(parentTableName) : undefined;
            if (!parentTableName) {
              violations.push(`compiled DAG parent ${target.parent} is outside ${config.database.app_schema}`);
            } else if (!parentColumns) {
              violations.push(`compiled DAG references missing parent table ${config.database.app_schema}.${parentTableName}`);
            } else {
              for (const column of target.parent_columns) {
                if (!parentColumns.has(column)) {
                  violations.push(
                    `compiled DAG references missing parent join column ${formatColumn(
                      `${config.database.app_schema}.${parentTableName}`,
                      column
                    )}`
                  );
                }
              }
            }

            if (
              target.parent_columns.length !== target.child_columns.length ||
              (target.parent_columns.length === 0 && !target.join && !target.fk_condition)
            ) {
              violations.push(
                `compiled DAG target ${config.database.app_schema}.${tableName} has incomplete join columns`
              );
            }
          }
        }
      }
    }

    for (const table of tableRows) {
      if (!dagTables.has(table.table_name)) {
        violations.push(
          `live table ${config.database.app_schema}.${table.table_name} is missing from compiled DAG`
        );
      }
    }
  }

  if (violations.length > 0) {
    fail({
      code: "CONFIG_SCHEMA_MISMATCH",
      title: "Worker config does not match the application schema",
      detail: `Detected ${violations.length} schema compatibility violation(s): ${violations.join("; ")}`,
      category: "configuration",
      retryable: false,
      fatal: true,
      context: {
        appSchema: config.database.app_schema,
        violations,
      },
    });
  }
}
