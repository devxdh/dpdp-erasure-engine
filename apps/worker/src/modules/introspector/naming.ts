import { assertIdentifier } from "@/utils";
import type { QualifiedTable } from "./types";

/**
 * Parses a CLI table reference into validated schema and table identifiers.
 * 
 * @param value - `table` or `schema.table` reference.
 * @param defaultSchema - Schema used when `value` omits one.
 * @returns Validated qualified table reference.
 */
export function parseQualifiedTable(value: string, defaultSchema: string = "public"): QualifiedTable {
  const parts = value.split(".");
  if (parts.length > 2 || parts.some((part) => part.trim() == "")) {
    assertIdentifier(value, "qualified table reference");
  }

  if (parts.length === 1) {
    return {
      schema: assertIdentifier(defaultSchema, "default schema"),
      table: assertIdentifier(parts[0]!, "root table"),
    }
  }

  return {
    schema: assertIdentifier(parts[0]!, "root schema"),
    table: assertIdentifier(parts[1]!, "root schema"),
  };
}

/**
 * Serializes a qualified table in audit-friendly `schema.table` form.
 *
 * @param table - Qualified table reference.
 * @returns Dot-qualified table name.
 */
export function formatQualifiedTable(table: QualifiedTable): string {
  return `${table.schema}.${table.table}`;
}

/**
 * Serializes one join predicate without quoting so the YAML remains readable for DPO review.
 *
 * @param parent - Referenced parent table.
 * @param parentColumns - Referenced parent columns.
 * @param child - Dependent child table.
 * @param childColumns - Foreign key columns on the child.
 * @returns Stable join condition string.
 */
export function formatJoinCondition(
  parent: QualifiedTable,
  parentColumns: string[],
  child: QualifiedTable,
  childColumns: string[]
): string {
  return parentColumns
    .map((parentColumn, index) => {
      const childColumn = childColumns[index] ?? childColumns[0] ?? "UNKNOWN";
      return `${formatQualifiedTable(parent)}.${parentColumn} = ${formatQualifiedTable(child)}.${childColumn}`;
    })
    .join(" AND ");
}

/**
 * Quotes a YAML scalar only when needed.
 *
 * @param value - Scalar value.
 * @returns YAML-safe scalar representation.
 */
export function yamlScalar(value: string): string {
  if (/^[A-Za-z0-9_.:-]+$/.test(value)) {
    return value;
  }

  return JSON.stringify(value);
}