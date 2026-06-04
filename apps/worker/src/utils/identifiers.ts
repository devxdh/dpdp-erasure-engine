import { fail } from "@/errors";

const IDENTIFIER_PATTERN = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

/**
 * Validates an identifier used in dynamic SQL fragments.
 * 
 * @param name - Candidate identifier.
 * @param label - Human readable label used in validtation errors.
 * @returns Unchanged identifier when valid.
 * @throws {WorkerError} When `name` contains unsafe characters.
 */
export function assertIdentifier(name: string, label: string): string {
  if (!IDENTIFIER_PATTERN.test(name)) {
    fail({
      code: "IDENTIFIER_INVALID",
      title: "Invalid identifier",
      detail: `Invalid ${label}: "${name}". Only letters, numbers, and underscores are allowed.`,
      category: "validation",
      retryable: false,
      context: { label },
    });
  };
  return name;
}

/**
 * Quotes and escapes one SQL identifier.
 *
 * @param name - Untrusted identifier text.
 * @returns Safe quoted identifier.
 */
export function quoteIdentifier(name: string): string {
  return `"${name.replace(/"/g, "\"\"")}"`;
}

/**
 * Quotes a `schema.table` pair after validating both identifiers.
 *
 * @param schema - Schema identifier.
 * @param table - Table identifier.
 * @returns Fully qualified quoted identifier string.
 * @throws {WorkerError} When either identifier is invalid.
 */
export function quoteQualifiedIdentifier(schema: string, table: string): string {
  return `${quoteIdentifier(assertIdentifier(schema, "schema name"))}.${quoteIdentifier(assertIdentifier(table, "table name"))}`;
}

