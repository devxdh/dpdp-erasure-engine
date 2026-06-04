import type { Logger } from "pino";

const PARAM_REDACTION = "[REDACTED]";

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function containsConfiguredPiiColumn(query: string, piiColumns: string[]): boolean {
  return piiColumns.some((column) => new RegExp(`\\b${escapeRegExp(column)}\\b`, "i").test(query));
}

/**
 * Produces redacted debug parameters for postgres.js query logging.
 *
 * When the SQL text references a configured PII column, every bound parameter is redacted. This
 * conservative policy avoids leaking values from `WHERE email = $1` or dynamic PII updates where
 * postgres.js exposes values only as a positional parameter array.
 *
 * @param query - SQL text produced by postgres.js.
 * @param parameters - Positional query parameters supplied by postgres.js.
 * @param piiColumns - Client-declared PII columns from `graph.root_pii_columns`.
 * @returns Redacted parameters safe for structured debug logs.
 */
export function redactSqlDebugParameters(
  query: string,
  parameters: readonly unknown[],
  piiColumns: readonly string[]
): unknown[] {
  if (parameters.length === 0) return [];

  return containsConfiguredPiiColumn(query, [...piiColumns])
    ? parameters.map(() => PARAM_REDACTION)
    : parameters.map((value) => {
      if (typeof value === "string" && value.length > 128) {
        return `${value.slice(0, 125)}...`;
      }
      return value;
    })
}

/**
 * Creates a postgres.js `debug` hook that logs SQL without leaking configured PII values.
 *
 * @param logger - Pino logger receiving structured query records.
 * @param piiColumns - Client-declared PII columns that trigger full parameter redaction.
 * @returns postgres.js-compatible debug callback.
 */
export function createRedactingSqlDebugLogger(
  logger: Logger,
  piiColumns: readonly string[]
) {
  return (_connection: unknown, query: string, parameters: unknown[]) => {
    logger.debug({
      query: query.replace(/\s+/g, " ").trim(),
      parameters: redactSqlDebugParameters(query, parameters, piiColumns)
    },
      "Postgres query executed"
    );
  }
}