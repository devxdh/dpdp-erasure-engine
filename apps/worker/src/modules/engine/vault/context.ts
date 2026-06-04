import type { BlobTarget, MutationRule, RootPiiColumns, SatelliteTarget } from "@modules/config";
import { generateHMACWithKey } from "@modules/crypto";
import { fail } from "@/errors";
import { assertIdentifier, quoteQualifiedIdentifier } from "@/utils";
import type { DryRunPlan, VaultUserOptions } from "../types";

/**
 * Root-table mutation configuration resolved from worker runtime options.
 */
export interface RootMutationContext {
  rootTable: string;
  rootIdColumn: string;
  rootPiiColumns: RootPiiColumns;
  satelliteTargets: SatelliteTarget[];
  blobTargets: BlobTarget[];
}

/**
 * Normalizes an arbitrary row value into the string form used by hashing and mutation logic.
 *
 * @param value - Database cell value.
 * @returns String form or `null` when the source is absent.
 */
export function normalizeRootRowValue(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }

  return String(value);
}

/**
 * Produces a human-readable dry-run plan describing the exact vault mutation sequence.
 *
 * @param appSchema - Client application schema.
 * @param engineSchema - Worker engine schema.
 * @param subjectId - Root subject identifier.
 * @param rootContext - Validated root-table mutation config.
 * @param userHash - Deterministic worker-side subject hash.
 * @param dependencyCount - Count of discovered dependencies.
 * @param retentionExpiry - Calculated retention expiry timestamp.
 * @param notificationDueAt - Calculated notice dispatch timestamp.
 * @param appliedRuleName - Retention rule selected for the subject.
 * @returns Dry-run plan explaining intended crypto and SQL actions.
 */
export function buildVaultDryRunPlan(
  appSchema: string,
  engineSchema: string,
  subjectId: string | number,
  rootContext: RootMutationContext,
  userHash: string,
  dependencyCount: number,
  retentionExpiry: Date,
  notificationDueAt: Date,
  appliedRuleName: string
): DryRunPlan {
  const rootTable = quoteQualifiedIdentifier(appSchema, rootContext.rootTable);
  const vaultTable = quoteQualifiedIdentifier(engineSchema, "pii_vault");
  const keyTable = quoteQualifiedIdentifier(engineSchema, "user_keys");
  const outboxTable = quoteQualifiedIdentifier(engineSchema, "outbox");
  const mutationColumns = Object.keys(rootContext.rootPiiColumns).join(", ");
  const action = dependencyCount === 0 ? "hard delete" : "vault";

  return {
    mode: "dry-run",
    summary: `Would ${action} root row ${subjectId} in ${appSchema}.${rootContext.rootTable} with worker hash ${userHash}.`,
    checks: [
      `Validate ${appSchema} and ${engineSchema} as trusted schema identifiers.`,
      `Load the DPO-attested static execution plan rooted at ${rootTable}.`,
      `Evaluate retention evidence and select rule ${appliedRuleName}.`,
      `Lock the target row in ${rootTable} before mutating it.`,
      "Write the outbox event atomically with the primary data mutation.",
    ],
    cryptoSteps:
      dependencyCount === 0
        ? ["No vaulting cryptography required because the root table has no dependent tables."]
        : [
          "Generate a one-time 32-byte DEK for the root entity.",
          "Encrypt the configured root PII payload with AES-256-GCM.",
          "Wrap the DEK with the worker KEK using envelope encryption.",
          "Mutate configured root PII columns with rule-driven masking/HMAC/nullification.",
        ],
    sqlSteps:
      dependencyCount === 0
        ? [
          "BEGIN ISOLATION LEVEL REPEATABLE READ;",
          `SELECT ... FROM ${rootTable} WHERE ${rootContext.rootIdColumn} = '${String(subjectId)}' FOR UPDATE;`,
          `DELETE FROM ${rootTable} WHERE ${rootContext.rootIdColumn} = '${String(subjectId)}';`,
          `INSERT INTO ${outboxTable} (...) VALUES (...);`,
          "COMMIT;",
        ]
        : [
          "BEGIN ISOLATION LEVEL REPEATABLE READ;",
          `SELECT ... FROM ${rootTable} WHERE ${rootContext.rootIdColumn} = '${String(subjectId)}' FOR UPDATE;`,
          `INSERT INTO ${vaultTable} (... retention_expiry='${retentionExpiry.toISOString()}', notification_due_at='${notificationDueAt.toISOString()}', applied_rule_name='${appliedRuleName}');`,
          `INSERT INTO ${keyTable} (...);`,
          `UPDATE ${rootTable} SET {${mutationColumns}} = <rule-driven values> WHERE ${rootContext.rootIdColumn} = '${String(subjectId)}';`,
          `INSERT INTO ${outboxTable} (...) VALUES (...);`,
          "COMMIT;",
        ],
  };
}

/**
 * Resolves and validate root mutation config from worker options.
 * 
 * @param options - Runtime vault options.
 * @returns Trusted root-table context ready for dynamic SQL interactions.
 * @throws Invokes `fail()` When mandatory config is missing or identifiers are unsafe.
 */
export function resolveRootContext(options: VaultUserOptions): RootMutationContext {
  if (!options.rootTable) {
    fail({
      code: "VAULT_ROOT_TABLE_MISSING",
      title: "Missing root table configuration",
      detail: "rootTable is required.",
      category: "configuration",
      retryable: false,
      fatal: true,
    })
  }

  if (!options.rootIdColumn) {
    fail({
      code: "VAULT_ROOT_ID_COLUMN_MISSING",
      title: "Missing root identifier configuration",
      detail: "rootIdColumn is required.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  if (!options.rootPiiColumns || Object.keys(options.rootPiiColumns).length === 0) {
    fail({
      code: "VAULT_ROOT_PII_COLUMNS_MISSING",
      title: "Missing root PII column mapping",
      detail: "rootPiiColumns is required and must contain at least one mutation rule.",
      category: "configuration",
      retryable: false,
      fatal: true,
    });
  }

  const rootTable = assertIdentifier(options.rootTable, "graph root table");
  const rootIdColumn = assertIdentifier(options.rootIdColumn, "graph root id column");

  const rootPiiColumns: RootPiiColumns = {};
  for (const [column, mutation] of Object.entries(options.rootPiiColumns)) {
    rootPiiColumns[assertIdentifier(column, "graph root pii column")] = mutation;
  }

  const satelliteTargets = (options.satelliteTargets ?? []).map((target) => ({
    ...target,
    table: assertIdentifier(target.table, "satellite table name"),
    lookup_column: assertIdentifier(target.lookup_column, "satellite lookup column"),
  }));
  const blobTargets = (options.blobTargets ?? []).map((target) => ({
    ...target,
    table: assertIdentifier(target.table, "blob target table name"),
    column: assertIdentifier(target.column, "blob target column name"),
    lookup_column: target.lookup_column
      ? assertIdentifier(target.lookup_column, "blob target lookup column")
      : undefined,
  }));

  return {
    rootTable,
    rootIdColumn,
    rootPiiColumns,
    satelliteTargets,
    blobTargets,
  };
}

/**
 * Builds a deterministic worker idempotency key for `USER_VAULTED`.
 *
 * @param options - Runtime vault options.
 * @param appSchema - Client application schema.
 * @param rootTable - Root table name.
 * @param rootIdColumn - Root identifier column.
 * @param subjectId - Subject identifier.
 * @returns Stable idempotency key for the vault event.
 */
export function buildHardDeleteEventIdempotencyKey(
  options: VaultUserOptions,
  appSchema: string,
  rootTable: string,
  rootIdColumn: string,
  subjectId: string | number
): string {
  return options.requestId
    ? `hard-delete:${options.requestId}`
    : `hard-delete:${appSchema}:${rootTable}:${rootIdColumn}:${String(subjectId)}`;
}

/**
 * Calculates the replacement value for one configured root PII column.
 *
 * @param mutation - Mutation rule to apply.
 * @param originalValue - Existing root-row value.
 * @param appSchema - Client application schema.
 * @param rootTable - Root table name.
 * @param column - Column being mutated.
 * @param hmacKey - Pre-imported worker HMAC key.
 * @returns Replacement scalar persisted back to the root row.
 */
export async function computeMutationValue(
  mutation: MutationRule,
  originalValue: unknown,
  appSchema: string,
  rootTable: string,
  column: string,
  hmacKey: CryptoKey
): Promise<string | null> {
  if (mutation === "STATIC_MASK") {
    return "[REDACTED]";
  }

  if (mutation === "NULLIFY") {
    return null;
  }

  const normalizedValue = normalizeRootRowValue(originalValue);
  if (normalizedValue === null) {
    return null;
  }

  return generateHMACWithKey(`${appSchema}:${rootTable}:${column}:${normalizedValue}`, hmacKey);
};

/**
 * Builds a deterministic worker idempotency key for `USER_VAULTED`.
 *
 * @param options - Runtime vault options.
 * @param appSchema - Client application schema.
 * @param rootTable - Root table name.
 * @param rootIdColumn - Root identifier column.
 * @param subjectId - Subject identifier.
 * @returns Stable idempotency key for the vault event.
 */
export function buildVaultEventIdempotencyKey(
  options: VaultUserOptions,
  appSchema: string,
  rootTable: string,
  rootIdColumn: string,
  subjectId: string | number
): string {
  return options.requestId
    ? `vault:${options.requestId}`
    : `vault:${appSchema}:${rootTable}:${rootIdColumn}:${String(subjectId)}`;
}

