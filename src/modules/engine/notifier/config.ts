import { fail } from "@/errors";
import { assertIdentifier } from "@/utils";
import type { DispatchNoticeOptions } from "../types";

/**
 * Explicit root payload columns used to build the pre-erasure notice.
 */
export interface NoticeColumns {
  emailColumn: string;
  nameColumn?: string;
}

/**
 * Validates the short-lived notification lease duration.
 *
 * @param value - Optional lease duration in seconds.
 * @returns Lease duration in seconds.
 * @throws {WorkerError} When the value is non-integer or less than one second.
 */
export function resolveNotificationLeaseSeconds(value?: number): number {
  if (value === undefined) {
    return 120;
  }

  if (!Number.isInteger(value) || value < 1) {
    fail({
      code: "NOTIFICATION_LEASE_INVALID",
      title: "Invalid notification lease",
      detail: "notificationLeaseSeconds must be an integer greater than 0.",
      category: "validation",
      retryable: false,
    });
  }

  return value;
}

/**
 * Builds the deterministic mail idempotency key used by the transport.
 *
 * @param vault - Reserved vault row.
 * @returns Stable idempotency key for the notice delivery.
 */
export function buildNotificationIdempotencyKey(vault: {
  request_id: string | null;
  root_schema: string;
  root_table: string;
  root_id: string;
  notification_due_at: Date;
}): string {
  return vault.request_id
    ? `notice:${vault.request_id}:${vault.notification_due_at.toISOString()}`
    : `notice:${vault.root_schema}:${vault.root_table}:${vault.root_id}:${vault.notification_due_at.toISOString()}`;
}

/**
 * Resolves the root payload columns that should be used to build the legal notice.
 *
 * @param options - Runtime notice options.
 * @returns Validated email/name column mapping.
 * @throws {WorkerError} When no explicit or compatible email mapping can be derived.
 */
export function resolveNoticeColumns(options: DispatchNoticeOptions): NoticeColumns {
  if (options.noticeEmailColumn) {
    return {
      emailColumn: assertIdentifier(
        options.noticeEmailColumn,
        "graph notice email column"
      ),
      nameColumn: options.noticeNameColumn
        ? assertIdentifier(options.noticeNameColumn, "graph notice name column")
        : undefined,
    };
  }

  const configuredColumns = new Set(Object.keys(options.rootPiiColumns ?? {}));
  if (configuredColumns.size === 0) {
    return {
      emailColumn: "email",
      nameColumn: "full_name",
    };
  }

  if (configuredColumns.has("email")) {
    return {
      emailColumn: "email",
      nameColumn: configuredColumns.has("full_name") ? "full_name" : undefined,
    };
  }

  fail({
    code: "NOTIFICATION_EMAIL_COLUMN_MISSING",
    title: "Missing notice email column mapping",
    detail:
      "noticeEmailColumn is required when root_pii_columns does not contain 'email'. Configure graph.notice_email_column in compliance.worker.yml.",
    category: "configuration",
    retryable: false,
    fatal: true,
  });
}

/**
 * Produces the human-readable dry-run plan for a pre-erasure notice.
 *
 * @param appSchema - Source application schema.
 * @param engineSchema - Worker engine schema.
 * @param rootTable - Root table name.
 * @param subjectId - Root identifier.
 * @param userHash - Worker-side subject hash.
 * @param notificationDueAt - Notice eligibility timestamp.
 * @param retentionExpiry - Retention expiry timestamp.
 * @returns Dry-run plan describing the lease, decrypt, mail, and outbox flow.
 */
export function buildNoticeDryRunPlan(
  appSchema: string,
  engineSchema: string,
  rootTable: string,
  subjectId: string | number,
  userHash: string,
  notificationDueAt: Date,
  retentionExpiry: Date
) {
  return {
    mode: "dry-run" as const,
    summary: `Would attempt the pre-erasure notice for root row ${subjectId} (${userHash}).`,
    checks: [
      `Read ${engineSchema}.pii_vault using (${appSchema}, ${rootTable}, ${subjectId}) as the lookup key.`,
      `Verify that now is between notification_due_at (${notificationDueAt.toISOString()}) and retention_expiry (${retentionExpiry.toISOString()}).`,
      "Acquire a short notification lease before decrypting or sending mail.",
      "Use a deterministic mail idempotency key so retries do not duplicate sends.",
      "Write the outbox event only after the mailer succeeds.",
    ],
    cryptoSteps: [
      "Unwrap the stored DEK with the worker KEK.",
      "Decrypt the vaulted JSON payload in memory only.",
      "Null and overwrite temporary buffers after the email path completes.",
    ],
    sqlSteps: [
      `SELECT * FROM ${engineSchema}.pii_vault WHERE root_schema = '${appSchema}' AND root_table = '${rootTable}' AND root_id = '${subjectId}' FOR UPDATE;`,
      "UPDATE pii_vault SET notification_lock_id = '<uuid>', notification_lock_expires_at = '<lease-expiry>';",
      "SELECT encrypted_dek FROM user_keys WHERE user_uuid_hash = '<user-hash>';",
      "UPDATE pii_vault SET notification_sent_at = '<timestamp>', notification_lock_id = NULL, notification_lock_expires_at = NULL;",
      `INSERT INTO ${engineSchema}.outbox (...) VALUES (... 'NOTIFICATION_SENT' ...);`,
    ],
  };
}

