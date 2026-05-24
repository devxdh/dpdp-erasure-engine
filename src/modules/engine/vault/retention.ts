import type { RetentionRule } from "@/modules/config";
import type { SqlExecutor, Tsql } from "@/types";
import { assertIdentifier } from "@/utils";
import { resolveRetentionYears } from "../helpers";

/**
 * Inputs required to evaluate the dynamic legal retention policy.
 */
export interface RetentionEvaluationConfig {
  defualt_retention_years: number;
  root_id_column: string;
  retention_rule: readonly RetentionRule[];
  app_schema: string;
}

/**
 * Longest applicable retention window derived from physical evidence.
 */
export interface RetentionEvaluationResult {
  retentionYears: number;
  appliedRuleName: string;
  appliedRuleCitation: string;
}

interface ReturnTypeResolveRetentionWindow {
  retentionExpiry: Date;
  notificationDueAt: Date;
}

/**
 * Resolves retention and notice timestamps with Postgres time math when a live SQL handle exists.
 *
 * @param sql - SQL handle used to evaluate interval math.
 * @param now - Clock anchor for the lifecycle.
 * @param retentionYears - Selected retention period in years.
 * @param noticeWindowHours - Hours before shred when the notice should become due.
 * @returns Retention expiry and notification due timestamps.
 */
export async function resolveRetentionWindow(
  sql: SqlExecutor,
  now: Date,
  retentionYears: number,
  noticeWindowHours: number,
): Promise<ReturnTypeResolveRetentionWindow> {
  if (typeof sql !== "function") {
    const retentionExpiry = new Date(now);
    retentionExpiry.setUTCFullYear(retentionExpiry.getUTCFullYear() + retentionYears);

    const notificationDueAt = new Date(
      Math.max(
        now.getTime(),
        retentionExpiry.getTime() - noticeWindowHours * 60 * 60 * 1000
      )
    );

    return {
      retentionExpiry,
      notificationDueAt,
    };
  }

  const [window] = await sql<{ retention_expiry: Date; notification_due_at: Date }[]>`
    SELECT
      ${now}::timestamptz + MAKE_INTERVAL(years := ${retentionYears}) AS retention_expiry,
      GREATEST(
        ${now}::timestamptz,
        ${now}::timestamptz + MAKE_INTERVAL(years := ${retentionYears}) - MAKE_INTERVAL(hours := ${noticeWindowHours})
      ) AS notification_due_at
  `;

  return {
    retentionExpiry: window!.retention_expiry,
    notificationDueAt: window!.notification_due_at,
  };
}

/**
 * Evaluates configured evidence rules and selects the longest applicable retention window.
 *
 * @param tx - Active transaction used for consistent evidence reads.
 * @param subjectId - Root subject identifier being vaulted.
 * @param rules - Retention rules and default fallback parsed from worker config.
 * @param tenantId - Optional tenant discriminator for multi-tenant datasets.
 * @returns Highest retention duration and the rule that produced it.
 * @throws {WorkerError} When evidence table or column identifiers are unsafe.
 */
export async function evaluateRetention(
  tx: Tsql,
  subjectId: string | number,
  rules: RetentionEvaluationConfig,
  tenantId?: string
): Promise<RetentionEvaluationResult> {
  const rootIdColumn = assertIdentifier(rules.root_id_column, "graph root id column");
  let selectedYears = resolveRetentionYears(rules.defualt_retention_years);
  let selectedRuleName = "DEFAULT";
  let selectedRuleCitation = "Configured default_retention_years policy";

  for (const rule of rules.retention_rule) {
    for (const tableName of rule.if_has_data_in) {
      const safeTable = assertIdentifier(tableName, "retention rule evidence table");
      const tenantFilter = tenantId ? tx` AND tenant_id = ${tenantId}` : tx``;
      const [match] = await tx<{ exists: boolean }[]>`
        SELECT EXISTS(
          SELECT 1
          FROM ${tx(rules.app_schema)}.${tx(safeTable)}
          WHERE ${tx(rootIdColumn)} = ${subjectId}
          ${tenantFilter}
        ) AS exists
      `;

      if (match?.exists && rule.retention_years > selectedYears) {
        selectedYears = rule.retention_years;
        selectedRuleName = rule.rule_name;
        selectedRuleCitation = rule.legal_citation;
      }
    }
  }

  return {
    retentionYears: selectedYears,
    appliedRuleName: selectedRuleName,
    appliedRuleCitation: selectedRuleCitation,
  };
}