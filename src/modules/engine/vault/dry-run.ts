import type { Sql } from "@/types";
import { buildVaultDryRunPlan, type RootMutationContext } from "./context";
import type { CompiledExecutionTargetInput } from "@/modules/config";
import type { VaultUserResult } from "../types";
import { resolveStaticExecutionPlan } from "./static-plan";
import { resolveRetentionWindow } from "./retention";
import { getVaultRecordByUserId } from "./store";

/**
 * Prepared inputs shared across vault dry-run evaluation.
 */
export interface PreparedVaultDryRunContext {
  appSchema: string;
  engineSchema: string;
  rootContext: RootMutationContext;
  defaultRetentionYears: number;
  noticeWindowHours: number;
  now: Date;
  tenantId?: string;
  userHash: string;
  compiledTargets?: CompiledExecutionTargetInput[];
}

/**
 * Executes the vault dry-run path without mutating state.
 *
 * @param sql - Primary SQL handle used for time math and optional vault lookup.
 * @param sqlReplica - Deprecated replica handle retained for API compatibility.
 * @param subjectId - Root subject identifier.
 * @param context - Prepared dry-run context.
 * @returns Dry-run vault result with the computed execution plan.
 */
export async function runVaultDryRun(
  sql: Sql,
  _sqlReplica: Sql | undefined,
  subjectId: string | number,
  context: PreparedVaultDryRunContext
): Promise<VaultUserResult> {
  const staticPlan = resolveStaticExecutionPlan(
    context.appSchema,
    context.rootContext,
    { compiledTargets: context.compiledTargets }
  );

  const dependencyCount = staticPlan.dependencyCount;
  const retention = {
    retentionYears: context.defaultRetentionYears,
    appliedRuleName: "DEFAULT",
    appliedRuleCitation: "Configured defaut_retention_years policy"
  };
  const { retentionExpiry, notificationDueAt } = await resolveRetentionWindow(
    sql,
    context.now,
    retention.retentionYears,
    context.noticeWindowHours
  )

  const existingVault =
    typeof sql === "function"
      ? await getVaultRecordByUserId(
        sql,
        context.engineSchema,
        context.appSchema,
        subjectId,
        context.rootContext.rootTable,
        context.tenantId
      )
      : null;

  return {
    action: "dry_run",
    userHash: context.userHash,
    dryRun: true,
    dependencyCount,
    retentionYears: dependencyCount === 0 ? null : retention.retentionYears,
    appliedRuleName: dependencyCount === 0 ? null : retention.appliedRuleName,
    appliedRuleCitation: dependencyCount === 0 ? null : retention.appliedRuleCitation,
    retentionExpiry: dependencyCount === 0 ? null : retentionExpiry.toISOString(),
    notificationDueAt: dependencyCount === 0 ? null : notificationDueAt.toISOString(),
    pseudonym: existingVault?.pseudonym ?? null,
    outboxEventType: dependencyCount === 0 ? "USER_HARD_DELETED" : "USER_VAULTED",
    plan: buildVaultDryRunPlan(
      context.appSchema,
      context.engineSchema,
      subjectId,
      context.rootContext,
      context.userHash,
      dependencyCount,
      retentionExpiry,
      notificationDueAt,
      retention.appliedRuleName
    ),
  };
}