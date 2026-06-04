import type { Sql } from "@/types";
import { CODE, fail } from "@/errors";
import {
  assertWorkerSecrets,
  createUserHash,
  resolveNoticeWindowHours,
  resolveRetentionYears,
  resolveSchemas
} from "../helpers";
import type { VaultUserOptions, VaultUserResult, WorkerSecrets } from "../types";
import { resolveRootContext } from "./context";
import { runVaultDryRun } from "./dry-run";
import { runVaultMutation } from "./execution";

/**
 * Vaults or hard-deletes a configured root entity under repeatable-read guarantees.
 *
 * @param sql - Primary Postgres pool used for transactional writes.
 * @param subjectId - Root identifier for the subject.
 * @param secrets - Worker KEK/HMAC key material.
 * @param options - Vault execution options, including graph, retention, tenancy, and dry-run flags.
 * @returns Vault execution result with lifecycle timestamps and outbox classification.
 * @throws {WorkerError} When validation, integrity, concurrency, or crypto preconditions fail.
 */
export async function vaultUser(
  sql: Sql,
  subjectId: string | number,
  secrets: WorkerSecrets,
  options: VaultUserOptions = {}
): Promise<VaultUserResult> {
  if (
    (typeof subjectId !== "string" && typeof subjectId !== "number") ||
    String(subjectId).trim().length === 0
  ) {
    fail({
      code: `VAULT_${CODE.USER_ID_INVALID}`
    });
  }

  const { appSchema, engineSchema } = resolveSchemas(options);
  const rootContext = resolveRootContext(options);
  const { kek, hmacKey } = assertWorkerSecrets(secrets);
  const defaultRetentionYears = resolveRetentionYears(options.defaultRetentionYears);
  const noticeWindowHours = resolveNoticeWindowHours(options.noticeWindowHours);
  const now = options.now ? new Date(options.now) : new Date();
  const tenantId = options.tenantId;
  const normalizedSubjectId = String(subjectId);
  const userHash = await createUserHash(
    subjectId,
    appSchema,
    rootContext.rootTable,
    hmacKey,
    tenantId
  );

  if (options.dryRun) {
    return runVaultDryRun(sql, options.sqlReplica, subjectId, {
      appSchema,
      engineSchema,
      rootContext,
      defaultRetentionYears,
      noticeWindowHours,
      now,
      tenantId,
      userHash,
      compiledTargets: options.compiledTargets,
    });
  }

  return runVaultMutation(sql, subjectId, {
    appSchema,
    engineSchema,
    rootContext,
    defaultRetentionYears,
    noticeWindowHours,
    now,
    tenantId,
    normalizedSubjectId,
    userHash,
    kek,
    hmacKey,
    options,
  });
}