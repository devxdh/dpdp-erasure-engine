import type { Sql } from "@/types";
import type { VaultUserOptions, VaultUserResult } from "../types";
import { buildHardDeleteEventIdempotencyKey, buildVaultEventIdempotencyKey, computeMutationValue, normalizeRootRowValue, type RootMutationContext } from "./context";
import { importHmacKey, generateDEK, wrapKey, encryptGCMBytes } from "@/modules/crypto";
import { resolveStaticExecutionPlan } from "./static-plan";
import { getVaultRecordByUserId } from "./store";
import { finalizeVaultResult, ShadowModeRollback } from "./shadow";
import { fail } from "@/errors";
import { evaluateRetention, resolveRetentionWindow } from "./retention";
import { mutateCompiledTargets } from "./compiled-targets";
import { mutateSatelliteTargets } from "./satellite-mutation";
import { hasBlobTargetValues, protectBlobTargets } from "../blob";
import { createPseudonym, enqueueOutboxEvent } from "../helpers";
import { bytesToBase64, bytesToHex } from "@/lib";

const textEncoder = new TextEncoder();

/**
 * Prepared inputs shared across the live vault transaction.
 */
export interface PreparedVaultExecutionContext {
  appSchema: string;
  engineSchema: string;
  rootContext: RootMutationContext;
  defaultRetentionYears: number;
  noticeWindowHours: number;
  now: Date;
  tenantId?: string;
  normalizedSubjectId: string;
  userHash: string;
  kek: Uint8Array;
  hmacKey: Uint8Array;
  options: VaultUserOptions;
}

/**
 * Executes the live repeatable-read vault or hard-delete transaction.
 *
 * @param sql - Primary Postgres pool used for transactional writes.
 * @param subjectId - Root subject identifier.
 * @param context - Prepared vault execution context.
 * @returns Final vault result, or the rolled-back shadow result when shadow mode is enabled.
 */
export async function runVaultMutation(
  sql: Sql,
  subjectId: string | number,
  context: PreparedVaultExecutionContext
): Promise<VaultUserResult> {
  let dek: Uint8Array = new Uint8Array(0);
  let plainTextPiiBuffer: Uint8Array = new Uint8Array(0);
  let encryptedPiiBuffer: Uint8Array = new Uint8Array(0);
  const mutationHmacKey = await importHmacKey(context.hmacKey);

  try {
    try {
      return await sql.begin("ISOLATION LEVEL REPEATABLE READ", async (tx) => {
        await tx.unsafe("SET LOCAL lock_timeout = '5s'");
        const staticPlan = resolveStaticExecutionPlan(
          context.appSchema,
          context.rootContext,
          context.options,
        );

        const columnsToSelect = [
          context.rootContext.rootIdColumn,
          ...new Set([
            ...Object.keys(context.rootContext.rootPiiColumns),
            ...(staticPlan.source === "legacy_config"
              ? context.rootContext.satelliteTargets.map((target) => target.lookup_column)
              : []),
            ...context.rootContext.blobTargets
              .filter((target) => target.table === context.rootContext.rootTable)
              .map((target) => target.column),
          ]),
        ];

        const tenantFilter = context.tenantId ? tx`AND tenant_id = ${context.tenantId}` : tx``;

        const [lockedRootRow] = await tx<Record<string, unknown>[]>`
          SELECT ${tx(columnsToSelect)}
          FROM ${tx(context.appSchema)}.${tx(context.rootContext.rootTable)}
          WHERE ${tx(context.rootContext.rootIdColumn)} = ${subjectId}
          ${tenantFilter}
          FOR UPDATE
        `;

        const lockedVault = await getVaultRecordByUserId(
          tx,
          context.engineSchema,
          context.appSchema,
          subjectId,
          context.rootContext.rootTable,
          context.tenantId
        );

        if (lockedVault) {
          return finalizeVaultResult(
            {
              action: "already_vaulted",
              userHash: lockedVault.user_uuid_hash,
              dryRun: false,
              dependencyCount: lockedVault.dependency_count,
              retentionYears: null,
              appliedRuleName: lockedVault.applied_rule_name,
              appliedRuleCitation: lockedVault.applied_rule_citation,
              retentionExpiry: lockedVault.retention_expiry.toISOString(),
              notificationDueAt: lockedVault.notification_due_at.toISOString(),
              pseudonym: lockedVault.pseudonym,
              outboxEventType: null
            },
            context.options.shadowMode ?? false
          );
        }

        if (!lockedRootRow) {
          const hardDeleteIdempotencyKey = buildHardDeleteEventIdempotencyKey(
            context.options,
            context.appSchema,
            context.rootContext.rootTable,
            context.rootContext.rootIdColumn,
            subjectId
          );

          const hardDeleteEvents = await tx<{ id: string }[]>`
            SELECT id
            FROM ${tx(context.engineSchema)}.outbox
            WHERE idempotency_key = ${hardDeleteIdempotencyKey}
            LIMIT 1 
          `;

          if (hardDeleteEvents.length > 0) {
            return finalizeVaultResult(
              {
                action: "already_hard_deleted",
                userHash: context.userHash,
                dryRun: false,
                dependencyCount: 0,
                retentionYears: null,
                appliedRuleName: null,
                appliedRuleCitation: null,
                retentionExpiry: null,
                notificationDueAt: null,
                pseudonym: null,
                outboxEventType: null,
              },
              context.options.shadowMode ?? false
            );
          }

          fail({
            code: "VAULT_ROOT_ROW_NOT_FOUND",
            title: "Root row not found",
            detail: `Root row ${context.appSchema}.${context.rootContext.rootTable}#${context.normalizedSubjectId} disappeared before vaulting began.`,
            category: "validation",
            retryable: false,
          });
        }

        const dependencyCount = staticPlan.dependencyCount
        const retention = await evaluateRetention(
          tx,
          subjectId,
          {
            defualt_retention_years: context.defaultRetentionYears,
            root_id_column: context.rootContext.rootIdColumn,
            retention_rule: context.options.retentionRules ?? [],
            app_schema: context.appSchema
          },
          context.tenantId
        );

        const { retentionExpiry, notificationDueAt } = await resolveRetentionWindow(
          tx,
          context.now,
          retention.retentionYears,
          context.noticeWindowHours
        );

        const compiledMutations = await mutateCompiledTargets(
          tx,
          context.appSchema,
          context.rootContext.rootTable,
          context.rootContext.rootIdColumn,
          subjectId,
          staticPlan.targets,
          mutationHmacKey,
          context.tenantId
        );

        const manualSatelliteMutations = staticPlan.source === "legacy_config"
          ? await mutateSatelliteTargets(
            tx,
            context.appSchema,
            context.rootContext,
            lockedRootRow,
            mutationHmacKey,
            context.tenantId
          )
          : [];

        const satelliteMutations = { ...compiledMutations, ...manualSatelliteMutations };
        const hasBlobObjects = await hasBlobTargetValues({
          tx,
          appSchema: context.appSchema,
          engineSchema: context.engineSchema,
          rootTable: context.rootContext.rootTable,
          rootIdColumn: context.rootContext.rootIdColumn,
          rootId: subjectId,
          userHash: context.userHash,
          requestId: context.options.requestId,
          tenantId: context.tenantId,
          targets: context.rootContext.blobTargets,
          lockedRootRow,
          hmacKey: context.hmacKey,
          s3Client: context.options.s3Client,
          shadowMode: context.options.shadowMode,
          now: context.now,
        })

        if (dependencyCount === 0 && !hasBlobObjects) {
          const deleted = await tx`
            DELETE FROM ${tx(context.appSchema)}.${tx(context.rootContext.rootTable)}
            WHERE ${tx(context.rootContext.rootIdColumn)} = ${subjectId}
            ${tenantFilter}
            RETURNING ${tx(context.rootContext.rootIdColumn)}
          `;

          if (deleted.length === 0) {
            fail({
              code: "VAULT_ROOT_DELETE_FAILED",
              title: "Root row delete invariant failed",
              detail: `Root row ${context.appSchema}.${context.rootContext.rootTable}#${context.normalizedSubjectId} could not be deleted.`,
              category: "concurrency",
              retryable: true,
            });
          }

          await enqueueOutboxEvent(
            tx,
            context.engineSchema,
            context.userHash,
            "USER_HARD_DELETED",
            {
              request_id: context.options.requestId ?? null,
              subject_opaque_id: context.options.subjectOpaqueId ?? context.normalizedSubjectId,
              tenant_id: context.tenantId ?? null,
              trigger_source: context.options.triggerSource ?? null,
              legal_framework: context.options.legalFramework ?? null,
              actor_opaque_id: context.options.actorOpaqueId ?? null,
              applied_rule_name: retention.appliedRuleName,
              applied_rule_citation: retention.appliedRuleCitation,
              event_timestamp: context.now.toISOString(),
              root_schema: context.appSchema,
              root_table: context.rootContext.rootTable,
              root_id_column: context.rootContext.rootIdColumn,
              root_id: context.normalizedSubjectId,
              deleted_at: context.now.toISOString(),
              dependency_count: 0,
              execution_plan_source: staticPlan.source,
              satellite_mutations: satelliteMutations,
            },
            buildHardDeleteEventIdempotencyKey(
              context.options,
              context.appSchema,
              context.rootContext.rootTable,
              context.rootContext.rootIdColumn,
              subjectId
            ),
            context.now
          );

          return finalizeVaultResult(
            {
              action: "hard_deleted",
              userHash: context.userHash,
              dryRun: false,
              dependencyCount: 0,
              retentionYears: retention.retentionYears,
              appliedRuleName: retention.appliedRuleName,
              appliedRuleCitation: retention.appliedRuleCitation,
              retentionExpiry: null,
              notificationDueAt: null,
              pseudonym: null,
              outboxEventType: "USER_HARD_DELETED",
            },
            context.options.shadowMode ?? false
          );
        }

        const rootPiiPayload: Record<string, unknown> = {};
        const payloadColumns = new Set([
          ...Object.keys(context.rootContext.rootPiiColumns),
          ...context.rootContext.blobTargets
            .filter((target) => target.table === context.rootContext.rootTable)
            .map((target) => target.column),
        ]);
        for (const column of payloadColumns) {
          rootPiiPayload[column] = lockedRootRow[column] ?? null;
        }

        const salt = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
        const pseudonymSource =
          normalizeRootRowValue(
            rootPiiPayload[Object.keys(context.rootContext.rootPiiColumns)[0] ?? ""]
          ) ?? JSON.stringify(rootPiiPayload);
        const pseudonym = await createPseudonym(
          subjectId,
          pseudonymSource,
          salt,
          context.hmacKey
        );

        dek = generateDEK();
        const wrappedDEK = await wrapKey(dek, context.kek);
        plainTextPiiBuffer = textEncoder.encode(JSON.stringify(rootPiiPayload));
        encryptedPiiBuffer = await encryptGCMBytes(plainTextPiiBuffer, dek);
        const encryptedPiiPayload = {
          v: 1,
          data: bytesToBase64(encryptedPiiBuffer),
        };

        await tx`
          INSERT INTO ${tx(context.engineSchema)}.pii_vault (
              user_uuid_hash,
              request_id,
              tenant_id,
              root_schema,
              root_table,
              root_id,
              pseudonym,
              encrypted_pii,
              salt,
              dependency_count,
              trigger_source,
              legal_framework,
              actor_opaque_id,
              applied_rule_name,
              applied_rule_citation,
              retention_expiry,
              notification_due_at,
              created_at,
              updated_at
            )
            VALUES (
              ${context.userHash},
              ${context.options.requestId ?? null},
              ${context.tenantId ?? ""},
              ${context.appSchema},
              ${context.rootContext.rootTable},
              ${context.normalizedSubjectId},
              ${pseudonym},
              ${tx.json(encryptedPiiPayload)},
              ${salt},
              ${dependencyCount},
              ${context.options.triggerSource ?? null},
              ${context.options.legalFramework ?? null},
              ${context.options.actorOpaqueId ?? null},
              ${retention.appliedRuleName},
              ${retention.appliedRuleCitation},
              ${retentionExpiry},
              ${notificationDueAt},
              ${context.now},
              ${context.now}
          )
        `;

        await tx`
          INSERT INTO ${tx(context.engineSchema)}.user_keys (user_uuid_hash, encrypted_dek, created_at)
          VALUES (${context.userHash}, ${wrappedDEK}, ${context.now})
        `;

        const blobProtection = await protectBlobTargets({
          tx,
          appSchema: context.appSchema,
          engineSchema: context.engineSchema,
          rootTable: context.rootContext.rootTable,
          rootIdColumn: context.rootContext.rootIdColumn,
          rootId: subjectId,
          userHash: context.userHash,
          requestId: context.options.requestId,
          tenantId: context.tenantId,
          targets: context.rootContext.blobTargets,
          lockedRootRow,
          hmacKey: context.hmacKey,
          s3Client: context.options.s3Client,
          shadowMode: context.options.shadowMode,
          now: context.now,
        });

        const rootMutationValues: Record<string, string | null> = {};
        for (const [column, mutation] of Object.entries(context.rootContext.rootPiiColumns)) {
          rootMutationValues[column] = await computeMutationValue(
            mutation,
            lockedRootRow[column],
            context.appSchema,
            context.rootContext.rootTable,
            column,
            mutationHmacKey
          );
        }
        Object.assign(rootMutationValues, blobProtection.rootColumnMasks);

        await tx`
          UPDATE ${tx(context.appSchema)}.${tx(context.rootContext.rootTable)}
          SET ${tx(rootMutationValues)}
          WHERE ${tx(context.rootContext.rootIdColumn)} = ${subjectId}
          ${tenantFilter}
        `;

        await enqueueOutboxEvent(
          tx,
          context.engineSchema,
          context.userHash,
          "USER_VAULTED",
          {
            request_id: context.options.requestId ?? null,
            subject_opaque_id: context.options.subjectOpaqueId ?? context.normalizedSubjectId,
            tenant_id: context.tenantId ?? null,
            trigger_source: context.options.triggerSource ?? null,
            legal_framework: context.options.legalFramework ?? null,
            actor_opaque_id: context.options.actorOpaqueId ?? null,
            applied_rule_name: retention.appliedRuleName,
            applied_rule_citation: retention.appliedRuleCitation,
            event_timestamp: context.now.toISOString(),
            root_schema: context.appSchema,
            root_table: context.rootContext.rootTable,
            root_id_column: context.rootContext.rootIdColumn,
            root_id: context.normalizedSubjectId,
            pseudonym,
            dependency_count: dependencyCount,
            retention_years: retention.retentionYears,
            retention_expiry: retentionExpiry.toISOString(),
            notification_due_at: notificationDueAt.toISOString(),
            vaulted_at: context.now.toISOString(),
            execution_plan_source: staticPlan.source,
            satellite_mutations: satelliteMutations,
            blob_protections: blobProtection.receipts,
          },
          buildVaultEventIdempotencyKey(
            context.options,
            context.appSchema,
            context.rootContext.rootTable,
            context.rootContext.rootIdColumn,
            subjectId
          ),
          context.now
        );

        return finalizeVaultResult(
          {
            action: "vaulted",
            userHash: context.userHash,
            dryRun: false,
            dependencyCount,
            retentionYears: retention.retentionYears,
            appliedRuleName: retention.appliedRuleName,
            appliedRuleCitation: retention.appliedRuleCitation,
            retentionExpiry: retentionExpiry.toISOString(),
            notificationDueAt: notificationDueAt.toISOString(),
            pseudonym,
            outboxEventType: "USER_VAULTED",
            blobProtectionCount: blobProtection.receipts.length,
          },
          context.options.shadowMode ?? false
        );
      });
    } catch (error) {
      if (error instanceof ShadowModeRollback) {
        return error.result;
      }

      throw error;
    }
  } finally {
    dek.fill(0);
    plainTextPiiBuffer.fill(0);
    encryptedPiiBuffer.fill(0);
  }
};