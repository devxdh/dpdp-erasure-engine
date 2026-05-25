import { fail } from "@/errors";
import { getLogger } from "@/utils";
import type { Sql } from "@/types";
import { countPendingBlobObjectsForUser, shredBlobObjects } from "./blob";
import type { ShredUserOptions, ShredUserResult } from "./types";
import { DESTROYED_PII_SENTINEL, enqueueOutboxEvent, resolveSchemas } from "./helpers";
import { getVaultRecordByUserId } from "./vault/store";

const logger = getLogger({ component: "shredder" });

function buildShredDryRunPlan(
  appSchema: string,
  engineSchema: string,
  rootTable: string,
  subjectId: string | number,
  userHash: string,
  retentionExpiry: Date
) {
  return {
    mode: "dry-run" as const,
    summary: `Would crypto-shred root row ${subjectId} (${userHash}) in ${appSchema}.${rootTable} after ${retentionExpiry.toISOString()}.`,
    checks: [
      `Read ${engineSchema}.pii_vault using (${appSchema}, ${rootTable}, ${subjectId}) as the lookup key.`,
      "Confirm that retention_expiry has passed.",
      "Require a completed notification unless explicitly disabled.",
      "Delete the DEK and replace the vault payload in one transaction.",
    ],
    cryptoSteps: [
      "Delete the encrypted DEK from the key ring.",
      "Leave only non-PII metadata and a destroyed sentinel in the vault row.",
    ],
    sqlSteps: [
      "BEGIN ISOLATION LEVEL REPEATABLE READ;",
      `SELECT * FROM ${engineSchema}.pii_vault WHERE root_schema = '${appSchema}' AND root_table = '${rootTable}' AND root_id = '${subjectId}' FOR UPDATE;`,
      `DELETE FROM ${engineSchema}.user_keys WHERE user_uuid_hash = '<user-hash>';`,
      `UPDATE ${engineSchema}.pii_vault SET encrypted_pii = '{"destroyed":true}', shredded_at = '<timestamp>';`,
      `INSERT INTO ${engineSchema}.outbox (...) VALUES (... 'SHRED_SUCCESS' ...);`,
      "COMMIT;",
    ],
  };
}

/**
 * Destroys the DEK and replaces vaulted ciphertext with a non-PII sentinel.
 *
 * The function enforces fail-closed shredding semantics:
 * 1. Retention must be fully elapsed.
 * 2. Pre-erasure notice must be sent unless explicitly bypassed.
 * 3. Key deletion and vault mutation happen atomically inside one repeatable-read transaction.
 *
 * @param sql - Postgres connection pool used for transactional shredding.
 * @param subjectId - Subject identifier from the root table.
 * @param options - Shredding overrides such as schema/table, dry-run mode, and clock injection.
 * @returns Structured shred result describing whether shredding executed, was skipped, or was simulated.
 * @throws {WorkerError} When retention/notice preconditions fail or key/vault invariants are broken.
 */
export async function shredUser(
  sql: Sql,
  subjectId: string | number,
  options: ShredUserOptions = {}
): Promise<ShredUserResult> {
  if ((typeof subjectId !== "string" && typeof subjectId !== "number") || String(subjectId).trim().length === 0) {
    fail({
      code: "SHREDDER_USER_ID_INVALID",
      title: "Invalid root identifier",
      detail: "subjectId must be a non-empty string or number.",
      category: "validation",
      retryable: false,
    });
  }

  const normalizedSubjectId = String(subjectId);
  const { appSchema, engineSchema } = resolveSchemas(options);
  const rootTable = options.rootTable ?? "users";
  const now = options.now ? new Date(options.now) : new Date();
  const requireNotification = options.requireNotification ?? true;

  const vault = await getVaultRecordByUserId(sql, engineSchema, appSchema, normalizedSubjectId, rootTable);
  if (!vault) {
    fail({
      code: "SHREDDER_VAULT_NOT_FOUND",
      title: "Vault record not found",
      detail: `Vault record not found for ${appSchema}.${rootTable}#${normalizedSubjectId}.`,
      category: "validation",
      retryable: false,
    });
  }

  if (options.dryRun) {
    return {
      action: "dry_run",
      userHash: vault.user_uuid_hash,
      dryRun: true,
      shreddedAt: vault.shredded_at ? vault.shredded_at.toISOString() : null,
      outboxEventType: "SHRED_SUCCESS",
      plan: buildShredDryRunPlan(
        appSchema,
        engineSchema,
        rootTable,
        normalizedSubjectId,
        vault.user_uuid_hash,
        new Date(vault.retention_expiry)
      ),
    };
  }

  return sql.begin("isolation level repeatable read", async (tx) => {
    await tx.unsafe("SET LOCAL lock_timeout = '5s'");
    const [transactionRow] = await tx<{ txid: string }[]>`
      SELECT txid_current()::text AS txid
    `;
    const postgresTransactionId = transactionRow?.txid ?? null;

    const [lockedVault] = await tx`
      SELECT *
      FROM ${tx(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = ${rootTable}
        AND root_id = ${normalizedSubjectId}
      FOR UPDATE
    `;

    if (!lockedVault) {
      fail({
        code: "SHREDDER_VAULT_LOST",
        title: "Vault record vanished during shredding",
        detail: `Vault record for ${appSchema}.${rootTable}#${normalizedSubjectId} disappeared during shredding.`,
        category: "concurrency",
        retryable: true,
      });
    }

    if (lockedVault.shredded_at) {
      return {
        action: "already_shredded",
        userHash: lockedVault.user_uuid_hash,
        dryRun: false,
        shreddedAt: new Date(lockedVault.shredded_at).toISOString(),
        outboxEventType: null,
      };
    }

    if (new Date(lockedVault.retention_expiry) > now) {
      fail({
        code: "SHREDDER_RETENTION_NOT_REACHED",
        title: "Retention window still active",
        detail: `Cannot shred root row ${normalizedSubjectId} before retention expiry (${new Date(lockedVault.retention_expiry).toISOString()}).`,
        category: "validation",
        retryable: false,
      });
    }

    if (requireNotification && !lockedVault.notification_sent_at) {
      fail({
        code: "SHREDDER_NOTICE_MISSING",
        title: "Pre-erasure notice missing",
        detail: `Cannot shred root row ${normalizedSubjectId} before the pre-erasure notice has been sent.`,
        category: "validation",
        retryable: false,
      });
    }

    const pendingBlobCount = await countPendingBlobObjectsForUser(
      tx,
      engineSchema,
      lockedVault.user_uuid_hash
    );
    if (pendingBlobCount > 0 && !options.hmacKey) {
      fail({
        code: "SHREDDER_BLOB_HMAC_KEY_MISSING",
        title: "Blob shred HMAC key missing",
        detail: "Blob deletion receipts require the worker HMAC key so raw S3 object paths never leave the VPC.",
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    const deletedKeys = await tx`
      DELETE FROM ${tx(engineSchema)}.user_keys
      WHERE user_uuid_hash = ${lockedVault.user_uuid_hash}
      RETURNING user_uuid_hash
    `;

    if (deletedKeys.length === 0) {
      fail({
        code: "SHREDDER_KEY_MISSING",
        title: "Key ring record missing",
        detail: `Cannot shred root row ${normalizedSubjectId}: no active key exists for hash ${lockedVault.user_uuid_hash}.`,
        category: "integrity",
        retryable: false,
        fatal: true,
      });
    }

    await tx`
      UPDATE ${tx(engineSchema)}.pii_vault
      SET encrypted_pii = ${tx.json(DESTROYED_PII_SENTINEL)},
          shredded_at = ${now},
          updated_at = ${now}
      WHERE user_uuid_hash = ${lockedVault.user_uuid_hash}
    `;

    const blobReceipts = options.hmacKey
      ? await shredBlobObjects(
        tx,
        engineSchema,
        lockedVault.user_uuid_hash,
        options.hmacKey,
        now,
        options.s3Client
      )
      : [];

    await enqueueOutboxEvent(
      tx,
      engineSchema,
      lockedVault.user_uuid_hash,
      "SHRED_SUCCESS",
      {
        request_id: lockedVault.request_id,
        subject_opaque_id: lockedVault.root_id,
        tenant_id: lockedVault.tenant_id || null,
        trigger_source: lockedVault.trigger_source,
        legal_framework: lockedVault.legal_framework,
        actor_opaque_id: lockedVault.actor_opaque_id,
        applied_rule_name: lockedVault.applied_rule_name,
        applied_rule_citation: lockedVault.applied_rule_citation,
        event_timestamp: now.toISOString(),
        root_schema: appSchema,
        root_table: rootTable,
        root_id: normalizedSubjectId,
        shredded_at: now.toISOString(),
        postgres_transaction_ids: postgresTransactionId ? [postgresTransactionId] : [],
        blob_receipts: blobReceipts,
      },
      lockedVault.request_id
        ? `shred:${lockedVault.request_id}`
        : `shred:${appSchema}:${rootTable}:${normalizedSubjectId}`,
      now
    );

    logger.info(
      {
        userHash: lockedVault.user_uuid_hash,
        rootTable,
        rootId: normalizedSubjectId,
      },
      "Root row crypto-shredded"
    );

    return {
      action: "shredded",
      userHash: lockedVault.user_uuid_hash,
      dryRun: false,
      shreddedAt: now.toISOString(),
      outboxEventType: "SHRED_SUCCESS",
      blobReceiptCount: blobReceipts.length,
    };
  });
}
