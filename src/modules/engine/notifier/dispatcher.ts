import type { Sql } from "@/types";
import type { MockMailer } from "./types";
import { getLogger, logError } from "@/utils";
import type { DispatchNoticeOptions, DispatchNoticeResult, WorkerSecrets } from "../types";
import { fail } from "@/errors";
import { assertWorkerSecrets, enqueueOutboxEvent, resolveSchemas } from "../helpers";
import { buildNoticeDryRunPlan, buildNotificationIdempotencyKey, resolveNoticeColumns, resolveNotificationLeaseSeconds } from "./config";
import { getVaultRecordByUserId } from "../vault/store";
import { clearNoticeLease, reserveNotice } from "./reservation";
import { base64ToBytes, sha256HexDigest } from "@/lib";
import { decryptGCMBytes, unwrapKey } from "@/modules/crypto";
import { extractNoticeRecipient } from "./payload";

const logger = getLogger({ component: "notifier" });
const NOTICE_TEMPLATE_VERSION = "dpdp-pre-erasure-v1";
const NOTICE_TEMPLATE_CANONICAL =
  "subject:Notice of Permanent Data Erasure\nbody:Dear {{full_name}},\\n\\nYour data will be permanently anonymized in 48 hours in compliance with the DPDP Act.";

/**
 * Dispatches the pre-erasure notice for a vaulted subject.
 *
 * Execution model:
 * - Reserves a short-lived notification lease on the vault row.
 * - Decrypts vaulted PII in memory only.
 * - Sends one deterministic idempotent email.
 * - Emits `NOTIFICATION_SENT` to outbox only after successful mail delivery.
 *
 * @param sql - Postgres pool used for lease and state transitions.
 * @param subjectId - Root identifier.
 * @param secrets - Worker cryptographic keys used for DEK unwrap/decrypt.
 * @param mailer - Injected mail transport.
 * @param options - Schema and runtime overrides.
 * @returns Notice dispatch result with lifecycle timestamps and outbox classification.
 * @throws {WorkerError} When vault state is invalid, lease is lost, or crypto checks fail.
 */
export async function dispatchPreErasureNotice(
  sql: Sql,
  subjectId: string | number,
  secrets: WorkerSecrets,
  mailer: MockMailer,
  options: DispatchNoticeOptions = {}
): Promise<DispatchNoticeResult> {
  if (
    (typeof subjectId !== "string" && typeof subjectId !== "number") ||
    String(subjectId).trim().length === 0
  ) {
    fail({
      code: "NOTIFICATION_USER_ID_INVALID",
      title: "Invalid root identifier",
      detail: "subjectId must be a non-empty string or number.",
      category: "validation",
      retryable: false,
    });
  }

  const normalizedSubjectId = String(subjectId);
  const { appSchema, engineSchema } = resolveSchemas(options);
  const rootTable = options.rootTable ?? "users";
  const { kek } = assertWorkerSecrets(secrets);
  const now = options.now ? new Date(options.now) : new Date();
  const leaseSeconds = resolveNotificationLeaseSeconds(options.notificationLeaseSeconds);
  const noticeColumns = resolveNoticeColumns(options);

  const vault = await getVaultRecordByUserId(
    sql,
    engineSchema,
    appSchema,
    normalizedSubjectId,
    rootTable
  );
  if (!vault) {
    fail({
      code: "VAULT_NOT_FOUND",
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
      retentionExpiry: vault.retention_expiry.toISOString(),
      notificationDueAt: vault.notification_due_at.toISOString(),
      notificationSentAt: vault.notification_sent_at
        ? vault.notification_sent_at.toISOString()
        : null,
      outboxEventType: "NOTIFICATION_SENT",
      plan: buildNoticeDryRunPlan(
        appSchema,
        engineSchema,
        rootTable,
        normalizedSubjectId,
        vault.user_uuid_hash,
        new Date(vault.notification_due_at),
        new Date(vault.retention_expiry)
      ),
    };
  }

  let encryptedDek: Uint8Array | null = null;
  let dek: Uint8Array | null = null;
  let encryptedPayload: Uint8Array | null = null;
  let decryptedPiiBytes: Uint8Array | null = null;
  let lockId: string | null = null;

  try {
    const reservation = await reserveNotice(
      sql,
      engineSchema,
      appSchema,
      rootTable,
      normalizedSubjectId,
      now,
      leaseSeconds
    );
    if (reservation.action === "already_sent") {
      return {
        action: "already_sent",
        userHash: reservation.vault.user_uuid_hash,
        dryRun: false,
        retentionExpiry: reservation.vault.retention_expiry.toISOString(),
        notificationDueAt: reservation.vault.notification_due_at.toISOString(),
        notificationSentAt:
          reservation.vault.notification_sent_at?.toISOString() ?? null,
        outboxEventType: null,
      };
    }

    if (reservation.action === "not_due") {
      return {
        action: "not_due",
        userHash: reservation.vault.user_uuid_hash,
        dryRun: false,
        retentionExpiry: reservation.vault.retention_expiry.toISOString(),
        notificationDueAt: new Date(
          reservation.vault.notification_due_at
        ).toISOString(),
        notificationSentAt: null,
        outboxEventType: null,
      };
    }

    lockId = reservation.lockId!;
    encryptedDek = reservation.encryptedDek!;
    dek = await unwrapKey(encryptedDek, kek);

    const payload = reservation.vault.encrypted_pii;
    if (payload.destroyed || !payload.data) {
      fail({
        code: "NOTIFICATION_PAYLOAD_DESTROYED",
        title: "Vault payload is no longer decryptable",
        detail: `Vault payload for root row ${normalizedSubjectId} no longer contains decryptable PII.`,
        category: "integrity",
        retryable: false,
      });
    }

    encryptedPayload = base64ToBytes(payload.data);
    decryptedPiiBytes = await decryptGCMBytes(encryptedPayload, dek);
    const { email, fullName } = extractNoticeRecipient(
      decryptedPiiBytes,
      noticeColumns,
      normalizedSubjectId
    );

    const message = {
      to: email,
      subject: "Notice of Permanent Data Erasure",
      body: `Dear ${fullName},\n\nYour data will be permanently anonymized in 48 hours in compliance with the DPDP Act.`,
      idempotencyKey: buildNotificationIdempotencyKey(reservation.vault),
    };
    const templateHash = await sha256HexDigest(NOTICE_TEMPLATE_CANONICAL);
    const deliveryReceipt = await mailer.sendEmail(message);

    await sql.begin("isolation level repeatable read", async (tx) => {
      await tx.unsafe("SET LOCAL lock_timeout = '5s'");

      const updated = await tx`
        UPDATE ${tx(engineSchema)}.pii_vault
        SET notification_sent_at = ${now},
            notification_lock_id = NULL,
            notification_lock_expires_at = NULL,
            updated_at = ${now}
        WHERE user_uuid_hash = ${reservation.vault.user_uuid_hash}
          AND notification_lock_id = ${lockId}
          AND notification_sent_at IS NULL
        RETURNING user_uuid_hash
      `;

      if (updated.length === 0) {
        fail({
          code: "NOTIFICATION_LEASE_LOST",
          title: "Notification lease lost",
          detail: `Notification lease for root row ${normalizedSubjectId} was lost before completion.`,
          category: "concurrency",
          retryable: true,
        });
      }

      await tx`
        INSERT INTO ${tx(engineSchema)}.notification_receipts (
          user_uuid_hash,
          request_id,
          idempotency_key,
          provider,
          provider_message_id,
          template_version,
          template_hash,
          sent_at,
          metadata,
          created_at
        ) VALUES (
          ${reservation.vault.user_uuid_hash},
          ${reservation.vault.request_id},
          ${message.idempotencyKey},
          ${deliveryReceipt?.provider ?? "custom"},
          ${deliveryReceipt?.providerMessageId ?? null},
          ${NOTICE_TEMPLATE_VERSION},
          ${templateHash},
          ${now},
          ${tx.json((deliveryReceipt?.metadata ?? {}) as import("postgres").JSONValue)},
          ${now}
        )
        ON CONFLICT (idempotency_key) DO NOTHING
      `;

      await enqueueOutboxEvent(
        tx,
        engineSchema,
        reservation.vault.user_uuid_hash,
        "NOTIFICATION_SENT",
        {
          request_id: reservation.vault.request_id,
          subject_opaque_id: reservation.vault.root_id,
          tenant_id: reservation.vault.tenant_id || null,
          trigger_source: reservation.vault.trigger_source,
          legal_framework: reservation.vault.legal_framework,
          actor_opaque_id: reservation.vault.actor_opaque_id,
          applied_rule_name: reservation.vault.applied_rule_name,
          applied_rule_citation: reservation.vault.applied_rule_citation,
          event_timestamp: now.toISOString(),
          root_schema: appSchema,
          root_table: rootTable,
          root_id: normalizedSubjectId,
          sent_at: now.toISOString(),
        },
        reservation.vault.request_id
          ? `notice:${reservation.vault.request_id}`
          : `notice:${appSchema}:${rootTable}:${normalizedSubjectId}`,
        now
      );
    });

    logger.info(
      {
        userHash: reservation.vault.user_uuid_hash,
        rootTable,
        rootId: normalizedSubjectId,
      },
      "Pre-erasure notice sent"
    );

    return {
      action: "sent",
      userHash: reservation.vault.user_uuid_hash,
      dryRun: false,
      retentionExpiry: reservation.vault.retention_expiry.toISOString(),
      notificationDueAt: reservation.vault.notification_due_at.toISOString(),
      notificationSentAt: now.toISOString(),
      outboxEventType: "NOTIFICATION_SENT",
    };
  } catch (error) {
    if (lockId && vault.user_uuid_hash) {
      try {
        await clearNoticeLease(sql, engineSchema, vault.user_uuid_hash, lockId, now);
      } catch (leaseError) {
        logError(
          logger,
          leaseError,
          "Failed to clear notification lease after notifier error",
          {
            userHash: vault.user_uuid_hash,
            rootTable,
            rootId: normalizedSubjectId,
          }
        );
      }
    }

    throw error;
  } finally {
    encryptedDek?.fill(0);
    dek?.fill(0);
    encryptedPayload?.fill(0);
    decryptedPiiBytes?.fill(0);
  }
}

