import type { Sql } from "@/types";
import { fail } from "@/errors";
import type { NoticeReservation } from "./types";
import type { VaultRecord } from "../helpers";

/**
 * Reserves a notification lease on a vault row and loads the wrapped DEK needed for decryption.
 *
 * @param sql - Postgres pool used for reservation.
 * @param engineSchema - Worker engine schema.
 * @param appSchema - Source application schema.
 * @param rootTable - Root table name.
 * @param subjectId - Root identifier.
 * @param now - Reservation timestamp.
 * @param leaseSeconds - Lease duration in seconds.
 * @returns Reservation outcome plus wrapped DEK when the notice should be sent.
 * @throws {WorkerError} When the vault is missing, already shredded, outside the notice window,
 * or leased elsewhere.
 */
export async function reserveNotice(
  sql: Sql,
  engineSchema: string,
  appSchema: string,
  rootTable: string,
  subjectId: string | number,
  now: Date,
  leaseSeconds: number
): Promise<NoticeReservation> {
  const normalizedSubjectId = String(subjectId);

  return sql.begin("isolation level repeatable read", async (tx) => {
    await tx.unsafe("SET LOCAL lock_timeout = '5s'");

    const [vault] = await tx<VaultRecord[]>`
      SELECT *
      FROM ${tx(engineSchema)}.pii_vault
      WHERE root_schema = ${appSchema}
        AND root_table = ${rootTable}
        AND root_id = ${normalizedSubjectId}
      FOR UPDATE
    `;

    if (!vault) {
      fail({
        code: "VAULT_NOT_FOUND",
        title: "Vault record not found",
        detail: `Vault record not found for ${appSchema}.${rootTable}#${normalizedSubjectId}.`,
        category: "validation",
        retryable: false,
      });
    }

    if (vault.shredded_at) {
      fail({
        code: "NOTIFICATION_SHREDDED",
        title: "Notification cannot be sent after shredding",
        detail: `Cannot dispatch notice for root row ${normalizedSubjectId}: the vault has already been shredded.`,
        category: "validation",
        retryable: false,
      });
    }

    if (vault.notification_sent_at) {
      return { action: "already_sent", vault };
    }

    if (now < new Date(vault.notification_due_at)) {
      return { action: "not_due", vault };
    }

    if (now >= new Date(vault.retention_expiry)) {
      fail({
        code: "NOTIFICATION_WINDOW_MISSED",
        title: "Notification window has closed",
        detail: `Cannot dispatch notice for root row ${normalizedSubjectId}: the retention deadline has already expired.`,
        category: "validation",
        retryable: false,
      });
    }

    if (
      vault.notification_lock_expires_at &&
      new Date(vault.notification_lock_expires_at) > now
    ) {
      fail({
        code: "NOTIFICATION_ALREADY_LEASED",
        title: "Notification is already leased",
        detail: `Notification for root row ${normalizedSubjectId} is already leased by another worker.`,
        category: "concurrency",
        retryable: true,
      });
    }

    const lockId = globalThis.crypto.randomUUID();
    const lockExpiry = new Date(now.getTime() + leaseSeconds * 1000);

    await tx`
      UPDATE ${tx(engineSchema)}.pii_vault
      SET notification_lock_id = ${lockId},
          notification_lock_expires_at = ${lockExpiry},
          updated_at = ${now}
      WHERE user_uuid_hash = ${vault.user_uuid_hash}
    `;

    const [keyRow] = await tx<{ encrypted_dek: Uint8Array }[]>`
      SELECT encrypted_dek
      FROM ${tx(engineSchema)}.user_keys
      WHERE user_uuid_hash = ${vault.user_uuid_hash}
      FOR UPDATE
    `;

    if (!keyRow) {
      fail({
        code: "KEY_RING_NOT_FOUND",
        title: "Key ring record not found",
        detail: `Key ring record not found for user hash ${vault.user_uuid_hash}.`,
        category: "integrity",
        retryable: false,
        fatal: true,
      });
    }

    return {
      action: "send",
      vault,
      encryptedDek: new Uint8Array(keyRow.encrypted_dek),
      lockId,
    };
  });
}

/**
 * Clears a notification lease after a failed notice attempt.
 *
 * @param sql - Postgres pool.
 * @param engineSchema - Worker engine schema.
 * @param userHash - Subject hash key.
 * @param lockId - Lease identifier to release.
 * @param now - Update timestamp.
 */
export async function clearNoticeLease(
  sql: Sql,
  engineSchema: string,
  userHash: string,
  lockId: string,
  now: Date
): Promise<void> {
  await sql`
    UPDATE ${sql(engineSchema)}.pii_vault
    SET notification_lock_id = NULL,
        notification_lock_expires_at = NULL,
        updated_at = ${now}
    WHERE user_uuid_hash = ${userHash}
      AND notification_lock_id = ${lockId}
  `;
}
