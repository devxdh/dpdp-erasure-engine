import { fail } from "@/errors";
import type { NoticeColumns } from "./config";

const textDecoder = new TextDecoder();

/**
 * Extracts the recipient email and display name from decrypted vault JSON bytes.
 *
 * @param decryptedPiiBytes - Decrypted JSON payload bytes.
 * @param noticeColumns - Configured email/name column mapping.
 * @param subjectId - Subject identifier used in error details.
 * @returns Normalized email and display name.
 * @throws {WorkerError} When the configured email column is absent or empty.
 */
export function extractNoticeRecipient(
  decryptedPiiBytes: Uint8Array,
  noticeColumns: NoticeColumns,
  subjectId: string
): { email: string; fullName: string } {
  const parsed = JSON.parse(textDecoder.decode(decryptedPiiBytes)) as Record<
    string,
    unknown
  >;
  const emailCandidate = parsed[noticeColumns.emailColumn];
  const email =
    typeof emailCandidate === "string" && emailCandidate.trim().length > 0
      ? emailCandidate.trim()
      : null;
  if (!email) {
    fail({
      code: "NOTIFICATION_EMAIL_MISSING",
      title: "Notification email address missing",
      detail: `Vault payload for root row ${subjectId} does not contain ${noticeColumns.emailColumn}.`,
      category: "integrity",
      retryable: false,
    });
  }

  const nameCandidate = noticeColumns.nameColumn
    ? parsed[noticeColumns.nameColumn]
    : undefined;
  const fullName =
    typeof nameCandidate === "string" && nameCandidate.trim().length > 0
      ? nameCandidate.trim()
      : "User";

  return {
    email,
    fullName,
  };
}