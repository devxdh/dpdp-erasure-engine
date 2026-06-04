import { z } from "zod";
import { getWebhookUrlViolation } from "./webhook";

const isoDateTime = z.iso.datetime({ offset: true });
const emailLikePattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

function looksLikePhoneNumber(value: string): boolean {
  const normalized = value.replace(/[\s()-]/g, "");
  return /^\+?[0-9]{7,15}$/.test(normalized);
}

const opaqueIdentifierSchema = z
  .string()
  .trim()
  .min(1)
  .refine((value) => !emailLikePattern.test(value), "must be an opaque identifier, not an email address")
  .refine((value) => !looksLikePhoneNumber(value), "must be an opaque identifier, not a phone number");

export const erasureTriggerSourceSchema = z.enum([
  "USER_CONSENT_WITHDRAWAL",
  "PURPOSE_FULFILLED",
  "ADMIN_PURGE",
]);

/**
 * Lifecycle states of an erasure request managed by the Control Plane.
 */
export const erasureRequestStatusSchema = z.enum([
  "WAITING_COOLDOWN",
  "EXECUTING",
  "VAULTED",
  "NOTICE_SENT",
  "SHREDDED",
  "FAILED",
  "CANCELLED",
]);

export const outboxEventTypeSchema = z.enum([
  "USER_VAULTED",
  "NOTIFICATION_SENT",
  "SHRED_SUCCESS",
  "USER_HARD_DELETED",
]);

/**
 * Enterprise ingestion schema for `POST /api/v1/erasure-requests`.
 */
export const createErasureRequestSchema = z
  .object({
    subject_opaque_id: opaqueIdentifierSchema,
    idempotency_key: z.uuid(),
    trigger_source: erasureTriggerSourceSchema,
    actor_opaque_id: opaqueIdentifierSchema,
    legal_framework: z.string().min(1),
    request_timestamp: isoDateTime,
    tenant_id: z.string().min(1).optional(),
    cooldown_days: z.number().int().min(0).default(30),
    shadow_mode: z.boolean().default(false),
    webhook_url: z
      .url()
      .superRefine((value, ctx) => {
        const violation = getWebhookUrlViolation(value);
        if (violation) {
          ctx.addIssue({
            code: "custom",
            message: violation.detail,
          });
        }
      })
      .optional(),
  })
  .strict();

/**
 * Worker acknowledgement payload for task completion/failure.
 */
export const workerAckSchema = z
  .object({
    status: z.enum(["completed", "failed"]),
    result: z.unknown(),
  })
  .strict();

/**
 * Worker outbox envelope validated before WORM ledger ingestion.
 */
export const workerOutboxEventSchema = z
  .object({
    idempotency_key: z.string().min(1),
    request_id: z.uuid(),
    subject_opaque_id: z.string().min(1),
    event_type: outboxEventTypeSchema,
    payload: z.record(z.string(), z.unknown()),
    previous_hash: z
      .string()
      .refine(
        (value) => value === "GENESIS" || /^[0-9a-f]{64}$/i.test(value),
        "must be GENESIS or a 64-character hex digest"
      )
      .transform((value) => (value === "GENESIS" ? value : value.toLowerCase())),
    current_hash: z.string().regex(/^[0-9a-f]{64}$/i).transform((value) => value.toLowerCase()),
    event_timestamp: isoDateTime,
  })
  .strict();

export const workerHeaderSchema = z
  .object({
    "x-client-id": z.uuid(),
    authorization: z.string().regex(/^Bearer\s+\S+$/),
  });

export const workerSyncHeaderSchema = workerHeaderSchema.extend({
  "x-worker-config-hash": z.string().regex(/^[0-9a-fA-F]{64}$/),
  "x-worker-config-version": z.string().min(1).optional(),
  "x-worker-dpo-identifier": z.string().min(1).optional(),
});

export const requestIdParamSchema = z
  .object({
    requestId: z.uuid(),
  })
  .strict();

export const idempotencyKeyParamSchema = z
  .object({
    idempotency_key: z.uuid(),
  })
  .strict();

export const integrationProviderParamSchema = z
  .object({
    provider: z
      .string()
      .trim()
      .toLowerCase()
      .regex(/^[a-z0-9][a-z0-9_-]{1,63}$/, "provider must be a stable lowercase integration slug"),
  })
  .strict();

/**
 * Mapping from a GRC platform subject reference to the client's opaque subject id.
 *
 * Some GRC products can emit only an email/phone identifier. The service hashes that value
 * before storage; this schema permits the transient input while still requiring the Avantii
 * side of the mapping to remain opaque.
 */
export const externalSubjectMappingSchema = z
  .object({
    external_subject_id: z.string().trim().min(1),
    subject_opaque_id: opaqueIdentifierSchema,
    tenant_id: z.string().min(1).optional(),
  })
  .strict();

/**
 * Signed inbound webhook contract used by configurable GRC platforms such as OneTrust/Zendesk.
 *
 * The payload is intentionally strict. The external subject id may be an opaque id or a
 * provider-forced direct identifier; direct identifiers are hash-normalized before lookup.
 */
export const grcErasureWebhookSchema = z
  .object({
    event_id: z.string().trim().min(1),
    external_subject_id: z.string().trim().min(1),
    idempotency_key: z.uuid().optional(),
    trigger_source: erasureTriggerSourceSchema.default("USER_CONSENT_WITHDRAWAL"),
    actor_opaque_id: opaqueIdentifierSchema.optional(),
    legal_framework: z.string().min(1).default("DPDP_2023"),
    request_timestamp: isoDateTime.optional(),
    tenant_id: z.string().min(1).optional(),
    cooldown_days: z.number().int().min(0).default(30),
    shadow_mode: z.boolean().default(false),
    webhook_url: z
      .url()
      .superRefine((value, ctx) => {
        const violation = getWebhookUrlViolation(value);
        if (violation) {
          ctx.addIssue({
            code: "custom",
            message: violation.detail,
          });
        }
      })
      .optional(),
  })
  .strict();

export type CreateErasureRequestInput = z.infer<typeof createErasureRequestSchema>;
export type ErasureTriggerSource =
  | z.infer<typeof erasureTriggerSourceSchema>
  | "ONETRUST"
  | "JIRA"
  | "ZENDESK";
export type ErasureRequestStatus = z.infer<typeof erasureRequestStatusSchema>;
export type OutboxEventType = z.infer<typeof outboxEventTypeSchema>;
export type WorkerAckInput = z.infer<typeof workerAckSchema>;
export type WorkerOutboxEventInput = z.infer<typeof workerOutboxEventSchema>;
export type ExternalSubjectMappingInput = z.infer<typeof externalSubjectMappingSchema>;
export type GrcErasureWebhookInput = z.infer<typeof grcErasureWebhookSchema>;
