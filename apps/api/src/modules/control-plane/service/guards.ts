import { fail } from "@/errors";
import { canonicalJsonStringify } from "../hash";
import type { ErasureJobRow } from "../repository";
import type { CreateErasureRequestInput, WorkerOutboxEventInput } from "../schema";
import type {
  AllowedOutboxPredecessorStatus,
  VaultLifecyclePolicy,
  VaultLifecycleSchedule,
} from "./types";

const ALLOWED_OUTBOX_PREDECESSORS: Record<
  WorkerOutboxEventInput["event_type"],
  AllowedOutboxPredecessorStatus[]
> = {
  USER_VAULTED: ["EXECUTING"],
  USER_HARD_DELETED: ["EXECUTING"],
  NOTIFICATION_SENT: ["VAULTED"],
  SHRED_SUCCESS: ["NOTICE_SENT"],
};

/**
 * Canonical WORM payload stored in the audit ledger for every accepted worker event.
 *
 * @param input - Validated worker outbox envelope.
 * @returns Minimal canonical payload persisted in the audit ledger.
 */
export function buildOutboxPayload(input: WorkerOutboxEventInput) {
  return {
    request_id: input.request_id,
    subject_opaque_id: input.subject_opaque_id,
    event_timestamp: input.event_timestamp,
    payload: input.payload,
  };
}

/**
 * Extracts the Worker-computed schedule emitted by `USER_VAULTED`.
 *
 * @param payload - Nested worker payload persisted in the outbox event.
 * @returns Parsed notification/shred timestamps.
 * @throws {ApiError} When schedule timestamps are missing, malformed, or inverted.
 */
export function parseVaultLifecycleSchedule(payload: Record<string, unknown>): VaultLifecycleSchedule {
  const notificationCandidate =
    typeof payload.notification_due_at === "string"
      ? payload.notification_due_at
      : typeof payload.notificationDueAt === "string"
        ? payload.notificationDueAt
        : null;
  const shredCandidate =
    typeof payload.retention_expiry === "string"
      ? payload.retention_expiry
      : typeof payload.retentionExpiry === "string"
        ? payload.retentionExpiry
        : null;

  if (!notificationCandidate || !shredCandidate) {
    fail({
      code: "API_OUTBOX_VAULT_SCHEDULE_MISSING",
      title: "Vault schedule metadata missing",
      detail: "USER_VAULTED payload must include notification_due_at and retention_expiry.",
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  const notificationDueAt = new Date(notificationCandidate);
  const shredDueAt = new Date(shredCandidate);
  if (Number.isNaN(notificationDueAt.getTime()) || Number.isNaN(shredDueAt.getTime())) {
    fail({
      code: "API_OUTBOX_VAULT_SCHEDULE_INVALID",
      title: "Vault schedule metadata invalid",
      detail: "USER_VAULTED payload must carry valid ISO-8601 notification_due_at and retention_expiry timestamps.",
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  if (notificationDueAt.getTime() > shredDueAt.getTime()) {
    fail({
      code: "API_OUTBOX_VAULT_SCHEDULE_CONFLICT",
      title: "Vault schedule order invalid",
      detail: "notification_due_at cannot occur after retention_expiry.",
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }

  return {
    notificationDueAt,
    shredDueAt,
  };
}

/**
 * Extracts legal rule metadata emitted by `USER_VAULTED`.
 *
 * @param payload - Nested worker payload persisted in the outbox event.
 * @returns Parsed rule-name and citation pair.
 * @throws {ApiError} When metadata is missing or malformed.
 */
export function parseVaultLifecyclePolicy(payload: Record<string, unknown>): VaultLifecyclePolicy {
  const appliedRuleName =
    typeof payload.applied_rule_name === "string"
      ? payload.applied_rule_name
      : typeof payload.appliedRuleName === "string"
        ? payload.appliedRuleName
        : null;
  const appliedRuleCitation =
    typeof payload.applied_rule_citation === "string"
      ? payload.applied_rule_citation
      : typeof payload.appliedRuleCitation === "string"
        ? payload.appliedRuleCitation
        : null;

  if (!appliedRuleName || !appliedRuleCitation) {
    fail({
      code: "API_OUTBOX_VAULT_POLICY_MISSING",
      title: "Vault policy metadata missing",
      detail: "USER_VAULTED payload must include applied_rule_name and applied_rule_citation.",
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  return {
    appliedRuleName,
    appliedRuleCitation,
  };
}

/**
 * Verifies that worker-supplied outbox metadata still matches the immutable request contract.
 *
 * @param job - Persisted erasure job created during ingestion.
 * @param input - Worker outbox envelope under validation.
 * @throws {ApiError} When nested envelope fields or legal metadata diverge from the request.
 */
export function assertOutboxMetadata(job: ErasureJobRow, input: WorkerOutboxEventInput): void {
  const nestedRequestId = typeof input.payload.request_id === "string" ? input.payload.request_id : null;
  const nestedSubjectOpaqueId =
    typeof input.payload.subject_opaque_id === "string" ? input.payload.subject_opaque_id : null;
  const nestedEventTimestamp =
    typeof input.payload.event_timestamp === "string" ? input.payload.event_timestamp : null;
  const triggerSource = typeof input.payload.trigger_source === "string" ? input.payload.trigger_source : null;
  const actorOpaqueId =
    typeof input.payload.actor_opaque_id === "string" ? input.payload.actor_opaque_id : null;
  const legalFramework =
    typeof input.payload.legal_framework === "string" ? input.payload.legal_framework : null;
  const appliedRuleName =
    typeof input.payload.applied_rule_name === "string" ? input.payload.applied_rule_name : null;
  const appliedRuleCitation =
    typeof input.payload.applied_rule_citation === "string" ? input.payload.applied_rule_citation : null;

  if (nestedRequestId !== input.request_id || nestedSubjectOpaqueId !== input.subject_opaque_id) {
    fail({
      code: "API_OUTBOX_ENVELOPE_MISMATCH",
      title: "Outbox envelope mismatch",
      detail: "Nested outbox payload identifiers must match the signed worker envelope.",
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }

  if (nestedEventTimestamp !== input.event_timestamp) {
    fail({
      code: "API_OUTBOX_TIMESTAMP_MISMATCH",
      title: "Outbox timestamp mismatch",
      detail: "Nested payload event_timestamp must match the outer outbox envelope.",
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }

  if (!triggerSource || !actorOpaqueId || !legalFramework || !appliedRuleName || !appliedRuleCitation) {
    fail({
      code: "API_OUTBOX_METADATA_MISSING",
      title: "Outbox legal metadata missing",
      detail:
        "Worker outbox events must include trigger_source, actor_opaque_id, legal_framework, applied_rule_name, and applied_rule_citation.",
      status: 400,
      category: "validation",
      retryable: false,
    });
  }

  if (
    triggerSource !== job.trigger_source ||
    actorOpaqueId !== job.actor_opaque_id ||
    legalFramework !== job.legal_framework
  ) {
    fail({
      code: "API_OUTBOX_METADATA_CONFLICT",
      title: "Outbox legal metadata conflict",
      detail: "Worker outbox metadata does not match the immutable erasure request contract.",
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }

  if (
    job.applied_rule_name &&
    job.applied_rule_citation &&
    (appliedRuleName !== job.applied_rule_name || appliedRuleCitation !== job.applied_rule_citation)
  ) {
    fail({
      code: "API_OUTBOX_POLICY_METADATA_CONFLICT",
      title: "Outbox policy metadata conflict",
      detail: "Worker policy metadata does not match the persisted vault policy for this request.",
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }
}

/**
 * Rejects newly observed worker events that try to skip lifecycle stages.
 *
 * @param job - Persisted erasure job.
 * @param eventType - Candidate worker event type.
 * @throws {ApiError} When the event is illegal from the current state.
 */
export function assertAllowedOutboxTransition(
  job: ErasureJobRow,
  eventType: WorkerOutboxEventInput["event_type"]
): void {
  if (job.status === "CANCELLED" || job.status === "FAILED") {
    fail({
      code: "API_OUTBOX_JOB_TERMINAL",
      title: "Outbox event rejected for terminal job",
      detail: `Job ${job.id} is ${job.status} and cannot accept new worker events.`,
      status: 409,
      category: "concurrency",
      retryable: false,
    });
  }

  const allowedPredecessors = ALLOWED_OUTBOX_PREDECESSORS[eventType];
  if (!allowedPredecessors.includes(job.status)) {
    fail({
      code: "API_OUTBOX_EVENT_OUT_OF_ORDER",
      title: "Outbox event is out of order",
      detail: `Event ${eventType} is not valid while job ${job.id} is ${job.status}.`,
      status: 409,
      category: "integrity",
      retryable: false,
    });
  }
}

/**
 * Checks whether an idempotent create replay exactly matches the original request envelope.
 *
 * @param existing - Persisted erasure job.
 * @param input - Incoming create request.
 * @returns `true` when the replay is byte-for-byte equivalent at the domain level.
 */
export function isCreateRequestEquivalent(existing: ErasureJobRow, input: CreateErasureRequestInput): boolean {
  return (
    existing.subject_opaque_id === input.subject_opaque_id &&
    existing.trigger_source === input.trigger_source &&
    existing.actor_opaque_id === input.actor_opaque_id &&
    existing.legal_framework === input.legal_framework &&
    existing.request_timestamp.toISOString() === new Date(input.request_timestamp).toISOString() &&
    existing.tenant_id === (input.tenant_id ?? null) &&
    existing.cooldown_days === input.cooldown_days &&
    existing.shadow_mode === input.shadow_mode &&
    existing.webhook_url === (input.webhook_url ?? null)
  );
}

/**
 * Checks whether an outbox replay is equivalent to a previously committed event.
 *
 * @param existing - Persisted audit ledger row subset.
 * @param input - Incoming worker outbox event.
 * @param clientId - Authenticated worker client id.
 * @returns `true` when the replay exactly matches the stored event.
 */
export function isReplayEquivalent(
  existing: {
    client_id: string;
    event_type: string;
    payload: unknown;
    previous_hash: string;
    current_hash: string;
  },
  input: WorkerOutboxEventInput,
  clientId: string
): boolean {
  if (existing.client_id !== clientId) {
    return false;
  }

  if (existing.event_type !== input.event_type) {
    return false;
  }

  return canonicalJsonStringify(existing.payload) === canonicalJsonStringify(buildOutboxPayload(input));
}
