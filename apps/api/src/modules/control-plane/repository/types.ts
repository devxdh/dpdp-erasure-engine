import type { Sql } from "@/types";
import type {
  CreateErasureRequestInput,
  ErasureRequestStatus,
  ErasureTriggerSource,
  OutboxEventType,
} from "../schema";
import type {
  BillingSubscriptionRow,
  InsertBillingEventInput,
  UpsertBillingSubscriptionInput,
} from "./billing";
import type {
  ProviderCompletionTargetRow,
  UpsertProviderCompletionTargetInput,
} from "./completion";

export type {
  BillingSubscriptionRow,
  InsertBillingEventInput,
  UpsertBillingSubscriptionInput,
  ProviderCompletionTargetRow,
  UpsertProviderCompletionTargetInput,
};

/**
 * Persisted worker client authorized to sync and push outbox events.
 */
export interface ClientRow {
  id: string;
  organization_id: string;
  name: string;
  display_name: string | null;
  worker_api_key_hash: string;
  current_key_id: string;
  webhook_signing_secret: string | null;
  webhook_previous_signing_secret: string | null;
  webhook_secret_rotated_at: Date | null;
  webhook_previous_secret_expires_at: Date | null;
  is_active: boolean;
  shadow_success_count: number;
  shadow_required_successes: number;
  live_mutation_enabled: boolean;
  live_mutation_enabled_at: Date | null;
  require_approved_config: boolean;
  rotated_at: Date;
  last_authenticated_at: Date | null;
  created_at: Date;
}

/**
 * Erasure lifecycle aggregate owned by the Control Plane.
 */
export interface ErasureJobRow {
  id: string;
  organization_id: string;
  client_id: string;
  idempotency_key: string;
  subject_opaque_id: string;
  trigger_source: ErasureTriggerSource;
  actor_opaque_id: string;
  legal_framework: string;
  applied_rule_name: string | null;
  applied_rule_citation: string | null;
  request_timestamp: Date;
  tenant_id: string | null;
  cooldown_days: number;
  shadow_mode: boolean;
  webhook_url: string | null;
  status: ErasureRequestStatus;
  vault_due_at: Date;
  notification_due_at: Date | null;
  shred_due_at: Date | null;
  shredded_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * Individual worker task leased by the Control Plane.
 */
export type TaskQueueType = "COMPILE_DAG" | "VAULT_USER" | "NOTIFY_USER" | "SHRED_USER";

export interface TaskQueueRow {
  id: string;
  organization_id: string;
  client_id: string;
  erasure_job_id: string;
  task_type: TaskQueueType;
  payload: Record<string, unknown>;
  status: "QUEUED" | "DISPATCHED" | "COMPLETED" | "FAILED" | "DEAD_LETTER";
  worker_client_name: string | null;
  leased_at: Date | null;
  lease_expires_at: Date | null;
  completed_at: Date | null;
  shadow_burn_in_recorded_at: Date | null;
  attempt_count: number;
  next_attempt_at: Date;
  dead_lettered_at: Date | null;
  error_text: string | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * Signed Certificate of Erasure persisted for terminal lifecycle events.
 */
export interface CertificateRow {
  request_id: string;
  organization_id: string;
  subject_opaque_id: string;
  method: string;
  legal_framework: string;
  shredded_at: Date;
  payload: Record<string, unknown>;
  signature_base64: string;
  public_key_spki_base64: string;
  key_id: string;
  algorithm: string;
  archived_at: Date | null;
  archive_status: "PENDING" | "LEASED" | "ARCHIVED" | "FAILED";
  archive_attempt_count: number;
  archive_next_attempt_at: Date;
  archive_lease_token: string | null;
  archive_lease_expires_at: Date | null;
  archive_last_error: string | null;
  archive_bucket: string | null;
  archive_object_key: string | null;
  archive_object_etag: string | null;
  archive_object_version_id: string | null;
  archive_retention_until: Date | null;
  archive_retention_days?: number;
  created_at: Date;
}

/**
 * WORM audit ledger row appended by worker outbox ingestion.
 */
export interface AuditLedgerRow {
  id: string;
  ledger_seq: number;
  organization_id: string;
  client_id: string;
  worker_idempotency_key: string;
  event_type: string;
  payload: unknown;
  previous_hash: string;
  current_hash: string;
  created_at: Date;
}

/**
 * Result of recomputing a client WORM ledger from genesis to head.
 */
export interface AuditLedgerVerificationResult {
  valid: boolean;
  checked: number;
  head: string;
  heads?: Record<string, string>;
  firstInvalid: {
    ledger_seq: number;
    expected_previous_hash?: string;
    expected_current_hash?: string;
    actual_previous_hash: string;
    actual_current_hash: string;
    reason: "previous_hash_mismatch" | "current_hash_mismatch" | "heartbeat_mismatch";
  } | null;
}

/**
 * Immutable usage/billing record derived from billable Control Plane events.
 */
export interface UsageEventRow {
  id: string;
  billing_key: string;
  organization_id: string;
  client_id: string;
  erasure_job_id: string | null;
  audit_ledger_id: string | null;
  event_type: string;
  units: number;
  metadata: Record<string, unknown>;
  occurred_at: Date;
  created_at: Date;
}

/**
 * Aggregated usage summary grouped by client and billable event type.
 */
export interface UsageSummaryRow {
  organization_id: string;
  client_name: string;
  event_type: string;
  total_units: number;
  event_count: number;
}

/**
 * Shared repository dependencies passed into feature-specific persistence helpers.
 */
export interface RepositoryContext {
  sql: Sql;
  schema: string;
  taskLeaseSeconds: number;
  taskMaxAttempts: number;
  taskBaseBackoffMs: number;
}

/**
 * Input required to create a new worker client and issue its initial raw token.
 */
export interface CreateClientInput {
  organizationId: string;
  name: string;
  displayName?: string | null;
  workerApiKeyHash: string;
  currentKeyId: string;
  requireApprovedConfig?: boolean;
  now: Date;
}

/**
 * Input required to rotate an existing worker client token.
 */
export interface RotateClientKeyInput {
  organizationId?: string;
  name: string;
  workerApiKeyHash: string;
  currentKeyId: string;
  now: Date;
}

/**
 * Input required to rotate a provider webhook signing secret without dropping in-flight events.
 */
export interface RotateClientWebhookSecretInput {
  organizationId: string;
  name: string;
  webhookSigningSecret: string;
  previousSecretGraceHours: number;
  now: Date;
}

/**
 * Result returned after creating a new erasure job and its initial worker task.
 */
export interface CreatedJobRecord {
  job: ErasureJobRow;
  task: TaskQueueRow;
}

/**
 * One row in a bulk administrator-approved purge submission.
 */
export interface BulkAdminPurgeJobInputRow {
  jobId: string;
  taskId: string;
  idempotencyKey: string;
  subjectOpaqueId: string;
  payload: Record<string, unknown>;
}

/**
 * Input for inserting many `ADMIN_PURGE` jobs in a single bounded transaction.
 */
export interface CreateBulkAdminPurgeJobsInput {
  organizationId: string;
  clientId: string;
  rows: BulkAdminPurgeJobInputRow[];
  actorOpaqueId: string;
  legalFramework: string;
  requestTimestamp: Date;
  tenantId?: string | null;
  shadowMode: boolean;
  now: Date;
}

/**
 * Summary returned after a bulk purge insert transaction.
 */
export interface BulkAdminPurgeInsertResult {
  inserted: number;
  duplicates: number;
  requestIds: string[];
}

/**
 * Internal worker failure envelope persisted on failed task acknowledgements.
 */
export interface TaskFailureEnvelope {
  error?: {
    retryable?: boolean;
    fatal?: boolean;
  };
}

/**
 * Deferred tasks that the Control Plane materializes from persisted lifecycle timestamps.
 */
export type DeferredLifecycleTaskType = "NOTIFY_USER" | "SHRED_USER";

/**
 * Input required to create a new erasure job and queue the initial `VAULT_USER` task.
 */
export interface CreateJobAndQueueTaskInput {
  jobId: string;
  taskId: string;
  organizationId: string;
  clientId: string;
  request: CreateErasureRequestInput;
  payload: Record<string, unknown>;
  now: Date;
}

/**
 * Input required to append an audit ledger event.
 */
export interface InsertAuditLedgerEventInput {
  organizationId: string;
  clientId: string;
  idempotencyKey: string;
  eventType: OutboxEventType | "WORKER_CONFIG_HEARTBEAT";
  payload: unknown;
  previousHash: string;
  currentHash: string;
  now: Date;
}

/**
 * Input required to append a worker-config heartbeat marker to the audit ledger.
 */
export interface InsertWorkerConfigHeartbeatInput {
  organizationId: string;
  clientId: string;
  configHash: string;
  configVersion?: string;
  dpoIdentifier?: string;
  now: Date;
}

/**
 * Input required to persist a terminal certificate.
 */
export interface InsertCertificateInput {
  requestId: string;
  organizationId: string;
  subjectOpaqueId: string;
  method: string;
  legalFramework: string;
  shreddedAt: Date;
  payload: Record<string, unknown>;
  signatureBase64: string;
  publicKeySpkiBase64: string;
  keyId: string;
  algorithm: string;
  archiveNextAttemptAt?: Date;
}

/**
 * Input required to append a billable usage event.
 */
export interface InsertUsageEventInput {
  billingKey: string;
  organizationId: string;
  clientId: string;
  erasureJobId?: string | null;
  auditLedgerId?: string | null;
  eventType: string;
  units: number;
  metadata: Record<string, unknown>;
  occurredAt: Date;
}

/**
 * Operator filters for listing erasure lifecycle aggregates.
 */
export interface ListErasureJobsInput {
  organizationId?: string;
  status?: ErasureRequestStatus;
  limit: number;
  offset: number;
}

/**
 * Input required to transition a job from an accepted worker outbox event.
 */
export interface TransitionJobFromOutboxInput {
  jobId: string;
  eventType: OutboxEventType;
  now: Date;
  notificationDueAt?: Date;
  shredDueAt?: Date;
  shreddedAt?: Date;
  appliedRuleName?: string;
  appliedRuleCitation?: string;
}

/**
 * Tenant organization row.
 */
export interface OrganizationRow {
  id: string;
  name: string;
  billing_plan: string;
  certificate_archive_retention_days: number;
  created_at: Date;
}

/**
 * DPO-approved worker configuration release used to fail closed on silent config drift.
 */
export interface WorkerConfigReleaseRow {
  id: string;
  organization_id: string;
  client_id: string;
  config_hash: string;
  configuration_version: string;
  dpo_identifier: string;
  legal_review_date: Date | null;
  status: "APPROVED" | "REVOKED";
  allowed_live_mutation: boolean;
  approved_at: Date;
  revoked_at: Date | null;
  notes: string | null;
  created_at: Date;
}

/**
 * Organization member row used by dashboard membership views.
 */
export interface OrganizationUserRow {
  id: string;
  email: string;
  hashed_password: string | null;
  oidc_provider_id: string | null;
  organization_id: string;
  role: "OWNER" | "ADMIN" | "AUDITOR";
  created_at: Date;
}

/**
 * DB-backed Control Plane API key row.
 */
export interface ApiKeyRow {
  id: string;
  organization_id: string;
  hashed_key: string;
  label: string;
  scopes: string[];
  created_at: Date;
  last_used_at: Date | null;
}

/**
 * Deterministic mapping from an integration-local subject id hash to the tenant-safe opaque id.
 */
export interface ExternalSubjectMappingRow {
  id: string;
  organization_id: string;
  provider: string;
  external_subject_hash: string;
  subject_opaque_id: string;
  tenant_id: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface CreateOrganizationInput {
  name: string;
  billingPlan: string;
  certificateArchiveRetentionDays?: number;
  ownerEmail?: string;
  oidcProviderId?: string;
  now: Date;
}

export interface ApproveWorkerConfigReleaseInput {
  organizationId: string;
  clientName: string;
  configHash: string;
  configurationVersion: string;
  dpoIdentifier: string;
  legalReviewDate?: string | null;
  allowedLiveMutation: boolean;
  notes?: string | null;
  requireApprovedConfig: boolean;
  now: Date;
}

export interface CreateApiKeyInput {
  organizationId: string;
  hashedKey: string;
  label: string;
  scopes: string[];
  now: Date;
}

export interface UpsertExternalSubjectMappingInput {
  organizationId: string;
  provider: string;
  externalSubjectHash: string;
  subjectOpaqueId: string;
  tenantId?: string | null;
  now: Date;
}

/**
 * Calculates exponential backoff for Control Plane task retries, capped at five minutes.
 *
 * @param attemptNumber - Attempt count after the failure being processed.
 * @param baseBackoffMs - Configured base backoff duration in milliseconds.
 * @returns Retry delay in milliseconds.
 */
export function calculateTaskRetryDelayMs(
  attemptNumber: number,
  baseBackoffMs: number
): number {
  return Math.min(
    baseBackoffMs * 2 ** Math.max(0, attemptNumber - 1),
    5 * 60 * 1000
  );
}

/**
 * Interprets the worker's failure envelope to decide whether a task should be retried.
 *
 * @param result - Worker acknowledgement result payload.
 * @returns `true` when the Control Plane should requeue the task.
 */
export function shouldRetryTaskFailure(result: unknown): boolean {
  if (!result || typeof result !== "object") {
    return true;
  }

  const failure = result as TaskFailureEnvelope;
  if (!failure.error || typeof failure.error !== "object") {
    return true;
  }

  if (failure.error.fatal === true) {
    return false;
  }

  return failure.error.retryable !== false;
}
