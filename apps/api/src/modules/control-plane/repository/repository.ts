import {
  getAuditEventByIdempotencyKey,
  getLatestAuditHash,
  insertAuditLedgerEvent,
  insertWorkerConfigHeartbeat,
  listAuditLedgerEvents,
  verifyAuditLedgerChain,
} from "./audit";
import {
  claimUnarchivedCertificates,
  getCertificateByRequestId,
  insertCertificate,
  markCertificateArchived,
  markCertificateArchiveFailed,
} from "./certificates";
import {
  createClient,
  ensureClient,
  getClientById,
  getClientByName,
  listClients,
  recordShadowVaultSuccess,
  recordShadowVaultSuccessForTask,
  rotateClientKey,
  rotateClientWebhookSecret,
  setClientActiveState,
  setClientWebhookSecret,
  touchClientAuthentication,
} from "./clients";
import {
  approveWorkerConfigRelease,
  getWorkerConfigRelease,
  listWorkerConfigReleases,
  revokeWorkerConfigRelease,
} from "./config-releases";
import {
  cancelWaitingJobByIdempotencyKey,
  createBulkAdminPurgeJobs,
  createJobAndQueueTask,
  getJobById,
  getJobByIdempotencyKey,
  listErasureJobs,
  transitionJobFromOutbox,
} from "./jobs";
import {
  ackTask,
  claimNextTask,
  extendTaskLease,
  getTaskByJobId,
  listDeadLetterTasks,
  materializeDueLifecycleTasks,
  requeueDeadLetterTask,
} from "./tasks";
import { getOperationalMetricRows } from "./metrics";
import {
  insertUsageEvent,
  listUsageEvents,
  summarizeUsage,
} from "./usage";
import {
  authenticateApiKey,
  createApiKey,
  createOrganization,
  ensureBootstrapApiKey,
  ensureBootstrapOrganization,
  getOrganizationByName,
  listOrganizationMembers,
} from "./tenants";
import {
  claimPendingWebhooks,
  enqueueWebhook,
  markWebhookFailed,
  markWebhookProcessed,
} from "./webhooks";
import {
  getProviderCompletionTargetsForJob,
  listProviderCompletionTargets,
  upsertProviderCompletionTarget,
} from "./completion";
import {
  getBillingSubscription,
  insertBillingEvent,
  upsertBillingSubscription,
} from "./billing";
import {
  getExternalSubjectMapping,
  upsertExternalSubjectMapping,
} from "./integrations";
import type {
  AuditLedgerRow,
  AuditLedgerVerificationResult,
  CertificateRow,
  ClientRow,
  BulkAdminPurgeInsertResult,
  CreateBulkAdminPurgeJobsInput,
  CreateClientInput,
  CreateJobAndQueueTaskInput,
  CreatedJobRecord,
  ErasureJobRow,
  InsertAuditLedgerEventInput,
  InsertCertificateInput,
  InsertWorkerConfigHeartbeatInput,
  InsertUsageEventInput,
  ListErasureJobsInput,
  RepositoryContext,
  RotateClientKeyInput,
  RotateClientWebhookSecretInput,
  TaskQueueRow,
  TransitionJobFromOutboxInput,
  UsageEventRow,
  UsageSummaryRow,
  ApiKeyRow,
  CreateApiKeyInput,
  CreateOrganizationInput,
  OrganizationRow,
  OrganizationUserRow,
  ExternalSubjectMappingRow,
  UpsertExternalSubjectMappingInput,
  ApproveWorkerConfigReleaseInput,
  WorkerConfigReleaseRow,
  ProviderCompletionTargetRow,
  UpsertProviderCompletionTargetInput,
  BillingSubscriptionRow,
  UpsertBillingSubscriptionInput,
  InsertBillingEventInput,
} from "./types";
import type { Sql } from "@/types";

/**
 * Postgres.js repository for the control-plane state machine.
 *
 * The class is intentionally thin: each lifecycle area is implemented in a feature-scoped
 * helper module, while this public repository remains the stable integration surface consumed
 * by the service layer.
 */
export class ControlPlaneRepository {
  private readonly context: RepositoryContext;

  constructor(
    sql: Sql,
    schema: string,
    taskLeaseSeconds: number,
    taskMaxAttempts: number,
    taskBaseBackoffMs: number
  ) {
    this.context = {
      sql,
      schema,
      taskLeaseSeconds,
      taskMaxAttempts,
      taskBaseBackoffMs,
    };
  }

  /**
   * Upserts a worker client record and rotates its token hash atomically.
   *
   * @param name - Stable worker client name.
   * @param workerApiKeyHash - SHA-256 digest of worker bearer token.
   * @returns Persisted client row.
   */
  async ensureClient(name: string, workerApiKeyHash: string, organizationId?: string): Promise<ClientRow> {
    return ensureClient(this.context, name, workerApiKeyHash, organizationId);
  }

  async ensureBootstrapOrganization(): Promise<OrganizationRow> {
    return ensureBootstrapOrganization(this.context);
  }

  async createOrganization(input: CreateOrganizationInput): Promise<OrganizationRow> {
    return createOrganization(this.context, input);
  }

  async getOrganizationByName(name: string): Promise<OrganizationRow | null> {
    return getOrganizationByName(this.context, name);
  }

  async createApiKey(input: CreateApiKeyInput): Promise<ApiKeyRow> {
    return createApiKey(this.context, input);
  }

  async ensureBootstrapApiKey(hashedKey: string, now: Date): Promise<ApiKeyRow> {
    return ensureBootstrapApiKey(this.context, hashedKey, now);
  }

  async authenticateApiKey(hashedKey: string, now: Date): Promise<ApiKeyRow | null> {
    return authenticateApiKey(this.context, hashedKey, now);
  }

  async listOrganizationMembers(organizationId: string): Promise<OrganizationUserRow[]> {
    return listOrganizationMembers(this.context, organizationId);
  }

  async getOperationalMetricRows() {
    return getOperationalMetricRows(this.context);
  }

  /**
   * Upserts a tenant-owned integration subject mapping.
   *
   * @param input - Provider, external subject hash, opaque subject id, and tenant metadata.
   * @returns Persisted mapping row.
   */
  async upsertExternalSubjectMapping(
    input: UpsertExternalSubjectMappingInput
  ): Promise<ExternalSubjectMappingRow> {
    return upsertExternalSubjectMapping(this.context, input);
  }

  /**
   * Looks up a tenant-owned integration subject mapping.
   *
   * @param organizationId - Tenant organization id.
   * @param provider - Integration provider slug.
   * @param externalSubjectHash - Hash of the external subject id.
   * @returns Matching mapping or `null`.
   */
  async getExternalSubjectMapping(
    organizationId: string,
    provider: string,
    externalSubjectHash: string
  ): Promise<ExternalSubjectMappingRow | null> {
    return getExternalSubjectMapping(this.context, organizationId, provider, externalSubjectHash);
  }

  /**
   * Finds a registered worker client by ID.
   *
   * @param id - Worker client UUID.
   * @returns Matching client row or `null`.
   */
  async getClientById(id: string): Promise<ClientRow | null> {
    return getClientById(this.context, id);
  }

  /**
   * Finds a registered worker client by name.
   *
   * @param name - Worker client name.
   * @returns Matching client row or `null`.
   */
  async getClientByName(name: string, organizationId?: string): Promise<ClientRow | null> {
    return getClientByName(this.context, name, organizationId);
  }

  /**
   * Lists registered worker clients.
   *
   * @returns Persisted worker clients.
   */
  async listClients(organizationId?: string): Promise<ClientRow[]> {
    return listClients(this.context, organizationId);
  }

  /**
   * Creates a new worker client and persists its hashed token metadata.
   *
   * @param input - Client attributes and hashed token metadata.
   * @returns Persisted client row.
   */
  async createClient(input: CreateClientInput): Promise<ClientRow> {
    return createClient(this.context, input);
  }

  async approveWorkerConfigRelease(input: ApproveWorkerConfigReleaseInput): Promise<WorkerConfigReleaseRow | null> {
    return approveWorkerConfigRelease(this.context, input);
  }

  async revokeWorkerConfigRelease(
    organizationId: string,
    clientName: string,
    configHash: string,
    now: Date
  ): Promise<WorkerConfigReleaseRow | null> {
    return revokeWorkerConfigRelease(this.context, organizationId, clientName, configHash, now);
  }

  async getWorkerConfigRelease(clientId: string, configHash: string): Promise<WorkerConfigReleaseRow | null> {
    return getWorkerConfigRelease(this.context, clientId, configHash);
  }

  async listWorkerConfigReleases(
    organizationId: string,
    clientName: string
  ): Promise<WorkerConfigReleaseRow[]> {
    return listWorkerConfigReleases(this.context, organizationId, clientName);
  }

  /**
   * Rotates an existing worker client key.
   *
   * @param input - Rotation metadata and hashed token.
   * @returns Updated client row or `null`.
   */
  async rotateClientKey(input: RotateClientKeyInput): Promise<ClientRow | null> {
    return rotateClientKey(this.context, input);
  }

  /**
   * Rotates a provider webhook signing secret and preserves the previous value for a grace window.
   *
   * @param input - Client name, tenant id, new secret, and grace window.
   * @returns Updated client row or `null`.
   */
  async rotateClientWebhookSecret(input: RotateClientWebhookSecretInput): Promise<ClientRow | null> {
    return rotateClientWebhookSecret(this.context, input);
  }

  /**
   * Sets an initial provider webhook signing secret without carrying a previous secret.
   *
   * @param input - Client name, tenant id, new secret, and timestamp.
   * @returns Updated client row or `null`.
   */
  async setClientWebhookSecret(
    input: Omit<RotateClientWebhookSecretInput, "previousSecretGraceHours">
  ): Promise<ClientRow | null> {
    return setClientWebhookSecret(this.context, input);
  }

  /**
   * Enables or disables a worker client.
   *
   * @param name - Worker client name.
   * @param active - Desired active state.
   * @returns Updated client row or `null`.
   */
  async setClientActiveState(name: string, active: boolean, organizationId?: string): Promise<ClientRow | null> {
    return setClientActiveState(this.context, name, active, organizationId);
  }

  /**
   * Records the latest successful worker authentication timestamp.
   *
   * @param clientId - Worker client id.
   * @param now - Authentication timestamp.
   */
  async touchClientAuthentication(clientId: string, now: Date): Promise<void> {
    return touchClientAuthentication(this.context, clientId, now);
  }

  /**
   * Records a successful shadow-mode vault and enables live mutation after threshold.
   *
   * @param clientId - Worker client id.
   * @param requiredSuccesses - Required successful shadow vault count.
   * @param now - State transition timestamp.
   * @returns Updated client row or `null`.
   */
  async recordShadowVaultSuccess(
    clientId: string,
    requiredSuccesses: number,
    now: Date
  ): Promise<ClientRow | null> {
    return recordShadowVaultSuccess(this.context, clientId, requiredSuccesses, now);
  }

  /**
   * Idempotently records a completed shadow task and increments client burn-in once.
   *
   * @param taskId - Completed `VAULT_USER` task id.
   * @param clientId - Worker client id.
   * @param requiredSuccesses - Required successful shadow vault count.
   * @param now - State transition timestamp.
   * @returns Updated client row, or `null` when this task was already counted.
   */
  async recordShadowVaultSuccessForTask(
    taskId: string,
    clientId: string,
    requiredSuccesses: number,
    now: Date
  ): Promise<ClientRow | null> {
    return recordShadowVaultSuccessForTask(this.context, taskId, clientId, requiredSuccesses, now);
  }

  /**
   * Fetches an erasure job by request id.
   *
   * @param jobId - Erasure job UUID.
   * @returns Job row or `null`.
   */
  async getJobById(jobId: string, organizationId?: string): Promise<ErasureJobRow | null> {
    return getJobById(this.context, jobId, organizationId);
  }

  /**
   * Fetches an erasure job by idempotency key.
   *
   * @param idempotencyKey - Request idempotency UUID.
   * @returns Job row or `null`.
   */
  async getJobByIdempotencyKey(idempotencyKey: string, organizationId?: string): Promise<ErasureJobRow | null> {
    return getJobByIdempotencyKey(this.context, idempotencyKey, organizationId);
  }

  /**
   * Lists erasure lifecycle aggregates for operator dashboards.
   *
   * @param input - Pagination and optional status filter.
   * @returns Matching jobs newest first.
   */
  async listErasureJobs(input: ListErasureJobsInput): Promise<ErasureJobRow[]> {
    return listErasureJobs(this.context, input);
  }

  /**
   * Fetches the earliest task associated with a job.
   *
   * @param jobId - Erasure job UUID.
   * @returns Task row or `null`.
   */
  async getTaskByJobId(jobId: string, organizationId?: string): Promise<TaskQueueRow | null> {
    return getTaskByJobId(this.context, jobId, organizationId);
  }

  /**
   * Creates an erasure job and initial `VAULT_USER` task in one transaction.
   *
   * @param input - Precomputed ids, normalized request payload, and timestamp.
   * @returns Inserted job and task rows.
   */
  async createJobAndQueueTask(input: CreateJobAndQueueTaskInput): Promise<CreatedJobRecord> {
    return createJobAndQueueTask(this.context, input);
  }

  /**
   * Creates many administrator-approved purge jobs in one set-based transaction.
   *
   * @param input - Tenant, client, metadata, and per-subject purge rows.
   * @returns Inserted/duplicate counts and inserted request ids.
   */
  async createBulkAdminPurgeJobs(
    input: CreateBulkAdminPurgeJobsInput
  ): Promise<BulkAdminPurgeInsertResult> {
    return createBulkAdminPurgeJobs(this.context, input);
  }

  /**
   * Cancels a job only when it is still in `WAITING_COOLDOWN`.
   *
   * @param idempotencyKey - Request idempotency UUID.
   * @param now - Update timestamp.
   * @returns Cancelled job row or `null`.
   */
  async cancelWaitingJobByIdempotencyKey(
    idempotencyKey: string,
    now: Date,
    organizationId?: string
  ): Promise<ErasureJobRow | null> {
    return cancelWaitingJobByIdempotencyKey(this.context, idempotencyKey, now, organizationId);
  }

  /**
   * Claims the next due task using `FOR UPDATE SKIP LOCKED` leasing semantics.
   *
   * @param clientId - Authenticated worker client id.
   * @param workerClientName - Worker client name recorded in lease metadata.
   * @param now - Lease anchor timestamp.
   * @returns Leased task row or `null`.
   */
  async claimNextTask(
    clientId: string,
    workerClientName: string,
    now: Date
  ): Promise<TaskQueueRow | null> {
    return claimNextTask(this.context, clientId, workerClientName, now);
  }

  /**
   * Materializes due lifecycle tasks without leasing them to a worker.
   *
   * @param clientId - Worker client whose due jobs should be scanned.
   * @param now - Scheduler timestamp.
   * @param limit - Maximum jobs to scan per lifecycle task type.
   * @returns Number of tasks inserted.
   */
  async materializeDueLifecycleTasks(
    clientId: string,
    now: Date,
    limit: number = 1000
  ): Promise<number> {
    return materializeDueLifecycleTasks(this.context, clientId, now, limit);
  }

  /**
   * Acknowledges task completion or failure and applies retry/DLQ state transitions.
   *
   * @param taskId - Task UUID.
   * @param status - Worker ack status.
   * @param result - Worker result payload persisted for diagnostics.
   * @param now - Completion timestamp.
   * @returns Updated task row or `null` when task is missing.
   */
  async ackTask(
    taskId: string,
    status: "completed" | "failed",
    result: unknown,
    now: Date
  ): Promise<TaskQueueRow | null> {
    return ackTask(this.context, taskId, status, result, now);
  }

  /**
   * Extends the lease for a long-running dispatched worker task.
   *
   * @param taskId - Active task UUID.
   * @param clientId - Authenticated worker client id.
   * @param workerClientName - Worker name recorded during claim.
   * @param now - Heartbeat timestamp.
   * @returns Updated task row or `null` when the lease is no longer active.
   */
  async extendTaskLease(
    taskId: string,
    clientId: string,
    workerClientName: string,
    now: Date
  ): Promise<TaskQueueRow | null> {
    return extendTaskLease(this.context, taskId, clientId, workerClientName, now);
  }

  /**
   * Lists dead-letter tasks awaiting operator intervention.
   *
   * @returns Dead-letter task rows.
   */
  async listDeadLetterTasks(organizationId?: string): Promise<TaskQueueRow[]> {
    return listDeadLetterTasks(this.context, organizationId);
  }

  /**
   * Requeues a dead-letter task for retry.
   *
   * @param taskId - Dead-letter task UUID.
   * @param now - Requeue timestamp.
   * @returns Updated task row or `null`.
   */
  async requeueDeadLetterTask(taskId: string, now: Date, organizationId?: string): Promise<TaskQueueRow | null> {
    return requeueDeadLetterTask(this.context, taskId, now, organizationId);
  }

  /**
   * Reads the latest WORM hash pointer for a client.
   *
   * @param clientId - Worker client id.
   * @returns Current chain head hash or `null`.
   */
  async getLatestAuditHash(clientId: string): Promise<string | null> {
    return getLatestAuditHash(this.context, clientId);
  }

  /**
   * Appends one audit ledger event with idempotent conflict handling.
   *
   * @param input - Event envelope and chain hashes.
   * @returns `true` when inserted, `false` when conflict indicates replay.
   */
  async insertAuditLedgerEvent(input: InsertAuditLedgerEventInput): Promise<boolean> {
    return insertAuditLedgerEvent(this.context, input);
  }

  /**
   * Persists an idempotent worker-config heartbeat marker in the audit ledger.
   *
   * @param input - Worker config fingerprint metadata.
   * @returns `true` when inserted, `false` when already recorded.
   */
  async insertWorkerConfigHeartbeat(input: InsertWorkerConfigHeartbeatInput): Promise<boolean> {
    return insertWorkerConfigHeartbeat(this.context, input);
  }

  /**
   * Fetches a previously ingested audit event by its global idempotency key.
   *
   * @param idempotencyKey - Worker idempotency key.
   * @returns Matching audit event or `null`.
   */
  async getAuditEventByIdempotencyKey(
    idempotencyKey: string
  ): Promise<AuditLedgerRow | null> {
    return getAuditEventByIdempotencyKey(this.context, idempotencyKey);
  }

  /**
   * Lists audit ledger events for archival/export flows.
   *
   * @param filters - Optional client and ledger-sequence filters.
   * @returns Ordered audit ledger rows.
   */
  async listAuditLedgerEvents(filters: { organizationId?: string; clientName?: string; afterLedgerSeq?: number } = {}) {
    return listAuditLedgerEvents(this.context, filters);
  }

  /**
   * Recomputes a tenant/client audit ledger chain and reports the first integrity violation.
   *
   * @param filters - Tenant and optional worker client filter.
   * @returns Chain verification result.
   */
  async verifyAuditLedgerChain(filters: {
    organizationId: string;
    clientName?: string;
  }): Promise<AuditLedgerVerificationResult> {
    return verifyAuditLedgerChain(this.context, filters);
  }

  /**
   * Transitions erasure job state from worker outbox event semantics.
   *
   * @param input - Job id, event type, and timestamps.
   */
  async transitionJobFromOutbox(input: TransitionJobFromOutboxInput): Promise<void> {
    return transitionJobFromOutbox(this.context, input);
  }

  /**
   * Inserts a signed Certificate of Erasure idempotently.
   *
   * @param input - Persisted certificate payload and signature envelope.
   * @returns `true` when inserted, `false` when certificate already exists.
   */
  async insertCertificate(input: InsertCertificateInput): Promise<boolean> {
    return insertCertificate(this.context, input);
  }

  /**
   * Fetches minted certificate by request id.
   *
   * @param requestId - Erasure request UUID.
   * @returns Certificate row or `null`.
   */
  async getCertificateByRequestId(
    requestId: string,
    organizationId?: string
  ): Promise<CertificateRow | null> {
    return getCertificateByRequestId(this.context, requestId, organizationId);
  }

  /**
   * Fetches a batch of certificates that haven't been archived to S3 yet.
   *
   * @param limit - Batch size.
   * @returns Array of unarchived certificate rows.
   */
  async claimUnarchivedCertificates(now: Date, limit: number = 50, organizationId?: string) {
    return claimUnarchivedCertificates(this.context, now, limit, organizationId);
  }

  /**
   * Marks a certificate as successfully archived to WORM storage.
   *
   * @param requestId - Certificate request ID.
   * @param now - Archival timestamp.
   */
  async markCertificateArchived(
    requestId: string,
    leaseToken: string,
    now: Date,
    archive: {
      bucket: string;
      objectKey: string;
      objectETag: string | null;
      objectVersionId: string | null;
      retentionUntil: Date;
    }
  ) {
    return markCertificateArchived(this.context, {
      requestId,
      leaseToken,
      now,
      ...archive,
    });
  }

  async markCertificateArchiveFailed(
    requestId: string,
    leaseToken: string,
    error: string,
    nextAttemptAt: Date,
    now: Date
  ) {
    return markCertificateArchiveFailed(this.context, requestId, leaseToken, error, nextAttemptAt, now);
  }

  async enqueueWebhook(input: { jobId: string; url: string; headers?: Record<string, string>; payload: unknown; now: Date }) {
    return enqueueWebhook(this.context, input);
  }

  async claimPendingWebhooks(limit: number = 10, now: Date) {
    return claimPendingWebhooks(this.context, limit, now);
  }

  async markWebhookProcessed(id: string, leaseToken: string, now: Date) {
    return markWebhookProcessed(this.context, id, leaseToken, now);
  }

  async markWebhookFailed(
    id: string,
    leaseToken: string,
    error: string,
    nextAttemptAt: Date,
    isPermanent: boolean,
    now: Date
  ) {
    return markWebhookFailed(this.context, id, leaseToken, error, nextAttemptAt, isPermanent, now);
  }

  async upsertProviderCompletionTarget(
    input: UpsertProviderCompletionTargetInput
  ): Promise<ProviderCompletionTargetRow | null> {
    return upsertProviderCompletionTarget(this.context, input);
  }

  async listProviderCompletionTargets(
    organizationId: string,
    clientName?: string
  ): Promise<ProviderCompletionTargetRow[]> {
    return listProviderCompletionTargets(this.context, organizationId, clientName);
  }

  async getProviderCompletionTargetsForJob(
    jobId: string
  ): Promise<Array<ProviderCompletionTargetRow & { external_reference_id: string }>> {
    return getProviderCompletionTargetsForJob(this.context, jobId);
  }

  async upsertBillingSubscription(
    input: UpsertBillingSubscriptionInput
  ): Promise<BillingSubscriptionRow> {
    return upsertBillingSubscription(this.context, input);
  }

  async insertBillingEvent(input: InsertBillingEventInput): Promise<boolean> {
    return insertBillingEvent(this.context, input);
  }

  async getBillingSubscription(organizationId: string): Promise<BillingSubscriptionRow | null> {
    return getBillingSubscription(this.context, organizationId);
  }

  /**
   * Appends a billable usage event idempotently.
   *
   * @param input - Usage event envelope.
   * @returns `true` when inserted, `false` on billing-key replay.
   */
  async insertUsageEvent(input: InsertUsageEventInput): Promise<boolean> {
    return insertUsageEvent(this.context, input);
  }

  /**
   * Lists raw usage events.
   *
   * @param filters - Optional client/time filters.
   * @returns Usage event rows.
   */
  async listUsageEvents(filters: { organizationId?: string; clientName?: string; since?: Date; until?: Date } = {}) {
    return listUsageEvents(this.context, filters);
  }

  /**
   * Aggregates usage totals by client and billable event type.
   *
   * @param filters - Optional client/time filters.
   * @returns Usage summary rows.
   */
  async summarizeUsage(filters: { organizationId?: string; clientName?: string; since?: Date; until?: Date } = {}) {
    return summarizeUsage(this.context, filters);
  }
}
