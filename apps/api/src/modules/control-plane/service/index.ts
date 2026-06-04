import { fail } from "@/errors";
import { verifyEd25519Signature } from "@/crypto";
import {
  canonicalJsonStringify,
  computeSha256Hex,
  computeTokenHash,
  computeWormHash,
} from "../hash";
import { ControlPlaneRepository } from "../repository";
import type {
  CreateErasureRequestInput,
  ExternalSubjectMappingInput,
  GrcErasureWebhookInput,
  WorkerAckInput,
  WorkerOutboxEventInput,
} from "../schema";
import {
  assertAllowedOutboxTransition,
  assertOutboxMetadata,
  buildOutboxPayload,
  isCreateRequestEquivalent,
  parseVaultLifecyclePolicy,
  isReplayEquivalent,
  parseVaultLifecycleSchedule,
} from "./guards";
import { finalizeTerminalOutboxEvent, isTerminalEventType } from "./terminal";
import type { ServiceOptions } from "./types";
import { assertSafeWebhookUrl, assertSafeWebhookDispatchTarget } from "../webhook";
import { PdfCertificateGenerator, type ProofOfErasureData } from "./pdf-generator";
import { recordUsageEvent, recordWorkerOutboxEvent, getLogger } from "@/observability";
import { s3PutObject } from "@/utils";
import { verifyHmacSha256Hex } from "@/crypto";
import { normalizeProviderSubjectLookup } from "@modules/webhooks";

const logger = getLogger({ component: "control-plane-service" });
const textEncoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function computeExternalSubjectHash(provider: string, externalSubjectId: string): Promise<string> {
  const subject = await normalizeProviderSubjectLookup(externalSubjectId);
  return computeSha256Hex(`${provider}\n${subject.lookupId}`);
}

async function deterministicUuidFromText(value: string): Promise<string> {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", textEncoder.encode(value))
  );
  const uuid = digest.slice(0, 16);
  uuid[6] = (uuid[6]! & 0x0f) | 0x50;
  uuid[8] = (uuid[8]! & 0x3f) | 0x80;
  const hex = bytesToHex(uuid);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function readHeader(headers: Headers, name: string): string | null {
  return headers.get(name) ?? headers.get(name.toLowerCase());
}

function arrayPayloadValue(payload: Record<string, unknown>, key: string): unknown[] {
  const value = payload[key];
  return Array.isArray(value) ? value : [];
}

function safeOutboundWebhookHeaders(headers: unknown): Record<string, string> {
  if (typeof headers !== "object" || headers === null || Array.isArray(headers)) {
    return {};
  }

  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers as Record<string, unknown>)) {
    const normalized = name.toLowerCase();
    if (
      !/^[a-z0-9!#$%&'*+.^_`|~-]+$/i.test(name) ||
      ["host", "content-length", "transfer-encoding", "connection"].includes(normalized)
    ) {
      continue;
    }
    if (typeof value === "string" && value.length <= 2048) {
      output[name] = value;
    }
  }

  return output;
}

/**
 * Domain service for zero-PII control-plane orchestration.
 */
export class ControlPlaneService {
  private readonly now: () => Date;
  private readonly repository: ControlPlaneRepository;
  private readonly signer: ServiceOptions["signer"];
  private readonly pdfGenerator = new PdfCertificateGenerator();
  private readonly workerSharedSecret: string;
  private readonly workerClientName: string;
  private readonly maxOutboxPayloadBytes: number;
  private readonly webhookTimeoutMs: number;
  private readonly shadowBurnInRequired: boolean;
  private readonly shadowRequiredSuccesses: number;

  constructor(options: ServiceOptions) {
    this.repository = options.repository;
    this.signer = options.signer;
    this.workerSharedSecret = options.workerSharedSecret;
    this.workerClientName = options.workerClientName;
    this.maxOutboxPayloadBytes = options.maxOutboxPayloadBytes;
    this.webhookTimeoutMs = options.webhookTimeoutMs ?? 10_000;
    this.shadowBurnInRequired = options.shadowBurnInRequired ?? true;
    this.shadowRequiredSuccesses = options.shadowRequiredSuccesses ?? 100;
    this.now = options.now ?? (() => new Date());
  }

  /**
   * Stores a GRC-platform subject mapping without persisting the raw external identifier.
   *
   * @param provider - Integration provider slug, for example `onetrust` or `zendesk`.
   * @param input - External subject id and tenant-safe opaque subject id.
   * @param organizationId - Tenant organization that owns the mapping.
   * @returns Persisted mapping metadata safe for API responses.
   */
  async registerExternalSubjectMapping(
    provider: string,
    input: ExternalSubjectMappingInput,
    organizationId: string
  ) {
    const mapping = await this.repository.upsertExternalSubjectMapping({
      organizationId,
      provider,
      externalSubjectHash: await computeExternalSubjectHash(provider, input.external_subject_id),
      subjectOpaqueId: input.subject_opaque_id,
      tenantId: input.tenant_id,
      now: this.now(),
    });

    return {
      id: mapping.id,
      provider: mapping.provider,
      subject_opaque_id: mapping.subject_opaque_id,
      tenant_id: mapping.tenant_id,
      updated_at: mapping.updated_at.toISOString(),
    };
  }

  /**
   * Verifies and translates a signed GRC webhook into a normal erasure request.
   *
   * The raw external subject id is used only for an in-memory hash lookup. It is never
   * stored in Control Plane tables or forwarded to the worker.
   *
   * @param provider - Integration provider slug.
   * @param input - Strict webhook payload emitted by the external GRC platform.
   * @param organizationId - Authenticated tenant organization.
   * @param rawBody - Exact request body text used by the emitter's signature.
   * @param headers - Request headers carrying timestamp/signature.
   * @param signingSecret - Tenant API key presented as bearer auth and used as HMAC secret.
   * @returns Created erasure request metadata plus integration mapping context.
   * @throws {ApiError} When signature, mapping, or request validation fails.
   */
  async ingestGrcWebhook(
    provider: string,
    input: GrcErasureWebhookInput,
    organizationId: string,
    rawBody: string,
    headers: Headers,
    signingSecret: string
  ) {
    const timestamp = readHeader(headers, "x-grc-timestamp");
    const signature = readHeader(headers, "x-grc-signature");
    if (!timestamp || !signature) {
      fail({
        code: "API_GRC_WEBHOOK_SIGNATURE_MISSING",
        title: "Missing GRC webhook signature",
        detail: "GRC webhooks must include x-grc-timestamp and x-grc-signature.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    const timestampMs = Number(timestamp);
    if (!Number.isFinite(timestampMs) || Math.abs(this.now().getTime() - timestampMs) > 5 * 60 * 1000) {
      fail({
        code: "API_GRC_WEBHOOK_SIGNATURE_EXPIRED",
        title: "Expired GRC webhook signature",
        detail: "GRC webhook signature timestamp is outside the five-minute replay window.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    if (!await verifyHmacSha256Hex(signingSecret, `${timestamp}\n${rawBody}`, signature)) {
      fail({
        code: "API_GRC_WEBHOOK_SIGNATURE_INVALID",
        title: "Invalid GRC webhook signature",
        detail: "GRC webhook signature verification failed.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    const externalSubjectHash = await computeExternalSubjectHash(provider, input.external_subject_id);
    const mapping = await this.repository.getExternalSubjectMapping(
      organizationId,
      provider,
      externalSubjectHash
    );
    if (!mapping) {
      fail({
        code: "API_GRC_SUBJECT_MAPPING_NOT_FOUND",
        title: "GRC subject mapping not found",
        detail: "The signed webhook referenced an external subject id that has not been mapped to an opaque subject id.",
        status: 404,
        category: "validation",
        retryable: false,
        context: {
          provider,
          externalSubjectHash,
        },
      });
    }

    const idempotencyKey = input.idempotency_key ??
      await deterministicUuidFromText(`${organizationId}\n${provider}\n${input.event_id}`);
    const created = await this.createErasureRequest(
      {
        subject_opaque_id: mapping.subject_opaque_id,
        idempotency_key: idempotencyKey,
        trigger_source: input.trigger_source,
        actor_opaque_id: input.actor_opaque_id ?? `integration:${provider}`,
        legal_framework: input.legal_framework,
        request_timestamp: input.request_timestamp ?? this.now().toISOString(),
        tenant_id: input.tenant_id ?? mapping.tenant_id ?? undefined,
        cooldown_days: input.cooldown_days,
        shadow_mode: input.shadow_mode,
        webhook_url: input.webhook_url,
      },
      organizationId
    );

    return {
      ...created,
      provider,
      mapped: true as const,
      idempotency_key: idempotencyKey,
    };
  }

  /**
   * Applies deterministic Control Plane state transitions for a committed worker outbox event.
   *
   * This method is replay-safe. If the API crashes after appending the WORM ledger but before
   * updating the state machine, a worker retry must be able to restore the same lifecycle
   * transition without duplicating downstream work.
   *
   * @param job - Existing erasure job.
   * @param input - Validated worker outbox event.
   * @param now - Request clock anchor.
   */
  private async applyOutboxLifecycle(
    job: Awaited<ReturnType<ControlPlaneRepository["getJobById"]>> extends infer T
      ? Exclude<T, null>
      : never,
    input: WorkerOutboxEventInput,
    now: Date
  ): Promise<void> {
    const schedule =
      input.event_type === "USER_VAULTED"
        ? parseVaultLifecycleSchedule(input.payload)
        : null;
    const policy =
      input.event_type === "USER_VAULTED" || input.event_type === "USER_HARD_DELETED"
        ? parseVaultLifecyclePolicy(input.payload)
        : null;
    const shreddedAt = isTerminalEventType(input.event_type)
      ? new Date(input.event_timestamp)
      : undefined;

    await this.repository.transitionJobFromOutbox({
      jobId: input.request_id,
      eventType: input.event_type,
      now,
      notificationDueAt: schedule?.notificationDueAt,
      shredDueAt: schedule?.shredDueAt,
      shreddedAt,
      appliedRuleName: policy?.appliedRuleName,
      appliedRuleCitation: policy?.appliedRuleCitation,
    });

    if (isTerminalEventType(input.event_type)) {
      await finalizeTerminalOutboxEvent(
        this.repository,
        this.signer,
        this.webhookTimeoutMs,
        job,
        input.event_type,
        shreddedAt!,
        input.current_hash,
        arrayPayloadValue(input.payload, "blob_receipts"),
        arrayPayloadValue(input.payload, "postgres_transaction_ids")
      );
    }
  }

  /**
   * Registers an erasure request and queues the first worker task.
   *
   * @param input - Validated erasure ingestion payload.
   * @returns Request/task identifiers plus idempotent replay indicator.
   * @throws {ApiError} When the idempotency key is reused with a different payload.
   */
  async createErasureRequest(input: CreateErasureRequestInput, organizationId?: string) {
    const organization = organizationId ? null : await this.repository.ensureBootstrapOrganization();
    const effectiveOrganizationId = organizationId ?? organization!.id;

    if (input.webhook_url) {
      assertSafeWebhookUrl(input.webhook_url);
    }

    const existingJob = await this.repository.getJobByIdempotencyKey(
      input.idempotency_key,
      effectiveOrganizationId
    );
    if (existingJob) {
      if (!isCreateRequestEquivalent(existingJob, input)) {
        fail({
          code: "API_ERASURE_REQUEST_IDEMPOTENCY_CONFLICT",
          title: "Idempotency key conflict",
          detail: `idempotency_key ${input.idempotency_key} already exists with a different request payload.`,
          status: 409,
          category: "integrity",
          retryable: false,
        });
      }

      const existingTask = await this.repository.getTaskByJobId(existingJob.id, effectiveOrganizationId);
      return {
        request_id: existingJob.id,
        task_id: existingTask?.id ?? null,
        accepted_at: existingJob.created_at.toISOString(),
        idempotent_replay: true as const,
      };
    }

    const now = this.now();
    const jobId = globalThis.crypto.randomUUID();
    const taskId = globalThis.crypto.randomUUID();
    const tokenHash = await computeTokenHash(this.workerSharedSecret);
    const client = await this.repository.ensureClient(
      this.workerClientName,
      tokenHash,
      effectiveOrganizationId
    );
    if (!client.is_active) {
      fail({
        code: "API_WORKER_CLIENT_INACTIVE",
        title: "Configured worker client is inactive",
        detail: `Worker client ${this.workerClientName} is disabled and cannot accept new erasure jobs.`,
        status: 409,
        category: "configuration",
        retryable: false,
      });
    }

    if (
      this.shadowBurnInRequired &&
      this.shadowRequiredSuccesses > 0 &&
      !input.shadow_mode &&
      !client.live_mutation_enabled
    ) {
      fail({
        code: "API_LIVE_MUTATION_BURN_IN_REQUIRED",
        title: "Shadow-mode burn-in required",
        detail: `Worker client ${client.name} must complete ${this.shadowRequiredSuccesses} successful shadow-mode vault tasks before live mutation. Current successes: ${client.shadow_success_count}.`,
        status: 409,
        category: "configuration",
        retryable: false,
        context: {
          clientName: client.name,
          currentSuccesses: client.shadow_success_count,
          requiredSuccesses: this.shadowRequiredSuccesses,
        },
      });
    }

    const created = await this.repository.createJobAndQueueTask({
      jobId,
      taskId,
      organizationId: effectiveOrganizationId,
      clientId: client.id,
      request: input,
      payload: {
        request_id: jobId,
        subject_opaque_id: input.subject_opaque_id,
        idempotency_key: input.idempotency_key,
        trigger_source: input.trigger_source,
        actor_opaque_id: input.actor_opaque_id,
        legal_framework: input.legal_framework,
        request_timestamp: input.request_timestamp,
        tenant_id: input.tenant_id,
        cooldown_days: input.cooldown_days,
        shadow_mode: input.shadow_mode,
        webhook_url: input.webhook_url,
      },
      now,
    });

    return {
      request_id: created.job.id,
      task_id: created.task.id,
      accepted_at: created.job.created_at.toISOString(),
      idempotent_replay: false as const,
    };
  }

  /**
   * Authenticates a worker using client ID plus bearer-token hash matching.
   *
   * @param clientId - Worker client UUID from the request header.
   * @param bearerToken - Raw bearer token.
   * @returns Worker client id when credentials match, otherwise `null`.
   */
  async authorizeWorker(
    clientId: string,
    bearerToken: string
  ): Promise<string | null> {
    const client = await this.repository.getClientById(clientId);
    if (!client || !client.is_active) {
      return null;
    }

    const tokenHash = await computeTokenHash(bearerToken);
    if (tokenHash !== client.worker_api_key_hash) {
      return null;
    }

    await this.repository.touchClientAuthentication(client.id, this.now());
    return client.id;
  }

  /**
   * Leases at most one pending task for the authenticated worker.
   *
   * @param clientName - Worker client name for lease attribution.
   * @param clientId - Authenticated worker client id.
   * @param heartbeat - Worker config fingerprint metadata from sync headers.
   * @returns Pending task envelope or `pending: false`.
   */
  async syncWorker(
    clientName: string,
    clientId: string,
    heartbeat: { configHash: string; configVersion?: string; dpoIdentifier?: string }
  ) {
    const client = await this.repository.getClientById(clientId);
    if (!client) {
      fail({
        code: "API_WORKER_AUTH_INVALID",
        title: "Invalid worker credentials",
        detail: "Worker authentication failed.",
        status: 401,
        category: "authentication",
        retryable: false,
      });
    }

    if (client.require_approved_config) {
      const release = await this.repository.getWorkerConfigRelease(client.id, heartbeat.configHash);
      if (!release || release.status !== "APPROVED") {
        fail({
          code: "API_WORKER_CONFIG_NOT_APPROVED",
          title: "Worker config is not approved",
          detail: "Worker sync rejected because its active configuration hash is not DPO-approved.",
          status: 403,
          category: "authorization",
          retryable: false,
          context: {
            clientId,
            configHash: heartbeat.configHash,
          },
        });
      }

      if (
        release.configuration_version !== heartbeat.configVersion ||
        release.dpo_identifier !== heartbeat.dpoIdentifier
      ) {
        fail({
          code: "API_WORKER_CONFIG_ATTESTATION_MISMATCH",
          title: "Worker config attestation mismatch",
          detail: "Worker sync rejected because its config version or DPO identifier differs from the approved release.",
          status: 403,
          category: "authorization",
          retryable: false,
          context: {
            clientId,
            configHash: heartbeat.configHash,
          },
        });
      }
    }

    await this.repository.insertWorkerConfigHeartbeat({
      organizationId: client.organization_id,
      clientId,
      configHash: heartbeat.configHash,
      configVersion: heartbeat.configVersion,
      dpoIdentifier: heartbeat.dpoIdentifier,
      now: this.now(),
    });

    const task = await this.repository.claimNextTask(
      clientId,
      clientName,
      this.now()
    );

    if (!task) {
      return { pending: false as const };
    }

    return {
      pending: true as const,
      task: {
        id: task.id,
        task_type: task.task_type,
        payload: task.payload,
      },
    };
  }

  /**
   * Cancels a queued erasure request before the cooldown window completes.
   *
   * @param idempotencyKey - Request idempotency UUID.
   * @returns Cancellation payload or `null` when request does not exist.
   * @throws {ApiError} When request is already beyond cancellable states.
   */
  async cancelErasureRequest(idempotencyKey: string, organizationId?: string) {
    const existingJob = await this.repository.getJobByIdempotencyKey(idempotencyKey, organizationId);
    if (!existingJob) {
      return null;
    }

    if (existingJob.status === "CANCELLED") {
      return {
        request_id: existingJob.id,
        status: existingJob.status,
        cancelled: true as const,
        idempotent_replay: true as const,
      };
    }

    if (existingJob.status !== "WAITING_COOLDOWN") {
      fail({
        code: "API_ERASURE_REQUEST_CANCEL_INVALID_STATE",
        title: "Erasure request cannot be cancelled",
        detail: `Erasure request ${existingJob.id} is already ${existingJob.status}.`,
        status: 409,
        category: "concurrency",
        retryable: false,
      });
    }

    const cancelled = await this.repository.cancelWaitingJobByIdempotencyKey(
      idempotencyKey,
      this.now(),
      organizationId
    );
    if (!cancelled) {
      fail({
        code: "API_ERASURE_REQUEST_CANCEL_RACE",
        title: "Cancellation race detected",
        detail: `Erasure request ${existingJob.id} changed state before cancellation completed.`,
        status: 409,
        category: "concurrency",
        retryable: true,
      });
    }

    return {
      request_id: cancelled.id,
      status: cancelled.status,
      cancelled: true as const,
      idempotent_replay: false as const,
    };
  }

  /**
   * Finalizes an active worker task.
   *
   * @param taskId - Task UUID.
   * @param input - Worker ack payload.
   * @returns Updated task status payload or `null` when task is unknown.
   */
  async ackWorkerTask(taskId: string, input: WorkerAckInput) {
    const now = this.now();
    const task = await this.repository.ackTask(
      taskId,
      input.status,
      input.result,
      now
    );
    if (!task) {
      return null;
    }

    if (
      input.status === "completed" &&
      task.task_type === "VAULT_USER" &&
      task.status === "COMPLETED" &&
      task.payload.shadow_mode === true &&
      this.shadowRequiredSuccesses > 0
    ) {
      await this.repository.recordShadowVaultSuccessForTask(
        task.id,
        task.client_id,
        this.shadowRequiredSuccesses,
        now
      );
    }

    return {
      task_id: task.id,
      status: task.status,
    };
  }

  /**
   * Extends a dispatched worker task lease while long-running local mutation continues.
   *
   * @param taskId - Active task UUID.
   * @param clientId - Authenticated worker client id.
   * @param workerClientName - Worker name/header used when the task was leased.
   * @returns Updated lease metadata, or `null` when the task is no longer actively leased.
   */
  async heartbeatWorkerTask(taskId: string, clientId: string, workerClientName: string) {
    const task = await this.repository.extendTaskLease(
      taskId,
      clientId,
      workerClientName,
      this.now()
    );

    if (!task) {
      return null;
    }

    return {
      task_id: task.id,
      status: task.status,
      lease_expires_at: task.lease_expires_at?.toISOString() ?? null,
    };
  }

  /**
   * Ingests worker outbox events with chain validation and idempotent replay handling.
   *
   * @param input - Validated outbox event from the worker.
   * @param clientId - Authenticated worker client id.
   * @returns Acceptance result with idempotent replay flag.
   * @throws {ApiError} On chain mismatch, payload conflicts, or authorization violations.
   */
  async ingestWorkerOutbox(input: WorkerOutboxEventInput, clientId: string) {
    const now = this.now();
    const job = await this.repository.getJobById(input.request_id);
    if (!job) {
      fail({
        code: "API_OUTBOX_REQUEST_UNKNOWN",
        title: "Unknown request id",
        detail: `Unknown request_id: ${input.request_id}.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    if (job.client_id !== clientId) {
      fail({
        code: "API_OUTBOX_WORKER_UNAUTHORIZED",
        title: "Worker is not authorized for this request",
        detail: `Worker is not authorized to append events for request ${input.request_id}.`,
        status: 403,
        category: "authorization",
        retryable: false,
      });
    }

    if (job.subject_opaque_id !== input.subject_opaque_id) {
      fail({
        code: "API_OUTBOX_SUBJECT_MISMATCH",
        title: "Subject mismatch",
        detail: `subject_opaque_id does not match request ${input.request_id}.`,
        status: 409,
        category: "integrity",
        retryable: false,
      });
    }

    assertOutboxMetadata(job, input);

    const existingEvent = await this.repository.getAuditEventByIdempotencyKey(
      input.idempotency_key
    );
    if (existingEvent) {
      if (isReplayEquivalent(existingEvent, input, clientId)) {
        await this.applyOutboxLifecycle(job, input, now);
        const usageInserted = await this.repository.insertUsageEvent({
          billingKey: `outbox:${input.idempotency_key}`,
          organizationId: job.organization_id,
          clientId,
          erasureJobId: job.id,
          eventType: input.event_type,
          units: 1,
          metadata: {
            replay: true,
          },
          occurredAt: now,
        });
        recordWorkerOutboxEvent(input.event_type, "replay");
        recordUsageEvent(input.event_type, usageInserted ? "inserted" : "replay");
        return { accepted: true as const, idempotent_replay: true as const };
      }

      fail({
        code: "API_OUTBOX_IDEMPOTENCY_CONFLICT",
        title: "Outbox idempotency conflict",
        detail: `idempotency_key ${input.idempotency_key} already exists with a different event payload.`,
        status: 409,
        category: "integrity",
        retryable: false,
      });
    }

    assertAllowedOutboxTransition(job, input.event_type);

    const payloadBytes = new TextEncoder().encode(
      canonicalJsonStringify(input.payload)
    ).byteLength;
    if (payloadBytes > this.maxOutboxPayloadBytes) {
      fail({
        code: "API_OUTBOX_PAYLOAD_TOO_LARGE",
        title: "Outbox payload too large",
        detail: `Outbox payload exceeds ${this.maxOutboxPayloadBytes} bytes.`,
        status: 413,
        category: "validation",
        retryable: false,
      });
    }

    const workerCurrentHash = await computeWormHash(
      input.previous_hash,
      input.payload,
      input.idempotency_key
    );
    if (workerCurrentHash !== input.current_hash) {
      fail({
        code: "API_OUTBOX_CURRENT_HASH_INVALID",
        title: "Outbox chain hash invalid",
        detail: "current_hash is invalid for the provided payload chain.",
        status: 400,
        category: "integrity",
        retryable: false,
      });
    }

    const latestHash = (await this.repository.getLatestAuditHash(clientId)) ?? "GENESIS";
    const ledgerPreviousHash = latestHash;
    const ledgerCurrentHash =
      input.previous_hash === latestHash
        ? input.current_hash
        : await computeWormHash(latestHash, input.payload, input.idempotency_key);

    const inserted = await this.repository.insertAuditLedgerEvent({
      organizationId: job.organization_id,
      clientId,
      idempotencyKey: input.idempotency_key,
      eventType: input.event_type,
      payload: buildOutboxPayload(input),
      previousHash: ledgerPreviousHash,
      currentHash: ledgerCurrentHash,
      now,
    });

    if (!inserted) {
      const racedEvent = await this.repository.getAuditEventByIdempotencyKey(
        input.idempotency_key
      );
      if (racedEvent && isReplayEquivalent(racedEvent, input, clientId)) {
        await this.applyOutboxLifecycle(job, input, now);
        const usageInserted = await this.repository.insertUsageEvent({
          billingKey: `outbox:${input.idempotency_key}`,
          organizationId: job.organization_id,
          clientId,
          erasureJobId: job.id,
          eventType: input.event_type,
          units: 1,
          metadata: {
            replay: true,
          },
          occurredAt: now,
        });
        recordWorkerOutboxEvent(input.event_type, "replay");
        recordUsageEvent(input.event_type, usageInserted ? "inserted" : "replay");
        return { accepted: true as const, idempotent_replay: true as const };
      }

      fail({
        code: "API_OUTBOX_RACE_CONFLICT",
        title: "Outbox idempotency race conflict",
        detail: `idempotency_key ${input.idempotency_key} conflicted with a different event during insert.`,
        status: 409,
        category: "concurrency",
        retryable: true,
      });
    }

    await this.applyOutboxLifecycle(job, input, now);
    const usageInserted = await this.repository.insertUsageEvent({
      billingKey: `outbox:${input.idempotency_key}`,
      organizationId: job.organization_id,
      clientId,
      erasureJobId: job.id,
      eventType: input.event_type,
      units: 1,
      metadata: {
        current_hash: ledgerCurrentHash,
        worker_current_hash: input.current_hash,
        chain_rebased: input.previous_hash !== ledgerPreviousHash,
      },
      occurredAt: now,
    });
    recordWorkerOutboxEvent(input.event_type, "accepted");
    recordUsageEvent(input.event_type, usageInserted ? "inserted" : "replay");

    return { accepted: true as const, idempotent_replay: false as const };
  }

  /**
   * Fetches a minted Certificate of Erasure by request id.
   *
   * @param requestId - Erasure request UUID.
   * @returns Certificate row or `null`.
   */
  async getCertificate(requestId: string, organizationId?: string) {
    return this.repository.getCertificateByRequestId(requestId, organizationId);
  }

  /**
   * Verifies the stored Ed25519 Certificate of Erasure signature against its payload.
   *
   * @param requestId - Erasure request UUID.
   * @param organizationId - Optional tenant scope enforced by caller auth.
   * @returns Verification result or `null` when the certificate is missing.
   */
  async verifyCertificate(requestId: string, organizationId?: string) {
    const cert = await this.repository.getCertificateByRequestId(requestId, organizationId);
    if (!cert) {
      return null;
    }

    const valid = await verifyEd25519Signature(
      cert.public_key_spki_base64,
      cert.signature_base64,
      cert.payload
    );

    return {
      request_id: cert.request_id,
      valid,
      algorithm: cert.algorithm,
      key_id: cert.key_id,
      signature_base64: cert.signature_base64,
      public_key_spki_base64: cert.public_key_spki_base64,
      payload_hash: await computeSha256Hex(canonicalJsonStringify(cert.payload)),
      verified_at: this.now().toISOString(),
    };
  }

  /**
   * Generates a signed PDF artifact for a completed erasure request.
   *
   * @param requestId - Erasure request UUID.
   * @returns PDF buffer or `null` when certificate is not yet minted.
   */
  async getCertificatePdf(requestId: string, organizationId?: string): Promise<Uint8Array | null> {
    const cert = await this.repository.getCertificateByRequestId(requestId, organizationId);
    if (!cert) {
      return null;
    }

    const payload = cert.payload as Record<string, unknown>;
    const blobReceipts = (payload.blob_receipts as any[]) ?? [];

    let blobSummary: ProofOfErasureData["blobSummary"] | undefined;
    if (blobReceipts.length > 0) {
      blobSummary = {
        totalObjects: blobReceipts.length,
        totalVersionsPurged: blobReceipts.reduce((sum, r) => sum + (r.versionCount ?? 0), 0),
        provider: blobReceipts[0]?.provider === "aws_s3" ? "Amazon S3" : blobReceipts[0]?.provider ?? "External Object Storage",
      };
    }

    const proof: ProofOfErasureData = {
      requestId: cert.request_id,
      subjectOpaqueId: cert.subject_opaque_id,
      method: cert.method,
      legalFramework: cert.legal_framework,
      appliedRuleName: (payload.applied_rule_name as string) ?? null,
      appliedRuleCitation: (payload.applied_rule_citation as string) ?? null,
      shreddedAt: cert.shredded_at.toISOString(),
      finalWormHash: (payload.final_worm_hash as string) ?? null,
      postgresTransactionIds: Array.isArray(payload.postgres_transaction_ids)
        ? payload.postgres_transaction_ids.filter((value): value is string => typeof value === "string")
        : [],
      blobSummary,
      signature: {
        algorithm: cert.algorithm,
        keyId: cert.key_id,
        signatureBase64: cert.signature_base64,
        publicKeySpkiBase64: cert.public_key_spki_base64,
      },
    };

    return this.pdfGenerator.generate(proof);
  }

  /**
   * Scans for unarchived certificates and uploads them to WORM S3 storage.
   *
   * @param options - S3 bucket, region, and credentials for archival.
   * @returns Number of successfully archived certificates.
   */
  async archivePendingCertificates(options: {
    bucket: string;
    region: string;
    accessKeyId: string;
    secretAccessKey: string;
    endpoint?: string;
  }): Promise<number> {
    const now = this.now();
    const certs = await this.repository.claimUnarchivedCertificates(now, 20);
    if (certs.length === 0) {
      return 0;
    }

    let count = 0;

    for (const cert of certs) {
      if (!cert.archive_lease_token) {
        continue;
      }

      try {
        const pdf = await this.getCertificatePdf(cert.request_id);
        if (!pdf) {
          throw new Error("Certificate PDF rendering returned no artifact");
        }

        const retentionDays = cert.archive_retention_days ?? 365;
        const retainUntil = new Date(now.getTime() + retentionDays * 24 * 60 * 60 * 1000);
        const objectKey = `certificates/${cert.request_id}.pdf`;

        const receipt = await s3PutObject({
          bucket: options.bucket,
          key: objectKey,
          region: options.region,
          body: pdf,
          contentType: "application/pdf",
          endpointOverride: options.endpoint,
          credentials: {
            accessKeyId: options.accessKeyId,
            secretAccessKey: options.secretAccessKey,
          },
          objectLockMode: "COMPLIANCE",
          retainUntilDate: retainUntil,
        });

        await this.repository.markCertificateArchived(cert.request_id, cert.archive_lease_token, this.now(), {
          bucket: options.bucket,
          objectKey,
          objectETag: receipt.eTag,
          objectVersionId: receipt.versionId,
          retentionUntil: retainUntil,
        });
        count++;

        logger.info(
          { requestId: cert.request_id, bucket: options.bucket },
          "Certificate archived to WORM storage"
        );
      } catch (err) {
        const attempt = cert.archive_attempt_count + 1;
        const failureNow = this.now();
        const delayMs = Math.min(Math.pow(2, cert.archive_attempt_count) * 60_000, 6 * 60 * 60 * 1000);
        await this.repository.markCertificateArchiveFailed(
          cert.request_id,
          cert.archive_lease_token,
          err instanceof Error ? err.message : String(err),
          new Date(failureNow.getTime() + delayMs),
          failureNow
        );
        logger.error(
          { requestId: cert.request_id, attempt, err },
          "Failed to archive certificate to S3"
        );
      }
    }

    return count;
  }

  /**
   * Processes a batch of pending webhooks with exponential backoff retries.
   *
   * @returns Number of successfully delivered webhooks.
   */
  async processWebhookOutbox(): Promise<number> {
    const now = this.now();
    const webhooks = await this.repository.claimPendingWebhooks(10, now);
    if (webhooks.length === 0) {
      return 0;
    }

    let successCount = 0;

    for (const webhook of webhooks) {
      try {
        const safeUrl = await assertSafeWebhookDispatchTarget(webhook.url);
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.webhookTimeoutMs);

        try {
          const response = await fetch(safeUrl, {
            method: "POST",
            headers: {
              "content-type": "application/json",
              "idempotency-key": `webhook:${webhook.id}`,
              ...safeOutboundWebhookHeaders(webhook.headers),
            },
            body: JSON.stringify(webhook.payload),
            signal: controller.signal,
            redirect: "error",
          });

          if (!response.ok) {
            throw new Error(`Webhook responded with HTTP ${response.status}`);
          }

          if (!webhook.lease_token) {
            continue;
          }

          await this.repository.markWebhookProcessed(webhook.id, webhook.lease_token, this.now());
          successCount++;

          logger.info({ webhookId: webhook.id, jobId: webhook.job_id }, "Webhook delivered successfully");
        } finally {
          clearTimeout(timer);
        }
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : String(err);
        // Exponential backoff: 1m, 2m, 4m, 8m... up to ~17 hours at attempt 10
        const delayMs = Math.pow(2, webhook.attempt_count) * 60 * 1000;
        const nextAttemptAt = new Date(now.getTime() + delayMs);
        const isPermanent = webhook.attempt_count >= 10;
        if (!webhook.lease_token) {
          continue;
        }

        await this.repository.markWebhookFailed(
          webhook.id,
          webhook.lease_token,
          errorMessage,
          nextAttemptAt,
          isPermanent,
          this.now()
        );

        logger.warn(
          { webhookId: webhook.id, attempt: webhook.attempt_count + 1, err },
          "Webhook delivery attempt failed"
        );
      }
    }

    return successCount;
  }
}
