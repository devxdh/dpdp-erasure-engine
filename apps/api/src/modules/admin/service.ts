import { fail } from "@/errors";
import { computeTokenHash, type ControlPlaneRepository } from "@modules/control-plane";
import type {
  AdminCreateApiKeyInput,
  AdminAuditExportQueryInput,
  AdminApproveWorkerConfigInput,
  AdminBulkPurgeInput,
  AdminCreateClientInput,
  AdminCreateOrganizationInput,
  AdminErasureRequestQueryInput,
  AdminProviderCompletionTargetInput,
  AdminRotateWebhookSecretInput,
} from "./schemas";

export interface AdminTenantContext {
  organizationId: string;
}

const textEncoder = new TextEncoder();

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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

export interface AdminServiceOptions {
  repository: ControlPlaneRepository;
  now?: () => Date;
}

function redactProviderCompletionTarget<T extends { auth_header_value: string | null }>(target: T) {
  return {
    ...target,
    auth_header_value: target.auth_header_value ? "[REDACTED]" : null,
  };
}

/**
 * Operator-facing service for client lifecycle, DLQ recovery, usage reporting, and audit export.
 */
export class AdminService {
  private readonly repository: ControlPlaneRepository;
  private readonly now: () => Date;

  constructor(options: AdminServiceOptions) {
    this.repository = options.repository;
    this.now = options.now ?? (() => new Date());
  }

  /**
   * Lists registered worker clients with their current auth and activity metadata.
   *
   * @returns Persisted worker clients.
   */
  async listClients(tenant: AdminTenantContext) {
    return this.repository.listClients(tenant.organizationId);
  }

  /**
   * Creates a new worker client and returns its one-time raw token.
   *
   * @param input - Client identity metadata.
   * @returns Persisted client metadata plus the issued raw bearer token.
   * @throws {ApiError} When the client name already exists.
   */
  async createClient(input: AdminCreateClientInput, tenant: AdminTenantContext) {
    const existing = await this.repository.getClientByName(input.name, tenant.organizationId);
    if (existing) {
      fail({
        code: "API_ADMIN_CLIENT_EXISTS",
        title: "Client already exists",
        detail: `Worker client ${input.name} already exists.`,
        status: 409,
        category: "integrity",
        retryable: false,
      });
    }

    const rawToken = `wkr_${globalThis.crypto.randomUUID()}`;
    const currentKeyId = `key_${globalThis.crypto.randomUUID()}`;
    const now = this.now();
    const client = await this.repository.createClient({
      organizationId: tenant.organizationId,
      name: input.name,
      displayName: input.display_name ?? null,
      workerApiKeyHash: await computeTokenHash(rawToken),
      currentKeyId,
      requireApprovedConfig: input.require_approved_config,
      now,
    });

    return {
      client,
      bearer_token: rawToken,
    };
  }

  /**
   * Rotates the raw bearer token for an existing worker client.
   *
   * @param name - Stable worker client name.
   * @returns Updated client metadata plus the one-time replacement token.
   * @throws {ApiError} When the client does not exist.
   */
  async rotateClientKey(name: string, tenant: AdminTenantContext) {
    const rawToken = `wkr_${globalThis.crypto.randomUUID()}`;
    const currentKeyId = `key_${globalThis.crypto.randomUUID()}`;
    const client = await this.repository.rotateClientKey({
      name,
      organizationId: tenant.organizationId,
      workerApiKeyHash: await computeTokenHash(rawToken),
      currentKeyId,
      now: this.now(),
    });

    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return {
      client,
      bearer_token: rawToken,
    };
  }

  /**
   * Rotates the client-routed provider webhook secret with an overlap window.
   *
   * The new secret is returned once for provider-side configuration. During the grace period
   * the ingestion router accepts both the new and previous secret, preventing downtime while
   * OneTrust/Jira/Zendesk settings propagate.
   *
   * @param name - Stable worker client name.
   * @param input - Previous-secret grace window.
   * @param tenant - Authenticated tenant context.
   * @returns Updated client metadata plus the one-time replacement webhook secret.
   * @throws {ApiError} When the client does not exist.
   */
  async rotateClientWebhookSecret(
    name: string,
    input: AdminRotateWebhookSecretInput,
    tenant: AdminTenantContext
  ) {
    const rawSecret = `whsec_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const existing = await this.repository.getClientByName(name, tenant.organizationId);
    const client = existing?.webhook_signing_secret
      ? await this.repository.rotateClientWebhookSecret({
        name,
        organizationId: tenant.organizationId,
        webhookSigningSecret: rawSecret,
        previousSecretGraceHours: input.previous_secret_grace_hours,
        now: this.now(),
      })
      : await this.repository.setClientWebhookSecret({
        name,
        organizationId: tenant.organizationId,
        webhookSigningSecret: rawSecret,
        now: this.now(),
      });

    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return {
      client,
      webhook_signing_secret: rawSecret,
    };
  }

  /**
   * Lists configured provider completion callbacks for one worker client.
   *
   * @param name - Stable worker client name.
   * @param tenant - Authenticated tenant context.
   * @returns Tenant-owned completion targets.
   */
  async listProviderCompletionTargets(name: string, tenant: AdminTenantContext) {
    const client = await this.repository.getClientByName(name, tenant.organizationId);
    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    const targets = await this.repository.listProviderCompletionTargets(tenant.organizationId, name);
    return targets.map(redactProviderCompletionTarget);
  }

  /**
   * Configures the outbound completion callback used to close GRC tickets.
   *
   * The target is called after the terminal Certificate of Erasure is minted. Provider API
   * credentials remain tenant-owned and can be omitted when the external platform uses an
   * unauthenticated internal webhook receiver.
   *
   * @param name - Stable worker client name.
   * @param provider - Provider slug from the unified ingestion route.
   * @param input - Completion URL and optional auth header.
   * @param tenant - Authenticated tenant context.
   * @returns Persisted completion target.
   */
  async upsertProviderCompletionTarget(
    name: string,
    provider: "onetrust" | "jira" | "zendesk",
    input: AdminProviderCompletionTargetInput,
    tenant: AdminTenantContext
  ) {
    const target = await this.repository.upsertProviderCompletionTarget({
      organizationId: tenant.organizationId,
      clientName: name,
      provider,
      completionUrl: input.completion_url,
      authHeaderName: input.auth_header_name ?? null,
      authHeaderValue: input.auth_header_value ?? null,
      isActive: input.is_active,
      now: this.now(),
    });

    if (!target) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return redactProviderCompletionTarget(target);
  }

  /**
   * Disables a worker client without deleting its audit history.
   *
   * @param name - Stable worker client name.
   * @returns Updated client row.
   * @throws {ApiError} When the client does not exist.
   */
  async deactivateClient(name: string, tenant: AdminTenantContext) {
    const client = await this.repository.setClientActiveState(name, false, tenant.organizationId);
    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }
    return client;
  }

  async listWorkerConfigReleases(name: string, tenant: AdminTenantContext) {
    const client = await this.repository.getClientByName(name, tenant.organizationId);
    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return this.repository.listWorkerConfigReleases(tenant.organizationId, name);
  }

  async approveWorkerConfigRelease(
    name: string,
    input: AdminApproveWorkerConfigInput,
    tenant: AdminTenantContext
  ) {
    const release = await this.repository.approveWorkerConfigRelease({
      organizationId: tenant.organizationId,
      clientName: name,
      configHash: input.config_hash.toLowerCase(),
      configurationVersion: input.configuration_version,
      dpoIdentifier: input.dpo_identifier,
      legalReviewDate: input.legal_review_date ?? null,
      allowedLiveMutation: input.allowed_live_mutation,
      notes: input.notes ?? null,
      requireApprovedConfig: input.require_approved_config,
      now: this.now(),
    });

    if (!release) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return release;
  }

  async revokeWorkerConfigRelease(name: string, configHash: string, tenant: AdminTenantContext) {
    const release = await this.repository.revokeWorkerConfigRelease(
      tenant.organizationId,
      name,
      configHash,
      this.now()
    );

    if (!release) {
      fail({
        code: "API_ADMIN_CONFIG_RELEASE_NOT_FOUND",
        title: "Config release not found",
        detail: `Config release ${configHash} for worker client ${name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    return release;
  }

  /**
   * Lists dead-letter tasks currently requiring operator review.
   *
   * @returns Dead-letter task rows.
   */
  async listDeadLetters(tenant: AdminTenantContext) {
    return this.repository.listDeadLetterTasks(tenant.organizationId);
  }

  /**
   * Requeues a dead-letter task for another execution attempt.
   *
   * @param taskId - Dead-letter task UUID.
   * @returns Updated task row.
   * @throws {ApiError} When the task is missing or not dead-lettered.
   */
  async requeueDeadLetter(taskId: string, tenant: AdminTenantContext) {
    const task = await this.repository.requeueDeadLetterTask(taskId, this.now(), tenant.organizationId);
    if (!task) {
      fail({
        code: "API_ADMIN_DEAD_LETTER_NOT_FOUND",
        title: "Dead-letter task not found",
        detail: `Dead-letter task ${taskId} does not exist or is no longer recoverable.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }
    return task;
  }

  /**
   * Lists erasure requests for operator lifecycle monitoring.
   *
   * @param query - Pagination and optional status filter.
   * @returns Erasure jobs newest first.
   */
  async listErasureRequests(query: AdminErasureRequestQueryInput, tenant: AdminTenantContext) {
    return this.repository.listErasureJobs({
      organizationId: tenant.organizationId,
      status: query.status,
      limit: query.limit,
      offset: query.offset,
    });
  }

  /**
   * Fetches one erasure request lifecycle aggregate.
   *
   * @param requestId - Erasure request UUID.
   * @returns Matching erasure job.
   * @throws {ApiError} When the request does not exist.
   */
  async getErasureRequest(requestId: string, tenant: AdminTenantContext) {
    const job = await this.repository.getJobById(requestId, tenant.organizationId);
    if (!job) {
      fail({
        code: "API_ADMIN_ERASURE_REQUEST_NOT_FOUND",
        title: "Erasure request not found",
        detail: `Erasure request ${requestId} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }
    return job;
  }

  /**
   * Queues a DPO-approved purge batch using already-discovered opaque subject ids.
   *
   * The Control Plane does not inspect tenant databases. A worker-side purge selector or
   * client-owned review process must produce these opaque ids before this method is called.
   * Idempotency is deterministic per `(organization, client, batch_id, subject_opaque_id)`.
   *
   * @param input - Worker client, DPO batch id, opaque subjects, and legal metadata.
   * @param tenant - Authenticated tenant context.
   * @returns Inserted/duplicate counts for the batch.
   * @throws {ApiError} When the target client is missing, inactive, or not live-enabled.
   */
  async createBulkPurge(input: AdminBulkPurgeInput, tenant: AdminTenantContext) {
    const client = await this.repository.getClientByName(input.client_name, tenant.organizationId);
    if (!client) {
      fail({
        code: "API_ADMIN_CLIENT_NOT_FOUND",
        title: "Client not found",
        detail: `Worker client ${input.client_name} does not exist.`,
        status: 404,
        category: "validation",
        retryable: false,
      });
    }

    if (!client.is_active) {
      fail({
        code: "API_ADMIN_CLIENT_INACTIVE",
        title: "Client inactive",
        detail: `Worker client ${input.client_name} is inactive and cannot receive purge jobs.`,
        status: 409,
        category: "configuration",
        retryable: false,
      });
    }

    if (!input.shadow_mode && !client.live_mutation_enabled) {
      fail({
        code: "API_LIVE_MUTATION_BURN_IN_REQUIRED",
        title: "Shadow-mode burn-in required",
        detail: `Worker client ${client.name} must complete ${client.shadow_required_successes} successful shadow-mode vault tasks before bulk purge.`,
        status: 409,
        category: "configuration",
        retryable: false,
        context: {
          clientName: client.name,
          currentSuccesses: client.shadow_success_count,
          requiredSuccesses: client.shadow_required_successes,
        },
      });
    }

    const now = this.now();
    const requestTimestamp = input.request_timestamp ? new Date(input.request_timestamp) : now;
    const rows = await Promise.all(input.subject_opaque_ids.map(async (subjectOpaqueId) => {
      const idempotencyKey = await deterministicUuidFromText(
        `${tenant.organizationId}\n${client.id}\nADMIN_PURGE\n${input.batch_id}\n${subjectOpaqueId}`
      );
      const jobId = globalThis.crypto.randomUUID();
      return {
        jobId,
        taskId: globalThis.crypto.randomUUID(),
        idempotencyKey,
        subjectOpaqueId,
        payload: {
          request_id: jobId,
          subject_opaque_id: subjectOpaqueId,
          idempotency_key: idempotencyKey,
          trigger_source: "ADMIN_PURGE",
          actor_opaque_id: input.actor_opaque_id,
          legal_framework: input.legal_framework,
          request_timestamp: requestTimestamp.toISOString(),
          tenant_id: input.tenant_id,
          cooldown_days: 0,
          shadow_mode: input.shadow_mode,
        },
      };
    }));

    const result = await this.repository.createBulkAdminPurgeJobs({
      organizationId: tenant.organizationId,
      clientId: client.id,
      rows,
      actorOpaqueId: input.actor_opaque_id,
      legalFramework: input.legal_framework,
      requestTimestamp,
      tenantId: input.tenant_id ?? null,
      shadowMode: input.shadow_mode,
      now,
    });

    return {
      batch_id: input.batch_id,
      client_name: client.name,
      submitted: input.subject_opaque_ids.length,
      inserted: result.inserted,
      duplicates: result.duplicates,
      request_ids: result.requestIds,
    };
  }

  /**
   * Exports ordered audit ledger rows for archival and external WORM replication.
   *
   * @param query - Optional client/sequence filters.
   * @returns Ordered audit ledger rows.
   */
  async exportAuditLedger(query: AdminAuditExportQueryInput, tenant: AdminTenantContext) {
    return this.repository.listAuditLedgerEvents({
      organizationId: tenant.organizationId,
      clientName: query.client_name,
      afterLedgerSeq: query.after_ledger_seq,
    });
  }

  /**
   * Recomputes the tenant WORM ledger chain for forensic self-checks.
   *
   * @param query - Optional client filter.
   * @param tenant - Authenticated tenant context.
   * @returns Verification result with first mismatch details when invalid.
   */
  async verifyAuditLedger(query: Pick<AdminAuditExportQueryInput, "client_name">, tenant: AdminTenantContext) {
    return this.repository.verifyAuditLedgerChain({
      organizationId: tenant.organizationId,
      clientName: query.client_name,
    });
  }

  async listMembers(tenant: AdminTenantContext) {
    return this.repository.listOrganizationMembers(tenant.organizationId);
  }

  async createApiKey(input: AdminCreateApiKeyInput, tenant: AdminTenantContext) {
    const rawKey = `avk_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const apiKey = await this.repository.createApiKey({
      organizationId: tenant.organizationId,
      hashedKey: await computeTokenHash(rawKey),
      label: input.label,
      scopes: input.scopes,
      now: this.now(),
    });

    return {
      id: apiKey.id,
      organization_id: apiKey.organization_id,
      label: apiKey.label,
      scopes: apiKey.scopes,
      created_at: apiKey.created_at,
      api_key: rawKey,
    };
  }

  async createOrganization(input: AdminCreateOrganizationInput) {
    const now = this.now();
    const organization = await this.repository.createOrganization({
      name: input.name,
      certificate_archive_retention_days: input.certificate_archive_retention_days,
      ownerEmail: input.owner_email,
      now,
    });
    const rawKey = `avk_${globalThis.crypto.randomUUID().replace(/-/g, "")}`;
    const apiKey = await this.repository.createApiKey({
      organizationId: organization.id,
      hashedKey: await computeTokenHash(rawKey),
      label: "owner-bootstrap",
      scopes: ["*"],
      now,
    });

    return {
      organization,
      api_key: rawKey,
      api_key_id: apiKey.id,
      scopes: apiKey.scopes,
    };
  }
}
