import {
  dispatchPreErasureNotice,
  shredUser,
  vaultUser,
  type MockMailer,
  type WorkerSecrets
} from "@modules/engine";
import type { WorkerConfig } from "@modules/config";
import { processOutbox, type ProcessOutboxResult, type S3Client } from "@modules/network";
import type { Sql } from "@/types";
import { fail, serializeWorkerError } from "@/errors";
import { logError, workerLogger } from "@/utils";
import type { ApiClient, ComplianceWorkerOptions, TaskExecutionResult, WorkerTask } from "./types";
import { acknowledgeTask, resolveTaskSubject } from "./tasks";

/**
 * Orchestrates Control Plane tasks and enforces fail-closed execution semantics.
 */
export class ComplianceWorker {
  private readonly sql: Sql;
  private readonly sqlReplica?: Sql;
  private readonly secrets: WorkerSecrets;
  private readonly config: WorkerConfig;
  private readonly apiClient: ApiClient;
  private readonly mailer: MockMailer;
  private readonly s3Client?: S3Client;
  private readonly taskHeartbeatIntervalMs: number;

  constructor(options: ComplianceWorkerOptions) {
    this.sql = options.sql;
    this.sqlReplica = options.sqlReplica;
    this.secrets = options.secrets;
    this.config = options.config;
    this.apiClient = options.apiClient;
    this.mailer = options.mailer;
    this.s3Client = options.s3Client;
    this.taskHeartbeatIntervalMs = Math.max(1_000, options.taskHeartbeatIntervalMs ?? 30_000);
  }

  private startTaskHeartbeat(task: WorkerTask): () => void {
    if (!this.apiClient.heartbeatTask) {
      return () => undefined;
    }

    const heartbeat = this.apiClient.heartbeatTask;
    const timer = setInterval(() => {
      void heartbeat(task.id).catch((error) => {
        logError(
          workerLogger.child({ taskId: task.id, taskType: task.task_type }),
          error,
          "Task heartbeat failed"
        );
      });
    }, this.taskHeartbeatIntervalMs);

    return () => clearInterval(timer);
  }

  private async executeTask(task: WorkerTask, now: Date): Promise<TaskExecutionResult> {
    switch (task.task_type) {
      case "COMPILE_DAG":
        return {
          action: "compiled_dag",
          userHash: null,
          dryRun: false,
          compiledTargetCount: this.config.rules?.[0]?.targets.length ?? 0,
        };

      case "VAULT_USER":
        return vaultUser(
          this.sql,
          task.payload.subject_opaque_id ?? task.payload.userId ?? "",
          this.secrets,
          {
            appSchema: this.config.database.app_schema,
            engineSchema: this.config.database.engine_schema,
            defaultRetentionYears: this.config.compliance_policy.default_retention_years,
            noticeWindowHours: this.config.compliance_policy.notice_window_hours,
            graphMaxDepth: this.config.graph.max_depth,
            rootTable: this.config.graph.root_table,
            rootIdColumn: this.config.graph.root_id_column,
            rootPiiColumns: this.config.graph.root_pii_columns,
            satelliteTargets: this.config.satellite_targets,
            blobTargets: this.config.blob_targets,
            compiledTargets: this.config.rules?.[0]?.targets,
            retentionRules: this.config.compliance_policy.retention_rules,
            tenantId: task.payload.tenant_id,
            requestId: task.payload.request_id,
            subjectOpaqueId: task.payload.subject_opaque_id,
            triggerSource: task.payload.trigger_source,
            actorOpaqueId: task.payload.actor_opaque_id,
            legalFramework: task.payload.legal_framework,
            requestTimestamp: task.payload.request_timestamp,
            shadowMode: task.payload.shadow_mode ?? task.payload.shadowMode,
            sqlReplica: this.sqlReplica,
            s3Client: this.s3Client,
            now,
          }
        );

      case "NOTIFY_USER":
        return dispatchPreErasureNotice(this.sql, resolveTaskSubject(task), this.secrets, this.mailer, {
          appSchema: this.config.database.app_schema,
          engineSchema: this.config.database.engine_schema,
          rootTable: this.config.graph.root_table,
          notificationLeaseSeconds: this.config.security.notification_lease_seconds,
          noticeEmailColumn: this.config.graph.notice_email_column,
          noticeNameColumn: this.config.graph.notice_name_column,
          rootPiiColumns: this.config.graph.root_pii_columns,
        });

      case "SHRED_USER":
        return shredUser(this.sql, resolveTaskSubject(task), {
          appSchema: this.config.database.app_schema,
          engineSchema: this.config.database.engine_schema,
          rootTable: this.config.graph.root_table,
          hmacKey: this.secrets.hmacKey,
          s3Client: this.s3Client,
          now,
        });

      default:
        fail({
          code: "TASK_TYPE_UNKNOWN",
          title: "Unknown task type",
          detail: `Unknown task type: ${task.task_type}.`,
          category: "validation",
          retryable: false,
          context: {
            taskId: task.id,
            taskType: task.task_type,
          },
        });
    }
  }

  /**
   * Processes at most one leased task from the Control Plane.
   *
   * Retryable/fatal errors are rethrown to preserve lease recovery behavior in the caller loop.
   *
   * @returns `true` when a task was claimed (completed or failed-ack), `false` when no task was pending.
   * @throws {WorkerError} On retryable/fatal execution failures.
   */
  async processNextTask(): Promise<boolean> {
    const { pending, task } = await this.apiClient.syncTask();
    if (!pending || !task) {
      return false
    };

    const taskLogger = workerLogger.child({
      taskId: task.id,
      taskType: task.task_type
    });

    try {
      const now = task.payload.now ? new Date(task.payload.now) : new Date();
      const stopHeartbeat = this.startTaskHeartbeat(task);
      let result: TaskExecutionResult;

      try {
        result = await this.executeTask(task, now);
      } finally {
        stopHeartbeat();
      }

      await acknowledgeTask(this.apiClient, task.id, "completed", result)
      taskLogger.info({ action: result.action, uesrHash: result.userHash })

      return true;
    } catch (error) {
      const normalized = logError(taskLogger, error, 'Task execution failed');

      if (normalized.fatal || normalized.retryable) {
        throw normalized;
      }

      await acknowledgeTask(this.apiClient, task.id, "failed", {
        error: serializeWorkerError(normalized, `task:${task.id}`),
      });
      taskLogger.warn({ code: normalized.code }, "Task acknowledged as failed");
      return true;
    }
  }

  /**
   * Processes a bounded number of independent Control Plane tasks concurrently.
   *
   * Each task still owns its own database transaction, lease, heartbeat, and acknowledgement.
   * Fatal failures are rethrown after all in-flight tasks settle so one bad task cannot orphan
   * sibling leases in the same worker loop iteration.
   *
   * @param concurrency - Maximum task claims to attempt in this pass.
   * @returns Number of claimed tasks that completed or were acknowledged as failed.
   * @throws {WorkerError} If any in-flight task reports a fatal/retryable loop-level failure.
   */
  async processTaskBatch(concurrency: number): Promise<number> {
    const width = Math.max(1, Math.floor(concurrency));
    if (width === 1) {
      return await this.processNextTask() ? 1 : 0;
    }

    const results = await Promise.allSettled(
      Array.from({ length: width }, () => this.processNextTask())
    );
    let processed = 0;
    let firstFailure: unknown;

    for (const result of results) {
      if (result.status === "fulfilled") {
        if (result.value) {
          processed += 1;
        }
        continue;
      }

      firstFailure ??= result.reason;
    }

    if (firstFailure) {
      throw firstFailure;
    }

    return processed;
  }

  /**
     * Flushes the local transactional outbox to the Control Plane endpoint.
     *
     * @returns Promise resolved after one outbox processing pass.
     * @throws {WorkerError} When outbox processing detects fatal delivery/protocol errors.
     */
  async flushOutbox(): Promise<ProcessOutboxResult> {
    return processOutbox(this.sql, async (event) => this.apiClient.pushOutboxEvent(event), {
      engineSchema: this.config.database.engine_schema,
      batchSize: this.config.outbox.batch_size,
      leaseSeconds: this.config.outbox.lease_seconds,
      maxAttempts: this.config.outbox.max_attempts,
      baseBackoffMs: this.config.outbox.base_backoff_ms,
    });
  }
}