import type { Sql } from "@/types";
import type { MockMailer } from "../engine";
import type { WorkerProblemDetails } from "@/errors";
import type { DispatchNoticeResult, ShredUserResult, VaultUserResult, WorkerSecrets } from "../engine";
import type { OutboxEvent, S3Client } from "../network";
import type { WorkerConfig } from "../config";

/**
 * Normalizes task payload accepted from Control Plane. 
 */
export interface WorkerTaskPayload {
  request_id?: string;
  subject_opaque_id?: string;
  idempotency_key?: string;
  trigger_source?: string;
  actor_opaque_id?: string;
  legal_framework?: string;
  request_timestamp?: string;
  tenant_id?: string;
  cooldown_days?: number;
  shadow_mode?: boolean;
  webhook_url?: string;
  userId?: number;
  now?: string;
  shadowMode?: boolean;
}

/**
 * Leased task envelope returned by Control Plan sync.
 */
export interface WorkerTask {
  id: string;
  task_type: "COMPILE_DAG" | "VAULT_USER" | "NOTIFY_USER" | "SHRED_USER" | string;
  payload: WorkerTaskPayload;
}
/**
 * Control Plane sync response shape.
 */
export interface SyncTaskResponse {
  pending: boolean;
  task?: WorkerTask;
}

export interface CompileDagResult {
  action: "compiled_dag";
  userHash: null;
  dryRun: false;
  compiledTargetCount: number;
}

export type TaskExecutionResult = CompileDagResult | VaultUserResult | DispatchNoticeResult | ShredUserResult;

/**
 * Failed-task acknowledgement payload.
 */
export interface TaskFailureResult {
  error: WorkerProblemDetails;
}

export type TaskAckPayload = TaskExecutionResult | TaskFailureResult;

/**
 * Network contract required by the worker loop.
 */
export interface ApiClient {
  syncTask(): Promise<SyncTaskResponse>;
  ackTask(taskId: string, status: "completed" | "failed", result: TaskAckPayload): Promise<boolean>;
  heartbeatTask?(taskId: string): Promise<boolean>;
  pushOutboxEvent(event: OutboxEvent): Promise<boolean>;
}

/**
 * Dependencies required to construct the compliance worker.
 */
export interface ComplianceWorkerOptions {
  sql: Sql;
  sqlReplica?: Sql;
  secrets: WorkerSecrets;
  config: WorkerConfig;
  apiClient: ApiClient;
  mailer: MockMailer;
  s3Client?: S3Client;
  taskHeartbeatIntervalMs?: number;
}