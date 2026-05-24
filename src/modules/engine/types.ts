import type {
  BlobTarget,
  CompiledExecutionTargetInput,
  RetentionRule,
  RootPiiColumns,
  SatelliteTarget,
} from "../config";
import type { S3Client } from "@modules/network";
import type { Sql } from "@/types";

/**
 * Cryptographic material required by worker mutation pipelines.
 */
export interface WorkerSecrets {
  kek: Uint8Array;
  hmacKey?: Uint8Array;
}

// Cryptographic material required by worker mutation pipelines.
export interface WorkerSecrets {
  kek: Uint8Array;
  hmacKey?: Uint8Array;
}

// Schema overrides for multi-tenant or non-default deployments.
export interface WorkerSchemas {
  appSchema?: string;
  engineSchema?: string;
}

// Common runtime controls for worker operations.
export interface WorkerTimingOptions {
  now?: Date,
  defaultRetentionYears?: number;
  noticeWindowHours?: number;
  graphMaxDepth?: number;
  dryRun?: boolean;
}

/**
 * Human-readable execution plan returned during dry-run mode.
 */
export interface DryRunPlan {
  mode: "dry-run";
  summary: string;
  checks: string[];
  cryptoSteps: string[];
  sqlSteps: string[];
}

/**
 * Vault operation options controlling root mutation, retention logic, and transport metadata.
 */
export interface VaultUserOptions extends WorkerSchemas, WorkerTimingOptions {
  rootTable?: string;
  rootIdColumn?: string;
  rootPiiColumns?: RootPiiColumns;
  satelliteTargets?: SatelliteTarget[];
  blobTargets?: BlobTarget[];
  compiledTargets?: CompiledExecutionTargetInput[];
  retentionRules?: readonly RetentionRule[];
  tenantId?: string;
  requestId?: string;
  subjectOpaqueId?: string;
  triggerSource?: string;
  actorOpaqueId?: string;
  legalFramework?: string;
  requestTimestamp?: string;
  shadowMode?: boolean;
  sqlReplica?: Sql;
  s3Client?: S3Client;
}

/**
 * Notice dispatch options.
 */
export interface DispatchNoticeOptions extends WorkerSchemas, WorkerTimingOptions {
  rootTable?: string;
  notificationLeaseSeconds?: number;
  noticeEmailColumn?: string;
  noticeNameColumn?: string;
  rootPiiColumns?: RootPiiColumns;
}

/**
 * Crypto-shred operation options.
 */
export interface ShredUserOptions extends WorkerSchemas, WorkerTimingOptions {
  rootTable?: string;
  requireNotification?: boolean;
  hmacKey?: Uint8Array;
  s3Client?: S3Client;
}

/**
 * Base result fields shared by all worker operations.
 */
export interface WorkerOperationResult {
  userHash: string | null;
  dryRun: boolean;
}

/**
 * Result envelope for vault/hard-delete operations.
 */
export interface VaultUserResult extends WorkerOperationResult {
  action:
  | "vaulted"
  | "already_vaulted"
  | "hard_deleted"
  | "already_hard_deleted"
  | "dry_run";
  dependencyCount: number;
  retentionYears: number | null;
  appliedRuleName: string | null;
  appliedRuleCitation: string | null;
  retentionExpiry: string | null;
  notificationDueAt: string | null;
  pseudonym: string | null;
  outboxEventType: string | null;
  blobProtectionCount?: number;
  plan?: DryRunPlan;
}

/**
 * Result envelope for pre-erasure notice dispatch.
 */
export interface DispatchNoticeResult extends WorkerOperationResult {
  action: "sent" | "already_sent" | "not_due" | "dry_run";
  retentionExpiry: string | null;
  notificationDueAt: string | null;
  notificationSentAt: string | null;
  outboxEventType: string | null;
  plan?: DryRunPlan;
}

/**
 * Result envelope for crypto-shredding.
 */
export interface ShredUserResult extends WorkerOperationResult {
  action: "shredded" | "already_shredded" | "dry_run";
  shreddedAt: string | null;
  outboxEventType: string | null;
  blobReceiptCount?: number;
  plan?: DryRunPlan;
}
