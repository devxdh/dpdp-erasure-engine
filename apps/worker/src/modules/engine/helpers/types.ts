/**
 * Default application schema used by tests and local worker bootstrap.
 */
export const DEFAULT_APP_SCHEMA = "mock_app";

/**
 * Default worker-owned engine schema.
 */
export const DEFAULT_ENGINE_SCHEMA = "dpdp_engine";

/**
 * Default notice lead time in hours.
 */
export const DEFAULT_NOTICE_WINDOW_HOURS = 48;

/**
 * Default retention period when no evidence rule matches.
 */
export const DEFAULT_RETENTION_YEARS = 0;

/**
 * Default recursive graph traversal limit.
 */
export const DEFAULT_GRAPH_MAX_DEPTH = 32;

/**
 * Sentinel payload stored after cryptographic shredding.
 */
export const DESTROYED_PII_SENTINEL = Object.freeze({ v: 1, destroyed: true });

/**
 * Durable record shape stored in `${engineSchema}.pii_vault`.
 *
 * Legal metadata is treated as append-only, while lifecycle timestamps and lease fields remain
 * mutable as the state machine advances.
 */
export interface VaultRecord {
  user_uuid_hash: string;
  request_id: string | null;
  tenant_id: string;
  root_schema: string;
  root_table: string;
  root_id: string;
  pseudonym: string;
  encrypted_pii: { v?: number; data?: string; destroyed?: boolean };
  salt: string;
  dependency_count: number;
  trigger_source: string | null;
  legal_framework: string | null;
  actor_opaque_id: string | null;
  applied_rule_name: string | null;
  applied_rule_citation: string | null;
  retention_expiry: Date;
  notification_due_at: Date;
  notification_sent_at: Date | null;
  notification_lock_id: string | null;
  notification_lock_expires_at: Date | null;
  shredded_at: Date | null;
  created_at: Date;
  updated_at: Date;
}