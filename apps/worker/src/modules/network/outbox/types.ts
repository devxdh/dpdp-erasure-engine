// HTTP dispatcher configuration for pushing outbox events to the Control Plane.
export interface FetchDispatcherOptions {
  url: string;
  token?: string;
  clientId?: string;
  requestSigningSecret?: string;
  timeoutMs?: number;
}

// Worker-local outbox row appended inside mutation transactions.
export interface OutboxRow {
  id: string;
  idempotency_key: string;
  user_uuid_hash: string;
  event_type: string;
  payload: unknown;
  previous_hash: string;
  current_hash: string;
  chain_status: "pending" | "finalized";
  status: "pending" | "leased" | "processed" | "dead_letter";
  attempt_count: number;
  lease_token: string | null;
  lease_expires_at: Date | null;
  next_attempt_at: Date;
  processed_at: Date | null;
  last_error: string | null;
  created_at: Date;
  updated_at: Date;
}

/**
 * Aggregated counters from one outbox processing cycle.
 */
export interface ProcessOutboxResult {
  claimed: number;
  processed: number;
  failed: number;
  deadLettered: number;
}

/**
 * Runtime controls for outbox claim and retry behavior.
 */
export interface ProcessOutboxOptions {
  engineSchema?: string;
  batchSize?: number;
  leaseSeconds?: number;
  maxAttempts?: number;
  baseBackoffMs?: number;
  now?: Date;
}

// Outbox row type exposed by the relay pipeline.
export interface OutboxEvent extends OutboxRow { };