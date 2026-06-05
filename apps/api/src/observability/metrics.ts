/**
 * No-op metric recording for open-source version.
 * Prometheus/prom-client has been removed to simplify the codebase.
 */

export interface OperationalMetricSnapshotRow {
  metric: "task_queue" | "webhook_outbox" | "certificate_archive";
  label_a: string;
  label_b: string;
  value: number;
}

/**
 * Increments the rate-limit rejection counter.
 *
 * @param _path - Request path rejected by the limiter.
 */
export function recordRateLimit(_path: string): void {
  // No-op in open-source version
}

/**
 * Records worker outbox ingestion outcomes.
 *
 * @param _eventType - Worker event type.
 * @param _result - Acceptance result label.
 */
export function recordWorkerOutboxEvent(
  _eventType: string,
  _result: "accepted" | "replay"
): void {
  // No-op in open-source version
}
