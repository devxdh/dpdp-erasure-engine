import { Counter, Gauge, Histogram, Registry, collectDefaultMetrics } from "prom-client";
import type { Context, Next } from "hono";
import { routePath } from "hono/route";

const registry = new Registry();
collectDefaultMetrics({ register: registry, prefix: "dpdp_api_process_" });

const httpRequestsTotal = new Counter({
  name: "dpdp_api_http_requests_total",
  help: "Total HTTP requests handled by the Control Plane.",
  labelNames: ["method", "path", "status"] as const,
  registers: [registry],
});

const httpRequestDurationSeconds = new Histogram({
  name: "dpdp_api_http_request_duration_seconds",
  help: "HTTP request latency observed by the Control Plane.",
  labelNames: ["method", "path", "status"] as const,
  buckets: [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2, 5],
  registers: [registry],
});

const rateLimitedTotal = new Counter({
  name: "dpdp_api_rate_limited_total",
  help: "Requests rejected by API rate limiting middleware.",
  labelNames: ["path"] as const,
  registers: [registry],
});

const workerOutboxEventsTotal = new Counter({
  name: "dpdp_api_worker_outbox_events_total",
  help: "Worker outbox events accepted by the Control Plane.",
  labelNames: ["event_type", "result"] as const,
  registers: [registry],
});

const usageEventsTotal = new Counter({
  name: "dpdp_api_usage_events_total",
  help: "Billable usage events persisted by the Control Plane.",
  labelNames: ["event_type", "result"] as const,
  registers: [registry],
});

const taskQueueDepth = new Gauge({
  name: "dpdp_api_task_queue_depth",
  help: "Control Plane task queue depth grouped by status and task type.",
  labelNames: ["status", "task_type"] as const,
  registers: [registry],
});

const webhookOutboxDepth = new Gauge({
  name: "dpdp_api_webhook_outbox_depth",
  help: "Durable outbound webhook queue depth grouped by status.",
  labelNames: ["status"] as const,
  registers: [registry],
});

const certificateArchiveDepth = new Gauge({
  name: "dpdp_api_certificate_archive_depth",
  help: "Certificate archive backlog grouped by archival status.",
  labelNames: ["status"] as const,
  registers: [registry],
});

export interface OperationalMetricSnapshotRow {
  metric: "task_queue" | "webhook_outbox" | "certificate_archive";
  label_a: string;
  label_b: string;
  value: number;
}

function getObservedPath(c: Context): string {
  return routePath(c) || c.req.path;
}

/**
 * Prometheus request instrumentation middleware for the Control Plane.
 *
 * @param c - Hono request context.
 * @param next - Downstream middleware/handler continuation.
 */
export async function apiMetricsMiddleware(c: Context, next: Next): Promise<void> {
  const start = performance.now();
  try {
    await next();
  } finally {
    const path = getObservedPath(c);
    const status = String(c.res.status);
    const durationSeconds = (performance.now() - start) / 1000;
    httpRequestsTotal.inc({
      method: c.req.method,
      path,
      status,
    });
    httpRequestDurationSeconds.observe(
      {
        method: c.req.method,
        path,
        status,
      },
      durationSeconds
    );
  }
}

/**
 * Renders the Prometheus exposition format payload.
 *
 * @returns Metrics text payload.
 */
export async function renderApiMetrics(): Promise<string> {
  return registry.metrics();
}

/**
 * Updates low-cardinality queue/backlog gauges before rendering `/metrics`.
 *
 * @param rows - Snapshot rows read from the Control Plane repository.
 */
export function recordOperationalMetricSnapshot(rows: readonly OperationalMetricSnapshotRow[]): void {
  taskQueueDepth.reset();
  webhookOutboxDepth.reset();
  certificateArchiveDepth.reset();

  for (const row of rows) {
    if (row.metric === "task_queue") {
      taskQueueDepth.set({ status: row.label_a, task_type: row.label_b }, row.value);
    } else if (row.metric === "webhook_outbox") {
      webhookOutboxDepth.set({ status: row.label_a }, row.value);
    } else {
      certificateArchiveDepth.set({ status: row.label_a }, row.value);
    }
  }
}

/**
 * Increments the rate-limit rejection counter.
 *
 * @param path - Request path rejected by the limiter.
 */
export function recordRateLimit(path: string): void {
  rateLimitedTotal.inc({ path });
}

/**
 * Records worker outbox ingestion outcomes.
 *
 * @param eventType - Worker event type.
 * @param result - Acceptance result label.
 */
export function recordWorkerOutboxEvent(
  eventType: string,
  result: "accepted" | "replay"
): void {
  workerOutboxEventsTotal.inc({ event_type: eventType, result });
}

/**
 * Records usage event persistence outcomes.
 *
 * @param eventType - Billable event type.
 * @param result - Insert outcome.
 */
export function recordUsageEvent(
  eventType: string,
  result: "inserted" | "replay"
): void {
  usageEventsTotal.inc({ event_type: eventType, result });
}
