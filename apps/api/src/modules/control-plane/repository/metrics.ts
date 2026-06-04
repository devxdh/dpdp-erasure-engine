import type { RepositoryContext } from "./types";

export interface OperationalMetricRow {
  metric: "task_queue" | "webhook_outbox" | "certificate_archive";
  label_a: string;
  label_b: string;
  value: number;
}

/**
 * Reads low-cardinality operational backlog metrics for Prometheus exposition.
 *
 * @param context - Repository SQL context.
 * @returns Queue/archive/webhook counts grouped by state.
 */
export async function getOperationalMetricRows(
  context: RepositoryContext
): Promise<OperationalMetricRow[]> {
  return context.sql<OperationalMetricRow[]>`
    SELECT 'task_queue'::text AS metric,
           status AS label_a,
           task_type AS label_b,
           COUNT(*)::int AS value
    FROM ${context.sql(context.schema)}.task_queue
    GROUP BY status, task_type

    UNION ALL

    SELECT 'webhook_outbox'::text AS metric,
           status AS label_a,
           'all' AS label_b,
           COUNT(*)::int AS value
    FROM ${context.sql(context.schema)}.webhook_outbox
    GROUP BY status

    UNION ALL

    SELECT 'certificate_archive'::text AS metric,
           archive_status AS label_a,
           'all' AS label_b,
           COUNT(*)::int AS value
    FROM ${context.sql(context.schema)}.certificates
    GROUP BY archive_status
  `;
}
