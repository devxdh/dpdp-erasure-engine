import type {
  InsertUsageEventInput,
  RepositoryContext,
  UsageEventRow,
  UsageSummaryRow,
} from "./types";

/**
 * Appends a billable usage event idempotently.
 *
 * @param context - Repository SQL context.
 * @param input - Usage event envelope.
 * @returns `true` when inserted, `false` when a duplicate billing key already exists.
 */
export async function insertUsageEvent(
  context: RepositoryContext,
  input: InsertUsageEventInput
): Promise<boolean> {
  const rows = await context.sql<{ id: string }[]>`
    INSERT INTO ${context.sql(context.schema)}.usage_events (
      billing_key,
      organization_id,
      client_id,
      erasure_job_id,
      audit_ledger_id,
      event_type,
      units,
      metadata,
      occurred_at
    ) VALUES (
      ${input.billingKey},
      ${input.organizationId},
      ${input.clientId},
      ${input.erasureJobId ?? null},
      ${input.auditLedgerId ?? null},
      ${input.eventType},
      ${input.units},
      ${context.sql.json(input.metadata as import("postgres").JSONValue)},
      ${input.occurredAt}
    )
    ON CONFLICT (billing_key) DO NOTHING
    RETURNING id
  `;

  return rows.length > 0;
}

/**
 * Lists raw usage events, optionally filtered by client and time window.
 *
 * @param context - Repository SQL context.
 * @param filters - Optional client/time filters.
 * @returns Matching usage events newest first.
 */
export async function listUsageEvents(
  context: RepositoryContext,
  filters: {
    organizationId?: string;
    clientName?: string;
    since?: Date;
    until?: Date;
  } = {}
): Promise<UsageEventRow[]> {
  return context.sql<UsageEventRow[]>`
    SELECT ue.*
    FROM ${context.sql(context.schema)}.usage_events AS ue
    JOIN ${context.sql(context.schema)}.clients AS c
      ON c.id = ue.client_id
    WHERE (${filters.organizationId ?? null}::uuid IS NULL OR ue.organization_id = ${filters.organizationId ?? null})
      AND (${filters.clientName ?? null}::text IS NULL OR c.name = ${filters.clientName ?? null})
      AND (${filters.since ?? null}::timestamptz IS NULL OR ue.occurred_at >= ${filters.since ?? null})
      AND (${filters.until ?? null}::timestamptz IS NULL OR ue.occurred_at <= ${filters.until ?? null})
    ORDER BY ue.occurred_at DESC, ue.created_at DESC
  `;
}

/**
 * Aggregates usage totals by client and event type for lightweight billing/reporting.
 *
 * @param context - Repository SQL context.
 * @param filters - Optional client/time filters.
 * @returns Aggregated usage summary rows.
 */
export async function summarizeUsage(
  context: RepositoryContext,
  filters: {
    organizationId?: string;
    clientName?: string;
    since?: Date;
    until?: Date;
  } = {}
): Promise<UsageSummaryRow[]> {
  return context.sql<UsageSummaryRow[]>`
    SELECT
      ue.organization_id,
      c.name AS client_name,
      ue.event_type,
      SUM(ue.units)::int AS total_units,
      COUNT(*)::int AS event_count
    FROM ${context.sql(context.schema)}.usage_events AS ue
    JOIN ${context.sql(context.schema)}.clients AS c
      ON c.id = ue.client_id
    WHERE (${filters.organizationId ?? null}::uuid IS NULL OR ue.organization_id = ${filters.organizationId ?? null})
      AND (${filters.clientName ?? null}::text IS NULL OR c.name = ${filters.clientName ?? null})
      AND (${filters.since ?? null}::timestamptz IS NULL OR ue.occurred_at >= ${filters.since ?? null})
      AND (${filters.until ?? null}::timestamptz IS NULL OR ue.occurred_at <= ${filters.until ?? null})
    GROUP BY ue.organization_id, c.name, ue.event_type
    ORDER BY c.name ASC, ue.event_type ASC
  `;
}
