import type postgres from "postgres";
import type { RepositoryContext } from "./types";

export type BillingSubscriptionStatus = "TRIALING" | "ACTIVE" | "PAST_DUE" | "CANCELLED" | "EXPIRED";

export interface BillingSubscriptionRow {
  organization_id: string;
  plan_id: string;
  provider: string;
  provider_subscription_id: string | null;
  provider_order_id: string | null;
  provider_payment_id: string | null;
  status: BillingSubscriptionStatus;
  current_period_start: Date | null;
  current_period_end: Date | null;
  cancel_at_period_end: boolean;
  last_event_id: string | null;
  metadata: Record<string, unknown>;
  created_at: Date;
  updated_at: Date;
}

export interface BillingEventRow {
  id: string;
  organization_id: string;
  provider: string;
  provider_event_id: string;
  event_type: string;
  payload: Record<string, unknown>;
  created_at: Date;
}

export interface UpsertBillingSubscriptionInput {
  organizationId: string;
  planId: string;
  provider: string;
  status: BillingSubscriptionStatus;
  providerSubscriptionId?: string | null;
  providerOrderId?: string | null;
  providerPaymentId?: string | null;
  currentPeriodStart?: Date | null;
  currentPeriodEnd?: Date | null;
  cancelAtPeriodEnd?: boolean;
  lastEventId?: string | null;
  metadata?: Record<string, unknown>;
  now: Date;
}

export interface InsertBillingEventInput {
  organizationId: string;
  provider: string;
  providerEventId: string;
  eventType: string;
  payload: Record<string, unknown>;
  now: Date;
}

function toJsonValue(value: Record<string, unknown>): postgres.JSONValue {
  return value as postgres.JSONValue;
}

/**
 * Upserts a tenant's authoritative billing entitlement state.
 *
 * @param context - Repository dependencies.
 * @param input - Provider-backed subscription/payment state.
 * @returns Persisted subscription row.
 */
export async function upsertBillingSubscription(
  context: RepositoryContext,
  input: UpsertBillingSubscriptionInput
): Promise<BillingSubscriptionRow> {
  const [row] = await context.sql<BillingSubscriptionRow[]>`
    INSERT INTO ${context.sql(context.schema)}.billing_subscriptions (
      organization_id,
      plan_id,
      provider,
      provider_subscription_id,
      provider_order_id,
      provider_payment_id,
      status,
      current_period_start,
      current_period_end,
      cancel_at_period_end,
      last_event_id,
      metadata,
      created_at,
      updated_at
    ) VALUES (
      ${input.organizationId}::uuid,
      ${input.planId},
      ${input.provider},
      ${input.providerSubscriptionId ?? null},
      ${input.providerOrderId ?? null},
      ${input.providerPaymentId ?? null},
      ${input.status},
      ${input.currentPeriodStart ?? null},
      ${input.currentPeriodEnd ?? null},
      ${input.cancelAtPeriodEnd ?? false},
      ${input.lastEventId ?? null},
      ${context.sql.json(toJsonValue(input.metadata ?? {}))},
      ${input.now},
      ${input.now}
    )
    ON CONFLICT (organization_id) DO UPDATE
    SET plan_id = EXCLUDED.plan_id,
        provider = EXCLUDED.provider,
        provider_subscription_id = EXCLUDED.provider_subscription_id,
        provider_order_id = EXCLUDED.provider_order_id,
        provider_payment_id = EXCLUDED.provider_payment_id,
        status = EXCLUDED.status,
        current_period_start = EXCLUDED.current_period_start,
        current_period_end = EXCLUDED.current_period_end,
        cancel_at_period_end = EXCLUDED.cancel_at_period_end,
        last_event_id = EXCLUDED.last_event_id,
        metadata = EXCLUDED.metadata,
        updated_at = EXCLUDED.updated_at
    RETURNING *
  `;
  return row!;
}

/**
 * Appends one billing provider event idempotently.
 *
 * @param context - Repository dependencies.
 * @param input - Raw provider event envelope safe for operational audit.
 * @returns `true` when inserted, `false` when replayed.
 */
export async function insertBillingEvent(
  context: RepositoryContext,
  input: InsertBillingEventInput
): Promise<boolean> {
  const inserted = await context.sql`
    INSERT INTO ${context.sql(context.schema)}.billing_events (
      organization_id,
      provider,
      provider_event_id,
      event_type,
      payload,
      created_at
    ) VALUES (
      ${input.organizationId}::uuid,
      ${input.provider},
      ${input.providerEventId},
      ${input.eventType},
      ${context.sql.json(toJsonValue(input.payload))},
      ${input.now}
    )
    ON CONFLICT (organization_id, provider, provider_event_id) DO NOTHING
    RETURNING id
  `;
  return inserted.length > 0;
}

/**
 * Reads the current tenant billing entitlement.
 *
 * @param context - Repository dependencies.
 * @param organizationId - Tenant organization id.
 * @returns Subscription row or `null` for unpaid/uninitialized tenants.
 */
export async function getBillingSubscription(
  context: RepositoryContext,
  organizationId: string
): Promise<BillingSubscriptionRow | null> {
  const [row] = await context.sql<BillingSubscriptionRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.billing_subscriptions
    WHERE organization_id = ${organizationId}::uuid
  `;
  return row ?? null;
}
