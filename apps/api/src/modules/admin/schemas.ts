import { z } from "zod";
import { erasureRequestStatusSchema } from "@modules/control-plane";

const emailLikePattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/i;

function looksLikePhoneNumber(value: string): boolean {
  const normalized = value.replace(/[\s()-]/g, "");
  return /^\+?[0-9]{7,15}$/.test(normalized);
}

const opaqueIdentifierSchema = z
  .string()
  .trim()
  .min(1)
  .refine((value) => !emailLikePattern.test(value), "must be an opaque identifier, not an email address")
  .refine((value) => !looksLikePhoneNumber(value), "must be an opaque identifier, not a phone number");

export const adminCreateClientSchema = z
  .object({
    name: z.string().trim().min(1),
    display_name: z.string().trim().min(1).optional(),
    require_approved_config: z.boolean().default(false),
  })
  .strict();

export const adminWorkerConfigHashParamSchema = z
  .object({
    name: z.string().trim().min(1),
    configHash: z.string().regex(/^[a-f0-9]{64}$/i),
  })
  .strict();

export const adminApproveWorkerConfigSchema = z
  .object({
    config_hash: z.string().regex(/^[a-f0-9]{64}$/i),
    configuration_version: z.string().trim().min(1),
    dpo_identifier: z.string().trim().min(1),
    legal_review_date: z.iso.date().optional(),
    allowed_live_mutation: z.boolean().default(false),
    require_approved_config: z.boolean().default(true),
    notes: z.string().trim().max(2000).optional(),
  })
  .strict();

export const adminRotateWebhookSecretSchema = z
  .object({
    previous_secret_grace_hours: z.number().int().min(0).max(168).default(24),
  })
  .strict();

export const adminProviderParamSchema = z
  .object({
    name: z.string().trim().min(1),
    provider: z.enum(["onetrust", "jira", "zendesk"]),
  })
  .strict();

export const adminProviderCompletionTargetSchema = z
  .object({
    completion_url: z.url(),
    auth_header_name: z.string().trim().regex(/^[a-z0-9!#$%&'*+.^_`|~-]+$/i).optional(),
    auth_header_value: z.string().trim().min(1).max(2048).optional(),
    is_active: z.boolean().default(true),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (Boolean(value.auth_header_name) !== Boolean(value.auth_header_value)) {
      ctx.addIssue({
        code: "custom",
        path: ["auth_header_value"],
        message: "auth_header_name and auth_header_value must be provided together.",
      });
    }
  });

export const adminBillingSubscriptionSchema = z
  .object({
    plan_id: z.string().trim().min(1),
    provider: z.string().trim().min(1).default("razorpay"),
    status: z.enum(["TRIALING", "ACTIVE", "PAST_DUE", "CANCELLED", "EXPIRED"]),
    provider_subscription_id: z.string().trim().min(1).optional(),
    provider_order_id: z.string().trim().min(1).optional(),
    provider_payment_id: z.string().trim().min(1).optional(),
    current_period_start: z.iso.datetime({ offset: true }).optional(),
    current_period_end: z.iso.datetime({ offset: true }).optional(),
    cancel_at_period_end: z.boolean().default(false),
    provider_event_id: z.string().trim().min(1).optional(),
    event_type: z.string().trim().min(1).default("billing.subscription.updated"),
    metadata: z.record(z.string(), z.unknown()).default({}),
  })
  .strict();

export const adminCreateApiKeySchema = z
  .object({
    label: z.string().trim().min(1),
    scopes: z.array(z.string().trim().min(1)).min(1).default(["audit:read"]),
  })
  .strict();

export const adminCreateOrganizationSchema = z
  .object({
    name: z.string().trim().min(1),
    billing_plan: z.string().trim().min(1).default("pilot"),
    certificate_archive_retention_days: z.number().int().min(1).max(3650).default(365),
    owner_email: z.email().optional(),
  })
  .strict();

export const adminClientNameParamSchema = z
  .object({
    name: z.string().trim().min(1),
  })
  .strict();

export const adminTaskIdParamSchema = z
  .object({
    taskId: z.uuid(),
  })
  .strict();

export const adminRequestIdParamSchema = z
  .object({
    requestId: z.uuid(),
  })
  .strict();

export const adminUsageQuerySchema = z
  .object({
    client_name: z.string().trim().min(1).optional(),
    since: z.iso.datetime({ offset: true }).optional(),
    until: z.iso.datetime({ offset: true }).optional(),
  })
  .strict();

export const adminAuditExportQuerySchema = z
  .object({
    client_name: z.string().trim().min(1).optional(),
    after_ledger_seq: z.coerce.number().int().positive().optional(),
  })
  .strict();

export const adminErasureRequestQuerySchema = z
  .object({
    status: erasureRequestStatusSchema.optional(),
    limit: z.coerce.number().int().min(1).max(100).default(50),
    offset: z.coerce.number().int().min(0).default(0),
  })
  .strict();

export const adminBulkPurgeSchema = z
  .object({
    client_name: z.string().trim().min(1),
    batch_id: z.uuid(),
    subject_opaque_ids: z.array(opaqueIdentifierSchema).min(1).max(10_000),
    actor_opaque_id: opaqueIdentifierSchema,
    legal_framework: z.string().trim().min(1).default("DPDP_2023"),
    request_timestamp: z.iso.datetime({ offset: true }).optional(),
    tenant_id: z.string().trim().min(1).optional(),
    shadow_mode: z.boolean().default(false),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>();
    for (const [index, subject] of value.subject_opaque_ids.entries()) {
      if (seen.has(subject)) {
        ctx.addIssue({
          code: "custom",
          path: ["subject_opaque_ids", index],
          message: "subject_opaque_ids must be unique within a purge batch.",
        });
      }
      seen.add(subject);
    }
  });

export type AdminCreateClientInput = z.infer<typeof adminCreateClientSchema>;
export type AdminApproveWorkerConfigInput = z.infer<typeof adminApproveWorkerConfigSchema>;
export type AdminRotateWebhookSecretInput = z.infer<typeof adminRotateWebhookSecretSchema>;
export type AdminProviderCompletionTargetInput = z.infer<typeof adminProviderCompletionTargetSchema>;
export type AdminBillingSubscriptionInput = z.infer<typeof adminBillingSubscriptionSchema>;
export type AdminCreateApiKeyInput = z.infer<typeof adminCreateApiKeySchema>;
export type AdminCreateOrganizationInput = z.infer<typeof adminCreateOrganizationSchema>;
export type AdminUsageQueryInput = z.infer<typeof adminUsageQuerySchema>;
export type AdminAuditExportQueryInput = z.infer<typeof adminAuditExportQuerySchema>;
export type AdminErasureRequestQueryInput = z.infer<typeof adminErasureRequestQuerySchema>;
export type AdminBulkPurgeInput = z.infer<typeof adminBulkPurgeSchema>;
