import { z } from "zod";

export const isoDateStringSchema = z.iso.datetime({ offset: true });

export const taskPayloadBaseSchema = z.object({
  request_id: z.uuid().optional(),
  subject_opaque_id: z.string().min(1).optional(),
  idempotency_key: z.uuid().optional(),
  trigger_source: z.string().min(1).optional(),
  actor_opaque_id: z.string().min(1).optional(),
  legal_framework: z.string().min(1).optional(),
  request_timestamp: isoDateStringSchema.optional(),
  tenant_id: z.string().min(1).optional(),
  cooldown_days: z.number().int().min(0).optional(),
  shadow_mode: z.boolean().optional(),
  webhook_url: z.url().optional(),
  userId: z.number().int().positive().optional(),
  now: isoDateStringSchema.optional(),
})
  .strict();

export const syncTaskSchema = z.discriminatedUnion("task_type", [
  z.object({
    id: z.string().min(1),
    task_type: z.literal("COMPILE_DAG"),
    payload: taskPayloadBaseSchema.extend({
      erasure_job_id: z.uuid().optional(),
    }),
  })
    .strict(),
  z.object({
    id: z.string().min(1),
    task_type: z.literal("VAULT_USER"),
    payload: taskPayloadBaseSchema.extend({
      shadowMode: z.boolean().optional(),
    }).superRefine((value, ctx) => {
      if (!value.subject_opaque_id && value.userId === undefined) {
        ctx.addIssue({
          code: "custom",
          message: "VAULT_USER payload must include subject_opaque_id or userId.",
          path: ["subject_opaque_id"],
        });
      }
    }),
  })
    .strict(),
  z.object({
    id: z.string().min(1),
    task_type: z.literal("NOTIFY_USER"),
    payload: taskPayloadBaseSchema,
  })
    .strict(),
  z.object({
    id: z.string().min(1),
    task_type: z.literal("SHRED_USER"),
    payload: taskPayloadBaseSchema,
  })
    .strict(),
]);

export const syncResponseSchema = z.union([
  z.object({
    pending: z.literal(false),
  })
    .strict(),
  z.object({
    pending: z.literal(true),
    task: syncTaskSchema,
  })
    .strict(),
]);