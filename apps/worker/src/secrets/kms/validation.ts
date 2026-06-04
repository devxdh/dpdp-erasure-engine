import { z } from "zod";

const envSourceSchema = z
  .object({
    provider: z.literal("env"),
    env: z.string().min(1),
  })
  .strict();

const fileSourceSchema = z
  .object({
    provider: z.literal("file"),
    path: z.string().min(1),
  })

const awsKmsSourceSchema = z
  .object({
    provider: z.literal("aws_kms"),
    region: z.string().min(1),
    ciphertext_blob_base64: z.string().min(1),
    key_id: z.string().min(1).optional(),
    encryption_context: z.record(z.string(), z.string()).optional(),
    endpoint: z.url().optional(),
    access_key_id_env: z.string().min(1).default("AWS_ACCESS_KEY_ID"),
    secret_access_key_env: z.string().min(1).default("AWS_SECRET_ACCESS_KEY"),
    session_token_env: z.string().min(1).default("AWS_SESSION_TOKEN"),
  })
  .strict();

const gcpSecretManagerSourceSchema = z
  .object({
    provider: z.literal("gcp_secret_manager"),
    secret_version: z.string().min(1),
    endpoint: z.url().optional(),
    access_token_env: z.string().min(1).default("GCP_ACCESS_TOKEN"),
    metadata_token_url: z
      .url()
      .default("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
  })
  .strict();

const vaultKvV2SourceSchema = z
  .object({
    provider: z.literal("hashicorp_vault"),
    address: z.url().optional(),
    address_env: z.string().min(1).default("VAULT_ADDR"),
    token_env: z.string().min(1).default("VAULT_TOKEN"),
    namespace_env: z.string().min(1).default("VAULT_NAMESPACE"),
    mount: z.string().min(1),
    path: z.string().min(1),
    field: z.string().min(1),
    version: z.number().int().positive().optional(),
  })
  .strict();

export const keySourceSchema = z.discriminatedUnion("provider", [
  envSourceSchema,
  fileSourceSchema,
  awsKmsSourceSchema,
  gcpSecretManagerSourceSchema,
  vaultKvV2SourceSchema
])

export type KeySourceConfig = z.infer<typeof keySourceSchema>;