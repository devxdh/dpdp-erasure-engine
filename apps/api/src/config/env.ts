import { z } from "zod";
import { readSecretString } from "./secret";

const booleanEnv = z.preprocess((value) => {
  if (typeof value !== "string") {
    return value;
  }

  const normalized = value.trim().toLowerCase();

  if (["1", "true", "yes", "on"].includes(normalized)) {
    return true;
  }
  if (["0", "false", "no", "off"].includes(normalized)) {
    return false;
  }

  return value;
}, z.boolean())

const envSchema = z.object({
  NODE_ENV: z.enum(["production", "development", "test"]).default("development"),
  ALLOW_LOCAL_DEV: booleanEnv.default(false),
  DATABASE_URL: z.string().min(1).default("defpostgres://postgres:postgres@localhost:5432/postgres"),
  API_CONTROL_SCHEMA: z.string().min(1).default("dpdp_control"),
  PORT: z.coerce.number().int().positive().default(3000),
  WORKER_TASK_LEASE_SECONDS: z.coerce.number().int().positive().default(60),
  TASK_MAX_ATTEMPTS: z.coerce.number().int().positive().default(10),
  TASK_BASE_BACKOFF_MS: z.coerce.number().int().positive().default(1000),
  LIFECYCLE_MATERIALIZER_INTERVAL_MS: z.coerce.number().int().positive().default(5000),
  LIFECYCLE_MATERIALIZER_BATCH_SIZE: z.coerce.number().int().positive().default(1000),
  WORKER_SHARED_SECRET: z.string().min(1).default("worker-secret"),
  WORKER_SHARED_SECRET_FILE: z.string().min(1).optional(),
  WORKER_REQUEST_SIGNING_SECRET: z.string().min(1).optional(),
  WORKER_REQUEST_SIGNING_SECRET_FILE: z.string().min(1).optional(),
  WORKER_REQUEST_SIGNING_MAX_SKEW_MS: z.coerce.number().int().positive().default(60000),
  WORKER_CLIENT_NAME: z.string().min(1).default("worker-1"),
  MAX_OUTBOX_PAYLOAD_BYTES: z.coerce.number().int().positive().default(32768),
  WEBHOOK_TIMEOUT_MS: z.coerce.number().int().positive().default(10000),
  SHADOW_BURN_IN_REQUIRED: booleanEnv.default(true),
  SHADOW_REQUIRED_SUCCESSES: z.coerce.number().int().min(0).default(100),
  ADMIN_API_TOKEN: z.string().min(1).default("admin-secret"),
  ADMIN_API_TOKEN_FILE: z.string().min(1).optional(),
  PUBLIC_RATE_LIMIT_WINDOW_MS: z.coerce.number().int().positive().default(60000),
  PUBLIC_RATE_LIMIT_MAX_REQUESTS: z.coerce.number().int().positive().default(60),
  COE_KEY_ID: z.string().min(1).default("control-plane-ed25519-v1"),
  COE_PRIVATE_KEY_PKCS8_BASE64: z.string().min(1).optional(),
  COE_PRIVATE_KEY_PKCS8_BASE64_FILE: z.string().min(1).optional(),
  COE_PUBLIC_KEY_SPKI_BASE64: z.string().min(1).optional(),
  COE_PUBLIC_KEY_SPKI_BASE64_FILE: z.string().min(1).optional(),
  ARCHIVE_S3_ENABLED: booleanEnv.default(false),
  ARCHIVE_S3_BUCKET: z.string().min(1).optional(),
  ARCHIVE_S3_REGION: z.string().min(1).optional(),
  ARCHIVE_S3_ENDPOINT: z.url().optional(),
  ARCHIVE_S3_ACCESS_KEY_ID: z.string().min(1).optional(),
  ARCHIVE_S3_SECRET_ACCESS_KEY: z.string().min(1).optional(),
  ARCHIVE_INTERVAL_MS: z.coerce.number().int().positive().default(3600000),
  I_ACCEPT_APACHE2_AND_DPDP_OPERATIONAL_LIABILITY: booleanEnv.refine((val) => val === true, {
    message: "You must explicitly set I_ACCEPT_APACHE2_AND_DPDP_OPERATIONAL_LIABILITY=true in your environment variables to acknowledge the Apache 2.0 disclaimer and shift of operational risk."
  }),
}).superRefine((value, ctx) => {
  if (value.ARCHIVE_S3_ENABLED) {
    for (const key of [
      "ARCHIVE_S3_BUCKET",
      "ARCHIVE_S3_REGION",
      "ARCHIVE_S3_ACCESS_KEY_ID",
      "ARCHIVE_S3_SECRET_ACCESS_KEY"
    ] as const) {
      if (!value[key]) {
        ctx.addIssue({
          code: "custom",
          path: [key],
          message: `${key} is required when ARCHIVE_S3_ENABLED=true`,
        });
      }
    }
  }

  if (value.NODE_ENV !== "production" || value.ALLOW_LOCAL_DEV) {
    return;
  }

  const defaultDatabaseUrl = "postgres://postgres:postgres@localhost:5432/postgres";
  const localDatabase = /(?:localhost|127\.0\.0\.1)/i.test(value.DATABASE_URL);
  if (value.DATABASE_URL === defaultDatabaseUrl || localDatabase) {
    ctx.addIssue({
      code: "custom",
      path: ["DATABASE_URL"],
      message: "Production DATABASE_URL must not point at the local development database.",
    });
  }

  const forbiddenSecrets: Array<[keyof typeof value, string]> = [
    ["WORKER_SHARED_SECRET", "worker-secret"],
    ["ADMIN_API_TOKEN", "admin-secret"],
  ];
  for (const [key, forbidden] of forbiddenSecrets) {
    if (value[key] === forbidden) {
      ctx.addIssue({
        code: "custom",
        path: [key],
        message: `${key} must be provided by a production secret source.`,
      });
    }
  }

  for (const key of ["WORKER_REQUEST_SIGNING_SECRET", "COE_PRIVATE_KEY_PKCS8_BASE64", "COE_PUBLIC_KEY_SPKI_BASE64"] as const) {
    if (!value[key]) {
      ctx.addIssue({
        code: "custom",
        path: [key],
        message: `${key} is required in production.`,
      });
    }
  }
});

export type ApiEnv = z.infer<typeof envSchema>;

/**
 * Parses and validates API environment variables.
 *
 * @param env - Raw environment map (defaults to `process.env`).
 * @returns Strongly typed API runtime configuration.
 */
export async function readApiEnv(
  env: Record<string, string | undefined> = process.env
): Promise<ApiEnv> {
  const [
    workerSharedSecret,
    workerRequestSigningSecret,
    adminApiToken,
    coePrivateKey,
    coePublicKey,
  ] = await Promise.all([
    readSecretString(env.WORKER_SHARED_SECRET, env.WORKER_SHARED_SECRET_FILE),
    readSecretString(env.WORKER_REQUEST_SIGNING_SECRET, env.WORKER_REQUEST_SIGNING_SECRET_FILE),
    readSecretString(env.ADMIN_API_TOKEN, env.ADMIN_API_TOKEN_FILE),
    readSecretString(env.COE_PRIVATE_KEY_PKCS8_BASE64, env.COE_PRIVATE_KEY_PKCS8_BASE64_FILE),
    readSecretString(env.COE_PUBLIC_KEY_SPKI_BASE64, env.COE_PUBLIC_KEY_SPKI_BASE64_FILE),
  ]);

  return envSchema.parse({
    ...env,
    WORKER_SHARED_SECRET: workerSharedSecret,
    WORKER_REQUEST_SIGNING_SECRET: workerRequestSigningSecret,
    ADMIN_API_TOKEN: adminApiToken,
    COE_PRIVATE_KEY_PKCS8_BASE64: coePrivateKey,
    COE_PUBLIC_KEY_SPKI_BASE64: coePublicKey,
  });
};