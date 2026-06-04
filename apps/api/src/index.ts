import postgres from "postgres";
import { createApp } from "./app";
import { readApiEnv } from "./config";
import { createEd25519Signer } from "./crypto";
import { migrateApiSchema } from "./db";
import { computeTokenHash, ControlPlaneRepository } from "./modules/control-plane";

const env = await readApiEnv();
const sql = postgres(env.DATABASE_URL, {
  max: 10,
  idle_timeout: 20,
  connect_timeout: 10,
});

const signer = await createEd25519Signer(env.COE_KEY_ID, {
  privateKeyPkcs8Base64: env.COE_PRIVATE_KEY_PKCS8_BASE64,
  publicKeySpkiBase64: env.COE_PUBLIC_KEY_SPKI_BASE64,
});

await migrateApiSchema(sql, env.API_CONTROL_SCHEMA);

const bootstrapRepository = new ControlPlaneRepository(
  sql,
  env.API_CONTROL_SCHEMA,
  env.WORKER_TASK_LEASE_SECONDS,
  env.TASK_MAX_ATTEMPTS,
  env.TASK_BASE_BACKOFF_MS
);

const bootstrapClient = await bootstrapRepository.ensureClient(
  env.WORKER_CLIENT_NAME,
  await computeTokenHash(env.WORKER_SHARED_SECRET)
);

console.info(`[BOOTSTRAP] Ensured worker client: ${bootstrapClient.name} (${bootstrapClient.id})`);

const { app, controlPlaneService } = createApp({
  sql,
  controlSchema: env.API_CONTROL_SCHEMA,
  signer,
  workerSharedSecret: env.WORKER_SHARED_SECRET,
  workerRequestSigningSecret: env.WORKER_REQUEST_SIGNING_SECRET,
  workerRequestSigningMaxSkewMs: env.WORKER_REQUEST_SIGNING_MAX_SKEW_MS,
  workerClientName: env.WORKER_CLIENT_NAME,
  maxOutboxPayloadBytes: env.MAX_OUTBOX_PAYLOAD_BYTES,
  taskLeaseSeconds: env.WORKER_TASK_LEASE_SECONDS,
  taskMaxAttempts: env.TASK_MAX_ATTEMPTS,
  taskBaseBackoffMs: env.TASK_BASE_BACKOFF_MS,
  webhookTimeoutMs: env.WEBHOOK_TIMEOUT_MS,
  shadowBurnInRequired: env.SHADOW_BURN_IN_REQUIRED,
  shadowRequiredSuccesses: env.SHADOW_REQUIRED_SUCCESSES,
  adminApiToken: env.ADMIN_API_TOKEN,
  publicRateLimitWindowMs: env.PUBLIC_RATE_LIMIT_WINDOW_MS,
  publicRateLimitMaxRequests: env.PUBLIC_RATE_LIMIT_MAX_REQUESTS,
});

// Start bounded lifecycle materializer. Worker sync still has an idle fallback, but this loop
// keeps due NOTIFY/SHRED task creation off the hot request path during large due-job bursts.
const lifecycleMaterializerLoop = async () => {
  try {
    const clients = await bootstrapRepository.listClients();
    let inserted = 0;
    const now = new Date();
    for (const client of clients) {
      if (!client.is_active) {
        continue;
      }
      inserted += await bootstrapRepository.materializeDueLifecycleTasks(
        client.id,
        now,
        env.LIFECYCLE_MATERIALIZER_BATCH_SIZE
      );
    }
    if (inserted > 0) {
      console.debug(`[MATERIALIZER] Materialized ${inserted} lifecycle task(s)`);
    }
  } catch (err) {
    console.error("[MATERIALIZER] Loop iteration failed:", err);
  }
  setTimeout(lifecycleMaterializerLoop, env.LIFECYCLE_MATERIALIZER_INTERVAL_MS);
};
setTimeout(lifecycleMaterializerLoop, env.LIFECYCLE_MATERIALIZER_INTERVAL_MS);

// Start Background Archival Daemon
if (
  env.ARCHIVE_S3_ENABLED &&
  env.ARCHIVE_S3_BUCKET &&
  env.ARCHIVE_S3_REGION &&
  env.ARCHIVE_S3_ACCESS_KEY_ID &&
  env.ARCHIVE_S3_SECRET_ACCESS_KEY
) {
  console.info("[BOOTSTRAP] Starting S3 WORM Archival Daemon");

  const archiveLoop = async () => {
    try {
      const count = await controlPlaneService.archivePendingCertificates({
        bucket: env.ARCHIVE_S3_BUCKET!,
        region: env.ARCHIVE_S3_REGION!,
        accessKeyId: env.ARCHIVE_S3_ACCESS_KEY_ID!,
        secretAccessKey: env.ARCHIVE_S3_SECRET_ACCESS_KEY!,
        endpoint: env.ARCHIVE_S3_ENDPOINT,
      });
      if (count > 0) {
        console.debug(`[ARCHIVER] Archived ${count} certificate(s)`);
      }
    } catch (err) {
      console.error("[ARCHIVER] Loop iteration failed:", err);
    }
    setTimeout(archiveLoop, env.ARCHIVE_INTERVAL_MS);
  };

  // Give the app a moment to stabilize
  setTimeout(archiveLoop, 5000);
}

// Start Background Webhook Dispatcher
const webhookLoop = async () => {
  try {
    const count = await controlPlaneService.processWebhookOutbox();
    if (count > 0) {
      console.debug(`[WEBHOOK] Delivered ${count} webhook(s)`);
    }
  } catch (err) {
    console.error("[WEBHOOK] Loop iteration failed:", err);
  }
  // Fast frequency (30s) for notifications, but not tight enough to burn CPU
  setTimeout(webhookLoop, 30000);
};
setTimeout(webhookLoop, 10000);

export default {
  port: env.PORT,
  fetch: app.fetch,
};
