import postgres from "postgres";
import { normalize } from "zod";
import type { Sql } from "./types";
import {
  readWorkerConfigFromRuntime,
  verifySignatureWorkerConfig,
  assertConfigSchemaCompatibility,
} from "./modules/config";
import {
  createRedactingSqlDebugLogger,
  runMigrations
} from "./modules/db";
import {
  assertSchemaIntegrity,
  assertIndexPreflight
} from "./modules/bootstrap";
import { createFetchDispatcher, createS3Client, createControlPlaneApiClient } from "./modules/network";
import { type MockMailer } from "./modules/engine";
import { ComplianceWorker } from "./modules/worker";
import { asWorkerError, workerError } from "./errors";
import { getLogger, logError, registerProcessGuard } from "./utils";
import { sha256HexDigest } from "./lib";
import { readRuntimeSecret } from "./secrets";

const logger = getLogger({ component: "bootstrap" });
let deadLettersTotal = 0;
let workerBooted = false;
let workerQuarantined = false;

async function readOutboxQueueDepth(sql: Sql, engineSchema: string): Promise<number> {
  const [row] = await sql<{ total: number }[]>`
    SELECT COUNT(*)::int AS total
    FROM ${sql(engineSchema)}.outbox
    WHERE status IN ('pending', 'leased')
  `;

  return row?.total ?? 0;
}

function createMetricsPayload(queueDepth: number): string {
  return [
    "# HELP dpdp_outbox_queue_depth Number of relay-pending outbox rows.",
    "# TYPE dpdp_outbox_queue_depth gauge",
    `dpdp_outbox_queue_depth ${queueDepth}`,
    "# HELP dpdp_dead_letters_total Total outbox events moved to dead_letter.",
    "# TYPE dpdp_dead_letters_total counter",
    `dpdp_dead_letters_total ${deadLettersTotal}`,
    "# HELP dpdp_worker_quarantined Whether the worker is refusing new mutation tasks due to schema/config preflight failure.",
    "# TYPE dpdp_worker_quarantined gauge",
    `dpdp_worker_quarantined ${workerQuarantined ? 1 : 0}`,
    "",
  ].join("\n");
}

async function checkDatabaseHealth(sql: Sql): Promise<boolean> {
  try {
    await sql`SELECT 1`;
    return true;
  } catch {
    return false;
  }
}

function sleep(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function readPositiveIntegerEnv(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function computeIdlePollDelayMs(emptyPolls: number, baseMs: number, maxMs: number): number {
  const cappedExponent = Math.min(emptyPolls, 10);
  const exponential = Math.min(baseMs * 2 ** cappedExponent, maxMs);
  const jitter = Math.floor(globalThis.crypto.getRandomValues(
    new Uint32Array(1))[0]! % Math.max(1, Math.floor(baseMs / 2)
    ));
  return Math.min(exponential + jitter, maxMs);
}

async function sendMailerWebhook(
  url: string,
  message: Parameters<MockMailer["sendEmail"]>[0],
  timeoutMs: number
): ReturnType<MockMailer["sendEmail"]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(message),
      signal: controller.signal,
      redirect: "error",
    });

    if (!response.ok) {
      throw workerError({
        code: "MAILER_TRANSPORT_FAILED",
        title: "Mailer transport failed",
        detail: `MAILER_WEBHOOK_URL responded with HTTP ${response.status}.`,
        category: "network",
        retryable: response.status >= 500 || response.status === 429,
        fatal: response.status >= 400 && response.status < 500 && response.status !== 429,
      });
    }

    const providerMessageId = response.headers.get("x-message-id") ?? response.headers.get("x-provider-message-id");
    return {
      provider: new URL(url).hostname,
      providerMessageId: providerMessageId ?? undefined,
      metadata: {
        status: response.status,
      },
    };
  } catch (error) {
    if (error instanceof DOMException && error.name === "AbortError") {
      throw workerError({
        code: "MAILER_TRANSPORT_TIMEOUT",
        title: "Mailer transport timed out",
        detail: `MAILER_WEBHOOK_URL did not respond within ${timeoutMs}ms.`,
        category: "network",
        retryable: true,
        fatal: false,
      });
    }

    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  registerProcessGuard(logger);
  logger.info("Starting Compliance Worker");

  const configPath = new URL("../compliance.worker.yaml", import.meta.url)
  await verifySignatureWorkerConfig(process.env, configPath);
  const file = await Bun.file(configPath).text();
  const workerConfigHash = await sha256HexDigest(file);
  const config = await readWorkerConfigFromRuntime(process.env, workerConfigHash);
  const postgresDebug = (process.env.LOG_LEVEL ?? "info").toLowerCase() === "debug"
    ? createRedactingSqlDebugLogger(logger, Object.keys(config.graph.root_pii_columns))
    : undefined;

  let sql: Sql | undefined;
  let sqlReplica: Sql | undefined;

  try {
    sql = postgres(process.env.DB_URL ?? "postgres://postgres:postgres@localhost:5432/postgres", {
      max: 10,
      idle_timeout: 20,
      connect_timeout: 10,
      debug: postgresDebug
    });

    sqlReplica = config.database.replica_db_url
      ? postgres(config.database.replica_db_url, {
        max: 10,
        idle_timeout: 20,
        connect_timeout: 10,
        debug: postgresDebug
      })
      : undefined

    await runMigrations(sql, config.database.engine_schema)

    try {
      await assertSchemaIntegrity(
        sql,
        config.database.app_schema,
        config.legal_attestation.schema_hash ?? config.integrity.expected_schema_hash
      );
      await assertConfigSchemaCompatibility(sql, config);
      await assertIndexPreflight(sql, config);
    } catch (error) {
      const normalized = asWorkerError(error);
      if (
        normalized.code !== "SCHEMA_DRIFT_DETECTED" &&
        normalized.code !== "CONFIG_SCHEMA_MISMATCH" &&
        normalized.code !== "INDEX_PREFLIGHT_FAILED"
      ) {
        throw normalize;
      }

      workerQuarantined = true;
      logger.error(
        { code: normalized.code, detail: normalized.detail, context: normalized.context },
        "Worker entered quarantine mode; mutation tasks will not be claimed until configuration/schema/indexes are repaired"
      );
    }

    const workerClientId = process.env.API_CLIENT_ID ?? "worker-1";
    const workerBearerToken = await readRuntimeSecret(process.env, "API_WORKER_TOKEN") || "worker-secret";
    const requestSigningSecret = await readRuntimeSecret(process.env, "API_REQUEST_SIGNING_SECRET") || undefined;
    const workerAuthHeaders = {
      "x-client-id": workerClientId,
      authorization: `Bearer ${workerBearerToken}`
    } as const;

    const pushOutboxEvent = createFetchDispatcher({
      url: process.env.API_OUTBOX_URL ?? "http://localhost:3000/api/v1/worker/outbox",
      token: workerBearerToken,
      clientId: workerClientId,
      requestSigningSecret,
      timeoutMs: 10_000,
    })

    const mailerWebhookUrl = process.env.MAILER_WEBHOOK_URL;
    if (!mailerWebhookUrl) {
      throw workerError({
        code: "MAILER_TRANSPORT_MISSING",
        title: "Missing mailer transport",
        detail: "MAILER_WEBHOOK_URL must be configured for production notice dispatch.",
        category: "configuration",
        retryable: false,
        fatal: true,
      });
    }

    const mailerTimeoutMs = Number(process.env.MAILER_TIMEOUT_MS ?? "10000");
    const mailer: MockMailer = {
      async sendEmail(message) {
        await sendMailerWebhook(mailerWebhookUrl, message, mailerTimeoutMs);
      },
    };

    const apiClient = createControlPlaneApiClient({
      syncUrl: process.env.API_SYNC_URL ?? "http://localhost:3000/api/v1/worker/sync",
      ackBaseUrl: process.env.API_BASE_URL ?? "http://localhost:3000/api/v1/worker/tasks",
      workerAuthHeaders,
      workerConfigHash,
      workerConfigVersion: config.legal_attestation.configuration_version,
      workerDpoIdentifier: config.legal_attestation.dpo_identifier,
      pushOutboxEvent,
      requestSigningSecret,
      timeoutMs: 10_000,
    });

    const worker = new ComplianceWorker({
      sql,
      sqlReplica,
      config,
      secrets: { kek: config.masterKey, hmacKey: config.hmacKey },
      apiClient,
      mailer,
      s3Client: config.blob_targets.length > 0 ? createS3Client() : undefined,
      taskHeartbeatIntervalMs: readPositiveIntegerEnv("WORKER_TASK_HEARTBEAT_INTERVAL_MS", 30_000),
    });

    const metricsPort = Number(process.env.METRICS_PORT ?? "9466");

    Bun.serve({
      port: metricsPort,
      fetch: async (request) => {
        const url = new URL(request.url);
        if (url.pathname === "/healthz") {
          return new Response("ok", { status: 200 });
        }

        if (url.pathname === "/readyz") {
          const ready = workerBooted && (await checkDatabaseHealth(sql!));
          return new Response(ready ? "ready" : "not ready", {
            status: ready ? 200 : 503,
          });
        }

        if (url.pathname === "/metrics") {
          const queueDepth = await readOutboxQueueDepth(sql!, config.database.engine_schema);
          return new Response(createMetricsPayload(queueDepth), {
            status: 200,
            headers: {
              "content-type": "text/plain; version=0.0.4; charset=utf-8",
            },
          });
        }

        return new Response("Not Found", { status: 404 });
      },
    });

    workerBooted = true;
    const pollBaseDelayMs = readPositiveIntegerEnv("WORKER_POLL_BASE_DELAY_MS", 1_000);
    const pollMaxDelayMs = readPositiveIntegerEnv("WORKER_POLL_MAX_DELAY_MS", 30_000);
    const taskConcurrency = readPositiveIntegerEnv("WORKER_TASK_CONCURRENCY", 1);
    let emptyPolls = 0;

    logger.info(
      {
        appSchema: config.database.app_schema,
        engineSchema: config.database.engine_schema,
        replicaEnabled: Boolean(sqlReplica),
        metricsPort,
        mailerTimeoutMs,
        workerConfigHash,
        workerConfigVersion: config.legal_attestation.configuration_version,
        dpoIdentifier: config.legal_attestation.dpo_identifier,
        quarantined: workerQuarantined,
        pollBaseDelayMs,
        pollMaxDelayMs,
        taskConcurrency,
      },
      "DPDP Compliance Worker booted"
    );

    while (true) {
      try {
        const processedCount = workerQuarantined ? 0 : await worker.processTaskBatch(taskConcurrency);
        const realy = await worker.flushOutbox();
        deadLettersTotal += realy.deadLettered;

        if (processedCount > 0 || realy.claimed > 0) {
          emptyPolls = 0;
          continue;
        }

        const delayMs = computeIdlePollDelayMs(emptyPolls, pollBaseDelayMs, pollMaxDelayMs);
        emptyPolls += 1;
        await sleep(delayMs);

      } catch (error) {
        const normalized = logError(logger, error, "Worker loop iteration failed");
        if (normalized.fatal) {
          throw normalized;
        }

        await sleep(normalized.retryable
          ? pollBaseDelayMs
          : Math.min(pollMaxDelayMs, pollBaseDelayMs * 10)
        );
      }
    }


  } finally {
    const shutdownTasks: Promise<unknown>[] = [];
    if (sql) {
      shutdownTasks.push(sql.end());
    }
    if (sqlReplica) {
      shutdownTasks.push(sqlReplica.end());
    }
    await Promise.allSettled(shutdownTasks);
  }
};

main().catch((error) => {
  logError(logger, error, "Worker failed to start");
  process.exit(1);
});