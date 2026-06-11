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
let workerBooted = false;
let workerQuarantined = false;

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
  
  // Explicit Programmatic Legal Warning printed to standard output on boot
  console.log("\n=======================================================================");
  console.log("[ENGINE INIT] Copyright 2026 Dev Dhanadiya. Licensed under Apache 2.0.");
  console.log("[ENGINE INIT] DESIGN PATTERN: ACID FAIL-CLOSED ORCHESTRATION ENGINE.");
  console.log("[WARN] System will freeze execution queues upon any database conflict.");
  console.log("[LEGAL] Under Apache 2.0 Sec 7 & 8, User assumes 100% liability for");
  console.log("        monitoring API failures, worker drops, and DPDP timelines.");
  console.log("=======================================================================\n");

  if (process.env.I_ACCEPT_APACHE2_AND_DPDP_OPERATIONAL_LIABILITY !== "true") {
    console.error("[CRITICAL ERROR] Engine initialization aborted.");
    console.error("[CRITICAL ERROR] You must explicitly set 'I_ACCEPT_APACHE2_AND_DPDP_OPERATIONAL_LIABILITY=true'");
    console.error("                 in your environment variables to acknowledge the Apache 2.0 disclaimer");
    console.error("                 and assume full operational risk under the Indian DPDP Act 2023.");
    process.exit(1);
  }

  logger.info("Starting Compliance Worker");

  const configPath = new URL("../compliance.worker.yaml", import.meta.url)
  await verifySignatureWorkerConfig(process.env, configPath);
  const file = await Bun.file(configPath).text();
  const workerConfigHash = await sha256HexDigest(file);
  const config = await readWorkerConfigFromRuntime(process.env, configPath);
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

    const skipSchemaCheck = process.env.SKIP_SCHEMA_CHECK === "true";
    if (skipSchemaCheck) {
      logger.warn("Skipping schema integrity and compatibility checks as requested by SKIP_SCHEMA_CHECK=true");
    } else {
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
          throw normalized;
        }

        workerQuarantined = true;
        logger.error(
          { code: normalized.code, detail: normalized.detail, context: normalized.context },
          "Worker entered quarantine mode; mutation tasks will not be claimed until configuration/schema/indexes are repaired"
        );
      }
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