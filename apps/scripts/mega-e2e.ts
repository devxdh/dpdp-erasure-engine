import postgres from "postgres";
import { detectSchemaDrift } from "@engine/worker/src/modules/db";
import { runIntrospector } from "@engine/worker/src/modules/introspector";
import { sha256HexDigest } from "@engine/worker/src/lib/crypto";
import { selectPurgeCandidates } from "@engine/worker/src/modules/engine/vault/purge";
import { computeWormHash } from "@engine/api/src/modules/control-plane/hash";

const composeArgs = ["compose", "-f", "docker-compose.yml"];
const apiBaseUrl = process.env.DPDP_LOCAL_API_URL ?? "http://127.0.0.1:13000";
const databaseUrl = process.env.LOCAL_DATABASE_URL ?? "postgres://dpdp:dpdp@127.0.0.1:55432/dpdp_local";
const tenantApiToken = process.env.DPDP_MEGA_TENANT_API_TOKEN ?? "admin-secret";
const appSchema = process.env.LOCAL_APP_SCHEMA ?? "mock_app";
const engineSchema = process.env.LOCAL_ENGINE_SCHEMA ?? "dpdp_engine";
const workerCount = readPositiveInt("DPDP_MEGA_WORKERS", 3);
const totalUsers = readPositiveInt("DPDP_MEGA_TOTAL_USERS", 1_000_000);
const purgeRequests = readPositiveInt("DPDP_MEGA_PURGE_REQUESTS", 10_000);
const deleteRequests = readPositiveInt("DPDP_MEGA_DELETE_REQUESTS", 500);
const requestConcurrency = readPositiveInt("DPDP_MEGA_REQUEST_CONCURRENCY", 50);
const jobTimeoutMs = readPositiveInt("DPDP_MEGA_JOB_TIMEOUT_MS", 45 * 60 * 1000);
const keepUp = process.env.DPDP_E2E_KEEP_UP === "1";

function sleep(milliseconds: number): Promise<void> {
  return Bun.sleep(milliseconds);
}

interface ErasureCreateResponse {
  request_id: string;
  task_id: string;
  accepted_at: string;
  idempotent_replay?: boolean;
}

interface ScaleSummary {
  totalUsers: number;
  purgeRequests: number;
  deleteRequests: number;
  workerCount: number;
  seedMs: number;
  introspectorMs: number;
  submitMs: number;
  vaultMs: number;
  notifyMs: number;
  shredMs: number;
}

interface PerformanceSnapshot {
  totalJobsPerSecond: number;
  p95TaskLatencyMs: number | null;
  p95VaultTaskLatencyMs: number | null;
  p95NotifyTaskLatencyMs: number | null;
  p95ShredTaskLatencyMs: number | null;
  activeLockWaits: number;
  workerOutboxLag: number;
  workerOutboxLeaseExtensionsObserved: number;
}

interface IntrospectorAccuracyReport {
  physicalDag: {
    expected: number;
    found: number;
    missing: string[];
    recall: number;
  };
  piiClassifier: {
    expected: number;
    found: number;
    missing: string[];
    falsePositives: string[];
    precision: number;
    recall: number;
  };
  logicalLinks: {
    expected: string[];
    found: string[];
    missing: string[];
    recall: number;
  };
  warnings: string[];
}

interface StatusCounts {
  status: string;
  count: number;
}

interface TaskCounts {
  status: string;
  task_type: string;
  count: number;
}

interface TaskLatencyRow {
  task_type: string;
  p95_ms: number | null;
}

interface AuditLedgerRow {
  ledger_seq: number;
  worker_idempotency_key: string;
  event_type: string;
  payload: unknown;
  previous_hash: string;
  current_hash: string;
}

interface AuditVerifyResponse {
  valid: boolean;
  checked: number;
  head: string;
  heads?: Record<string, string>;
  firstInvalid: unknown;
}

interface RequestSubject {
  subjectId: string;
  triggerSource: "ADMIN_PURGE" | "USER_CONSENT_WITHDRAWAL";
  idempotencyKey: string;
  requestTimestamp: string;
}

interface MegaPurgePolicy {
  enabled: true;
  selector: {
    kind: "boolean_column";
    column: "purge_eligible";
    value: true;
  };
  max_batch_size: number;
  actor_opaque_id: "dpo_mega_purge";
  legal_framework: "DPDP_2023";
  legal_citation: "DPDP Act, 2023 Sec 12 read with configured client retention schedule";
}

interface MegaWorkerConfigRender {
  schemaHash: string;
  configHash: string;
  introspectorAccuracy: IntrospectorAccuracyReport;
}

function asJsonObject(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function auditHashPayload(payload: unknown): unknown {
  const envelope = asJsonObject(payload);
  return envelope && "payload" in envelope ? envelope.payload : payload;
}

function readPositiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) {
    return fallback;
  }

  const parsed = Number(raw);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function requireCapacity(): void {
  const selected = purgeRequests + deleteRequests;
  if (selected > totalUsers) {
    throw new Error(
      `DPDP_MEGA_PURGE_REQUESTS + DPDP_MEGA_DELETE_REQUESTS (${selected}) cannot exceed DPDP_MEGA_TOTAL_USERS (${totalUsers}).`
    );
  }
}

function run(command: string[], check: boolean = true, env: Record<string, string> = {}): string {
  const proc = Bun.spawnSync(command, {
    cwd: process.cwd(),
    env: {
      ...process.env,
      ...env,
    },
    stdout: "pipe",
    stderr: "pipe",
  });

  const stdout = proc.stdout.toString();
  const stderr = proc.stderr.toString();
  if (check && proc.exitCode !== 0) {
    throw new Error(`${command.join(" ")} failed\n${stdout}\n${stderr}`.trim());
  }

  return stdout.trim();
}

function composeEnv(): Record<string, string> {
  return {
    NODE_ENV: "development",
    PUBLIC_RATE_LIMIT_WINDOW_MS: "60000",
    PUBLIC_RATE_LIMIT_MAX_REQUESTS: String(Math.max(120, purgeRequests + deleteRequests + 1_000)),
    TASK_MAX_ATTEMPTS: "2",
    SKIP_SCHEMA_CHECK: "true",
    MAILER_WEBHOOK_URL: "http://api:3000/ready",
  };
}

function workerContainerName(index: number): string {
  return `dpdp-erasure-engine-worker-${index}`;
}

function tenantHeaders(contentType: boolean = true): Record<string, string> {
  return {
    ...(contentType ? { "content-type": "application/json" } : {}),
    authorization: `Bearer ${tenantApiToken}`,
  };
}

function cleanupMegaWorkers(): void {
  // Handled by docker compose
}

async function waitForUrl(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until timeout.
    }
    await sleep(1_000);
  }

  throw new Error(`Timed out waiting for ${url}`);
}

async function waitForSql(sql: postgres.Sql, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError: unknown;
  while (Date.now() < deadline) {
    try {
      await sql`SELECT 1`;
      return;
    } catch (error) {
      lastError = error;
      await sleep(1_000);
    }
  }

  throw lastError instanceof Error ? lastError : new Error("Timed out waiting for Postgres.");
}

async function waitForEngineSchema(sql: postgres.Sql, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const [row] = await sql<{ ready: boolean }[]>`
      SELECT to_regclass(${`${engineSchema}.outbox`}) IS NOT NULL AS ready
    `;
    if (row?.ready) {
      return;
    }
    await sleep(1_000);
  }

  throw new Error(`Timed out waiting for ${engineSchema}.outbox.`);
}

async function waitForWorkerContainerReady(index: number, timeoutMs: number): Promise<void> {
  const name = workerContainerName(index);
  const deadline = Date.now() + timeoutMs;
  let lastOutput = "";

  while (Date.now() < deadline) {
    lastOutput = run(
      [
        "docker",
        "exec",
        name,
        "/usr/local/bin/bun",
        "-e",
        "const r = await fetch('http://127.0.0.1:9464/readyz'); console.log(r.status); process.exit(r.ok ? 0 : 1);",
      ],
      false
    );
    if (lastOutput.trim() === "200") {
      return;
    }

    await sleep(1_000);
  }

  throw new Error(`Timed out waiting for ${name} readyz. Last output: ${lastOutput}`);
}

async function seedEnterpriseDatabase(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`
    SET statement_timeout = '45min';
    SET lock_timeout = '30s';
    DROP SCHEMA IF EXISTS ${quoteIdentifier(appSchema)} CASCADE;
    CREATE SCHEMA ${quoteIdentifier(appSchema)};

    CREATE TABLE ${quoteIdentifier(appSchema)}.users (
      id TEXT PRIMARY KEY,
      user_identifier TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      full_name TEXT NOT NULL,
      is_active BOOLEAN NOT NULL DEFAULT FALSE,
      purge_eligible BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.profiles (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.users(id),
      bio TEXT NOT NULL,
      address TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.profile_devices (
      id BIGSERIAL PRIMARY KEY,
      profile_id BIGINT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.profiles(id),
      device_fingerprint TEXT NOT NULL,
      ip_address TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.support_tickets (
      id BIGSERIAL PRIMARY KEY,
      requester_id TEXT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.users(id),
      subject TEXT NOT NULL,
      body TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.support_comments (
      id BIGSERIAL PRIMARY KEY,
      ticket_id BIGINT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.support_tickets(id),
      body TEXT
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.payment_methods (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.users(id),
      pan_token TEXT NOT NULL,
      billing_name TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.account_hierarchy (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.users(id),
      parent_id BIGINT REFERENCES ${quoteIdentifier(appSchema)}.account_hierarchy(id),
      note TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.marketing_leads (
      id BIGSERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      name TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.system_audit_logs (
      id BIGSERIAL PRIMARY KEY,
      user_identifier TEXT NOT NULL,
      message TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.login_events (
      id BIGSERIAL PRIMARY KEY,
      user_identifier TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      user_agent TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.notification_tokens (
      id BIGSERIAL PRIMARY KEY,
      user_identifier TEXT NOT NULL,
      token TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.transactions (
      id TEXT NOT NULL,
      transaction_ref TEXT PRIMARY KEY,
      amount NUMERIC(18,2) NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.invoices (
      id TEXT NOT NULL,
      invoice_ref TEXT PRIMARY KEY,
      total NUMERIC(18,2) NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.kyc_documents (
      id TEXT NOT NULL,
      document_ref TEXT PRIMARY KEY,
      document_number TEXT NOT NULL
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.bulk_analytics_events (
      id BIGSERIAL PRIMARY KEY,
      user_identifier TEXT NOT NULL,
      event_name TEXT NOT NULL,
      occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.pii_probe_documents (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL REFERENCES ${quoteIdentifier(appSchema)}.users(id),
      aadhaar_number TEXT NOT NULL,
      pan_number TEXT NOT NULL,
      credit_card_number TEXT NOT NULL,
      upi_id TEXT NOT NULL,
      indian_mobile TEXT NOT NULL,
      passport_number TEXT NOT NULL,
      ip_address TEXT NOT NULL,
      noisy_ten_digit TEXT NOT NULL,
      nested_payload JSONB
    );

    CREATE TABLE ${quoteIdentifier(appSchema)}.logical_user_notes (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      recovery_email TEXT NOT NULL,
      freeform_phone TEXT NOT NULL,
      note TEXT NOT NULL
    );

    INSERT INTO ${quoteIdentifier(appSchema)}.users (id, user_identifier, email, full_name, is_active, purge_eligible)
    SELECT
      CASE
        WHEN gs <= ${purgeRequests} THEN 'usr_purge_' || lpad(gs::text, 6, '0')
        WHEN gs <= ${purgeRequests + deleteRequests} THEN 'usr_delete_' || lpad((gs - ${purgeRequests})::text, 6, '0')
        ELSE 'usr_bulk_' || lpad(gs::text, 7, '0')
      END AS id,
      CASE
        WHEN gs <= ${purgeRequests} THEN 'usr_purge_' || lpad(gs::text, 6, '0')
        WHEN gs <= ${purgeRequests + deleteRequests} THEN 'usr_delete_' || lpad((gs - ${purgeRequests})::text, 6, '0')
        ELSE 'usr_bulk_' || lpad(gs::text, 7, '0')
      END AS user_identifier,
      CASE
        WHEN gs <= ${purgeRequests} THEN 'purge.' || lpad(gs::text, 6, '0') || '@mega.example'
        WHEN gs <= ${purgeRequests + deleteRequests} THEN 'delete.' || lpad((gs - ${purgeRequests})::text, 6, '0') || '@mega.example'
        ELSE 'bulk.' || lpad(gs::text, 7, '0') || '@mega.example'
      END AS email,
      CASE
        WHEN gs <= ${purgeRequests} THEN 'Purge User ' || gs::text
        WHEN gs <= ${purgeRequests + deleteRequests} THEN 'Delete User ' || (gs - ${purgeRequests})::text
        ELSE 'Bulk User ' || gs::text
      END AS full_name,
      gs > ${purgeRequests},
      gs <= ${purgeRequests}
    FROM generate_series(1, ${totalUsers}) AS gs;

    INSERT INTO ${quoteIdentifier(appSchema)}.users (id, user_identifier, email, full_name, is_active, purge_eligible)
    VALUES
      ('usr_concurrent_idempotency', 'usr_concurrent_idempotency', 'concurrent@mega.example', 'Concurrent User', true, false),
      ('usr_fail_recovery', 'usr_fail_recovery', 'recovery@mega.example', 'Recovery User', true, false);

    DROP TABLE IF EXISTS pg_temp.avantii_selected_subjects;
    CREATE TEMP TABLE avantii_selected_subjects AS
    SELECT id, user_identifier, email, full_name
    FROM ${quoteIdentifier(appSchema)}.users
    WHERE id LIKE 'usr_purge_%' OR id LIKE 'usr_delete_%'
       OR id = 'usr_concurrent_idempotency' OR id = 'usr_fail_recovery';

    INSERT INTO ${quoteIdentifier(appSchema)}.profiles (user_id, bio, address)
    SELECT id, 'PII profile for ' || full_name, 'Flat 42, Enterprise Road, Bengaluru'
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.profile_devices (profile_id, device_fingerprint, ip_address)
    SELECT p.id, 'device-' || p.user_id, '10.42.' || (p.id % 250)::text || '.' || ((p.id % 200) + 10)::text
    FROM ${quoteIdentifier(appSchema)}.profiles AS p;

    INSERT INTO ${quoteIdentifier(appSchema)}.support_tickets (requester_id, subject, body)
    SELECT id, 'Account erasure request', 'Ticket body containing personal context for ' || full_name
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.support_comments (ticket_id, body)
    SELECT st.id, 'Follow-up comment for requester ' || st.requester_id
    FROM ${quoteIdentifier(appSchema)}.support_tickets AS st;

    INSERT INTO ${quoteIdentifier(appSchema)}.payment_methods (user_id, pan_token, billing_name)
    SELECT id, '411111111111' || lpad((row_number() OVER ())::text, 4, '0'), full_name
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.pii_probe_documents (
      user_id,
      aadhaar_number,
      pan_number,
      credit_card_number,
      upi_id,
      indian_mobile,
      passport_number,
      ip_address,
      noisy_ten_digit,
      nested_payload
    )
    SELECT
      id,
      '2000 0000 0009',
      'ABCPE1234F',
      '4111111111111111',
      lower(replace(id, '_', '.')) || '@upi',
      '+919876543210',
      'A1234567',
      '192.168.' || (row_number() OVER () % 250)::text || '.42',
      '1234567890',
      jsonb_build_object(
        'contact', jsonb_build_object('email', email, 'mobile', '+919876543210'),
        'identity', jsonb_build_object('aadhaar', '2000 0000 0009', 'pan', 'ABCPE1234F')
      )
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.logical_user_notes (user_id, recovery_email, freeform_phone, note)
    SELECT id, email, '+919876543210', 'logical satellite without a physical foreign key for ' || id
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.account_hierarchy (user_id, parent_id, note)
    SELECT id, NULL, 'Root hierarchy node for ' || full_name
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.account_hierarchy (user_id, parent_id, note)
    SELECT ah.user_id, ah.id, 'Child hierarchy node for ' || ah.user_id
    FROM ${quoteIdentifier(appSchema)}.account_hierarchy AS ah
    WHERE ah.parent_id IS NULL;

    INSERT INTO ${quoteIdentifier(appSchema)}.marketing_leads (email, name)
    SELECT email, full_name
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.system_audit_logs (user_identifier, message)
    SELECT user_identifier, 'audit event for ' || user_identifier
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.login_events (user_identifier, ip_address, user_agent)
    SELECT user_identifier, '172.16.' || (row_number() OVER () % 250)::text || '.10', 'AvantiiMegaBrowser/1.0'
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.notification_tokens (user_identifier, token)
    SELECT user_identifier, 'push-token-' || user_identifier
    FROM avantii_selected_subjects;

    INSERT INTO ${quoteIdentifier(appSchema)}.transactions (id, transaction_ref, amount)
    SELECT id, 'txn_' || id, 1999.99
    FROM avantii_selected_subjects
    WHERE id LIKE 'usr_purge_%' AND right(id, 1) IN ('0', '5');

    INSERT INTO ${quoteIdentifier(appSchema)}.invoices (id, invoice_ref, total)
    SELECT id, 'inv_' || id, 1999.99
    FROM avantii_selected_subjects
    WHERE id LIKE 'usr_purge_%' AND right(id, 1) = '0';

    INSERT INTO ${quoteIdentifier(appSchema)}.kyc_documents (id, document_ref, document_number)
    SELECT id, 'kyc_' || id, 'ABCDE1234F'
    FROM avantii_selected_subjects
    WHERE id LIKE 'usr_purge_%' AND right(id, 1) IN ('1', '6');

    INSERT INTO ${quoteIdentifier(appSchema)}.bulk_analytics_events (user_identifier, event_name)
    SELECT user_identifier, 'page_view'
    FROM ${quoteIdentifier(appSchema)}.users
    WHERE right(user_identifier, 1) IN ('0', '3', '7');

    CREATE INDEX users_identifier_idx ON ${quoteIdentifier(appSchema)}.users (user_identifier);
    CREATE INDEX users_purge_eligible_id_idx ON ${quoteIdentifier(appSchema)}.users (purge_eligible, id) WHERE purge_eligible = TRUE;
    CREATE INDEX profiles_user_id_idx ON ${quoteIdentifier(appSchema)}.profiles (user_id);
    CREATE INDEX profile_devices_profile_id_idx ON ${quoteIdentifier(appSchema)}.profile_devices (profile_id);
    CREATE INDEX support_tickets_requester_id_idx ON ${quoteIdentifier(appSchema)}.support_tickets (requester_id);
    CREATE INDEX support_comments_ticket_id_idx ON ${quoteIdentifier(appSchema)}.support_comments (ticket_id);
    CREATE INDEX payment_methods_user_id_idx ON ${quoteIdentifier(appSchema)}.payment_methods (user_id);
    CREATE INDEX account_hierarchy_user_id_idx ON ${quoteIdentifier(appSchema)}.account_hierarchy (user_id);
    CREATE INDEX account_hierarchy_parent_id_idx ON ${quoteIdentifier(appSchema)}.account_hierarchy (parent_id);
    CREATE INDEX marketing_leads_email_idx ON ${quoteIdentifier(appSchema)}.marketing_leads (email);
    CREATE INDEX system_audit_logs_user_identifier_idx ON ${quoteIdentifier(appSchema)}.system_audit_logs (user_identifier);
    CREATE INDEX login_events_user_identifier_idx ON ${quoteIdentifier(appSchema)}.login_events (user_identifier);
	    CREATE INDEX notification_tokens_user_identifier_idx ON ${quoteIdentifier(appSchema)}.notification_tokens (user_identifier);
	    CREATE INDEX transactions_id_idx ON ${quoteIdentifier(appSchema)}.transactions (id);
	    CREATE INDEX invoices_id_idx ON ${quoteIdentifier(appSchema)}.invoices (id);
	    CREATE INDEX kyc_documents_id_idx ON ${quoteIdentifier(appSchema)}.kyc_documents (id);
	    CREATE INDEX bulk_analytics_events_user_identifier_idx ON ${quoteIdentifier(appSchema)}.bulk_analytics_events (user_identifier);
	    CREATE INDEX pii_probe_documents_user_id_idx ON ${quoteIdentifier(appSchema)}.pii_probe_documents (user_id);
	    CREATE INDEX logical_user_notes_user_id_idx ON ${quoteIdentifier(appSchema)}.logical_user_notes (user_id);
	  `);
}

function quoteIdentifier(identifier: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(identifier)) {
    throw new Error(`Unsafe SQL identifier: ${identifier}`);
  }
  return `"${identifier.replaceAll('"', '""')}"`;
}

function targetTableKey(table: { schema: string; table: string }): string {
  return `${table.schema}.${table.table}`;
}

function taxonomyKey(table: string, column: string): string {
  return `${table}.${column}`;
}

function formatAccuracy(found: number, expected: number): number {
  return expected === 0 ? 1 : Number((found / expected).toFixed(4));
}

function buildMegaPurgePolicy(): MegaPurgePolicy {
  return {
    enabled: true,
    selector: {
      kind: "boolean_column",
      column: "purge_eligible",
      value: true,
    },
    max_batch_size: Math.max(purgeRequests, 10_000),
    actor_opaque_id: "dpo_mega_purge",
    legal_framework: "DPDP_2023",
    legal_citation: "DPDP Act, 2023 Sec 12 read with configured client retention schedule",
  };
}

async function auditIntrospectorAccuracy(sql: postgres.Sql): Promise<IntrospectorAccuracyReport> {
  const { draft } = await runIntrospector({
    sql,
    rootTable: `${appSchema}.users`,
    samplePercent: 2,
    sampleLimit: 250,
    threshold: 0.75,
    generatedAt: new Date("2026-05-12T00:00:00.000Z"),
  });

  const expectedPhysicalTables = new Set([
    `${appSchema}.users`,
    `${appSchema}.profiles`,
    `${appSchema}.profile_devices`,
    `${appSchema}.support_tickets`,
    `${appSchema}.support_comments`,
    `${appSchema}.payment_methods`,
    `${appSchema}.account_hierarchy`,
    `${appSchema}.pii_probe_documents`,
  ]);
  const foundPhysicalTables = new Set(draft.targets.map((target) => targetTableKey(target.table)));
  const missingPhysicalTables = Array.from(expectedPhysicalTables)
    .filter((table) => !foundPhysicalTables.has(table))
    .sort();

  const expectedPii = new Set([
    taxonomyKey(`${appSchema}.users`, "email"),
    taxonomyKey(`${appSchema}.profile_devices`, "ip_address"),
    taxonomyKey(`${appSchema}.payment_methods`, "pan_token"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "aadhaar_number"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "pan_number"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "credit_card_number"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "upi_id"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "indian_mobile"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "passport_number"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "ip_address"),
    taxonomyKey(`${appSchema}.pii_probe_documents`, "nested_payload"),
  ]);
  const allowedPii = new Set([
    ...expectedPii,
    taxonomyKey(`${appSchema}.users`, "user_identifier"),
  ]);
  const foundPii = new Set<string>();
  for (const target of draft.targets) {
    const table = targetTableKey(target.table);
    for (const column of target.piiColumns) {
      foundPii.add(taxonomyKey(table, column.column));
    }
  }

  const missingPii = Array.from(expectedPii).filter((key) => !foundPii.has(key)).sort();
  const falsePositives = Array.from(foundPii)
    .filter((key) => !allowedPii.has(key))
    .sort();
  const truePositiveCount = Array.from(foundPii).filter((key) => expectedPii.has(key)).length;

  const expectedLogicalLinks = [`${appSchema}.logical_user_notes.user_id`];
  const foundLogicalLinks = draft.potentialLogicalLinks
    .map((link) => `${targetTableKey(link.sourceTable)}.${link.column}`)
    .concat(draft.potentialLogicalLinks.map((link) => `${targetTableKey(link.targetTable)}.${link.column}`));
  const foundLogicalSet = new Set(foundLogicalLinks);
  const missingLogicalLinks = expectedLogicalLinks.filter((link) => !foundLogicalSet.has(link));

  const report: IntrospectorAccuracyReport = {
    physicalDag: {
      expected: expectedPhysicalTables.size,
      found: expectedPhysicalTables.size - missingPhysicalTables.length,
      missing: missingPhysicalTables,
      recall: formatAccuracy(expectedPhysicalTables.size - missingPhysicalTables.length, expectedPhysicalTables.size),
    },
    piiClassifier: {
      expected: expectedPii.size,
      found: truePositiveCount,
      missing: missingPii,
      falsePositives,
      precision: formatAccuracy(truePositiveCount, Math.max(foundPii.size, 1)),
      recall: formatAccuracy(truePositiveCount, expectedPii.size),
    },
    logicalLinks: {
      expected: expectedLogicalLinks,
      found: Array.from(foundLogicalSet).filter((link) => link.includes(".logical_user_notes.")).sort(),
      missing: missingLogicalLinks,
      recall: formatAccuracy(expectedLogicalLinks.length - missingLogicalLinks.length, expectedLogicalLinks.length),
    },
    warnings: [],
  };

  if (report.physicalDag.recall !== 1) {
    report.warnings.push("Physical FK DAG did not discover every expected FK-linked table.");
  }
  if (report.piiClassifier.recall < 0.9 || report.piiClassifier.precision < 0.85) {
    report.warnings.push("PII classifier accuracy dropped below mega E2E thresholds.");
  }
  if (report.logicalLinks.recall !== 1) {
    report.warnings.push("Semantic logical-link discovery missed the intentionally unlinked satellite table.");
  }

  if (report.warnings.length > 0) {
    throw new Error(`Introspector accuracy gate failed: ${JSON.stringify(report, null, 2)}`);
  }

  await Bun.write("deploy/local/generated/introspector-mega-report.json", JSON.stringify({ draft, report }, null, 2));
  return report;
}

async function renderMegaWorkerConfig(
  sql: postgres.Sql,
  introspectorAccuracy: IntrospectorAccuracyReport
): Promise<MegaWorkerConfigRender> {
  const schemaHash = await detectSchemaDrift(sql, appSchema);
  const purgePolicy = buildMegaPurgePolicy();
  const yaml = `version: "1.0"
database:
  app_schema: "${appSchema}"
  engine_schema: "${engineSchema}"

compliance_policy:
  default_retention_years: 1
  notice_window_hours: 48
  retention_rules:
    - rule_name: "PMLA_FINANCIAL"
      legal_citation: "Prevention of Money Laundering Act, 2002, Sec 12"
      if_has_data_in: ["transactions", "invoices"]
      retention_years: 10
    - rule_name: "RBI_KYC"
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in: ["kyc_documents"]
      retention_years: 5

graph:
  root_table: "users"
  root_id_column: "id"
  max_depth: 32
  notice_email_column: "email"
  notice_name_column: "full_name"
  root_pii_columns:
    email: "HMAC"
    full_name: "STATIC_MASK"

rules:
  - id: "mega_static_dag"
    root_table: "${appSchema}.users"
    max_depth: 32
    targets:
      - table: "${appSchema}.users"
        primary_key_columns: ["id"]
        pii_columns: []
      - table: "${appSchema}.profiles"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["user_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["bio", "address"]
        mutation_rules:
          bio: "STATIC_MASK"
          address: "HMAC"
      - table: "${appSchema}.profile_devices"
        parent: "${appSchema}.profiles"
        parent_columns: ["id"]
        child_columns: ["profile_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["device_fingerprint", "ip_address"]
        mutation_rules:
          device_fingerprint: "HMAC"
          ip_address: "HMAC"
      - table: "${appSchema}.support_tickets"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["requester_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["subject", "body"]
        mutation_rules:
          subject: "STATIC_MASK"
          body: "HMAC"
      - table: "${appSchema}.support_comments"
        parent: "${appSchema}.support_tickets"
        parent_columns: ["id"]
        child_columns: ["ticket_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["body"]
        mutation_rules:
          body: "NULLIFY"
      - table: "${appSchema}.payment_methods"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["user_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["pan_token", "billing_name"]
        mutation_rules:
          pan_token: "HMAC"
          billing_name: "STATIC_MASK"
      - table: "${appSchema}.pii_probe_documents"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["user_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["aadhaar_number", "pan_number", "credit_card_number", "upi_id", "indian_mobile", "passport_number", "ip_address", "nested_payload"]
        mutation_rules:
          aadhaar_number: "HMAC"
          pan_number: "HMAC"
          credit_card_number: "HMAC"
          upi_id: "HMAC"
          indian_mobile: "HMAC"
          passport_number: "HMAC"
          ip_address: "HMAC"
          nested_payload: "NULLIFY"
      - table: "${appSchema}.account_hierarchy"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["user_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["note"]
        mutation_rules:
          note: "STATIC_MASK"
      - table: "${appSchema}.marketing_leads"
        parent: "${appSchema}.users"
        parent_columns: ["email"]
        child_columns: ["email"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["email", "name"]
        mutation_rules:
          email: "HMAC"
          name: "STATIC_MASK"
      - table: "${appSchema}.system_audit_logs"
        parent: "${appSchema}.users"
        parent_columns: ["user_identifier"]
        child_columns: ["user_identifier"]
        primary_key_columns: ["id"]
        action: "hard_delete"
        pii_columns: []
      - table: "${appSchema}.login_events"
        parent: "${appSchema}.users"
        parent_columns: ["user_identifier"]
        child_columns: ["user_identifier"]
        primary_key_columns: ["id"]
        action: "hard_delete"
        pii_columns: []
      - table: "${appSchema}.notification_tokens"
        parent: "${appSchema}.users"
        parent_columns: ["user_identifier"]
        child_columns: ["user_identifier"]
        primary_key_columns: ["id"]
        action: "hard_delete"
        pii_columns: []
      - table: "${appSchema}.transactions"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["id"]
        primary_key_columns: ["id"]
        pii_columns: []
      - table: "${appSchema}.invoices"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["id"]
        primary_key_columns: ["id"]
        pii_columns: []
      - table: "${appSchema}.kyc_documents"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["id"]
        primary_key_columns: ["id"]
        pii_columns: []
      - table: "${appSchema}.bulk_analytics_events"
        parent: "${appSchema}.users"
        parent_columns: ["user_identifier"]
        child_columns: ["user_identifier"]
        primary_key_columns: ["id"]
        pii_columns: []
      - table: "${appSchema}.logical_user_notes"
        parent: "${appSchema}.users"
        parent_columns: ["id"]
        child_columns: ["user_id"]
        primary_key_columns: ["id"]
        action: "redact"
        pii_columns: ["recovery_email", "freeform_phone", "note"]
        mutation_rules:
          recovery_email: "HMAC"
          freeform_phone: "HMAC"
          note: "STATIC_MASK"

satellite_targets:
  - table: "marketing_leads"
    lookup_column: "email"
    action: "redact"
    masking_rules:
      email: "HMAC"
      name: "STATIC_MASK"
  - table: "system_audit_logs"
    lookup_column: "user_identifier"
    action: "hard_delete"
  - table: "login_events"
    lookup_column: "user_identifier"
    action: "hard_delete"
  - table: "notification_tokens"
    lookup_column: "user_identifier"
    action: "hard_delete"

blob_targets: []

purge_policy:
  enabled: true
  selector:
    kind: "${purgePolicy.selector.kind}"
    column: "${purgePolicy.selector.column}"
    value: ${purgePolicy.selector.value}
  max_batch_size: ${purgePolicy.max_batch_size}
  actor_opaque_id: "${purgePolicy.actor_opaque_id}"
  legal_framework: "${purgePolicy.legal_framework}"
  legal_citation: "${purgePolicy.legal_citation}"

outbox:
  batch_size: 25
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 250

security:
  notification_lease_seconds: 120
  master_key_env: "DPDP_MASTER_KEY"
  hmac_key_env: "DPDP_HMAC_KEY"

integrity:
  expected_schema_hash: "${schemaHash}"

legal_attestation:
  dpo_identifier: "mega-e2e-dpo@example.com"
  configuration_version: "mega-e2e-v1"
  legal_review_date: "2026-05-09"
  schema_hash: "${schemaHash}"
  generated_by: "avantii-mega-e2e"
  acknowledgment: "I confirm this mega E2E configuration is a test attestation for DPDP lifecycle validation."
`;

  await Bun.write("deploy/local/generated/compliance.worker.yml", yaml);
  return {
    schemaHash,
    configHash: await sha256HexDigest(yaml),
    introspectorAccuracy,
  };
}

async function submitErasure(
  subjectId: string,
  triggerSource: "ADMIN_PURGE" | "USER_CONSENT_WITHDRAWAL",
  idempotencyKey: string = crypto.randomUUID(),
  cooldownDays: number = 0,
  requestTimestamp: string = new Date().toISOString()
): Promise<ErasureCreateResponse> {
  const response = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      subject_opaque_id: subjectId,
      idempotency_key: idempotencyKey,
      trigger_source: triggerSource,
      actor_opaque_id: triggerSource === "ADMIN_PURGE" ? "dpo_mega_purge" : subjectId,
      legal_framework: "DPDP_2023",
      request_timestamp: requestTimestamp,
      cooldown_days: cooldownDays,
      shadow_mode: false,
    }),
  });

  if (response.status !== 202) {
    throw new Error(`Create failed for ${subjectId}: HTTP ${response.status} ${await response.text()}`);
  }

  return response.json() as Promise<ErasureCreateResponse>;
}

async function mapLimit<T, R>(
  values: readonly T[],
  concurrency: number,
  fn: (value: T, index: number) => Promise<R>
): Promise<R[]> {
  const results: R[] = [];
  let cursor = 0;

  async function worker(): Promise<void> {
    while (true) {
      const index = cursor;
      cursor += 1;
      if (index >= values.length) {
        return;
      }
      results[index] = await fn(values[index]!, index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, values.length) }, () => worker()));
  return results;
}

function deleteSubjectId(index: number): string {
  return `usr_delete_${String(index).padStart(6, "0")}`;
}

async function buildRequestSubjects(sql: postgres.Sql): Promise<RequestSubject[]> {
  const subjects: RequestSubject[] = [];
  const requestTimestamp = new Date().toISOString();
  const purgeCandidates = await selectPurgeCandidates(sql, {
    appSchema,
    rootTable: "users",
    rootIdColumn: "id",
    purgePolicy: buildMegaPurgePolicy(),
    limit: purgeRequests,
  });

  if (purgeCandidates.length !== purgeRequests) {
    throw new Error(
      `Configured purge selector returned ${purgeCandidates.length} candidates; expected ${purgeRequests}.`
    );
  }

  for (const subjectId of purgeCandidates) {
    subjects.push({
      subjectId,
      triggerSource: "ADMIN_PURGE",
      idempotencyKey: crypto.randomUUID(),
      requestTimestamp,
    });
  }
  for (let index = 1; index <= deleteRequests; index += 1) {
    subjects.push({
      subjectId: deleteSubjectId(index),
      triggerSource: "USER_CONSENT_WITHDRAWAL",
      idempotencyKey: crypto.randomUUID(),
      requestTimestamp,
    });
  }
  return subjects;
}

async function waitForStatusCount(
  sql: postgres.Sql,
  status: string,
  expected: number,
  timeoutMs: number
): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  let lastLogAt = 0;
  while (Date.now() < deadline) {
    const [row] = await sql<{ count: number }[]>`
      SELECT COUNT(*)::int AS count
      FROM dpdp_control.erasure_jobs
      WHERE (subject_opaque_id LIKE 'usr_purge_%' OR subject_opaque_id LIKE 'usr_delete_%')
        AND status = ${status}
    `;
    if ((row?.count ?? 0) >= expected) {
      return row?.count ?? 0;
    }
    if (Date.now() - lastLogAt > 10_000) {
      lastLogAt = Date.now();
      const [lag] = await sql<{ outbox_lag: number; active_lock_waits: number }[]>`
        SELECT
          (SELECT COUNT(*)::int FROM ${sql(engineSchema)}.outbox WHERE status <> 'processed' OR chain_status <> 'finalized') AS outbox_lag,
          (SELECT COUNT(*)::int FROM pg_stat_activity WHERE wait_event_type = 'Lock') AS active_lock_waits
      `;
      console.log(JSON.stringify({
        phase: `wait:${status}`,
        completed: row?.count ?? 0,
        expected,
        outboxLag: lag?.outbox_lag ?? 0,
        activeLockWaits: lag?.active_lock_waits ?? 0,
      }));
    }
    await sleep(2_000);
  }

  await printDiagnostics(sql, `Timed out waiting for ${expected} jobs in ${status}.`);
  throw new Error(`Timed out waiting for ${expected} jobs in ${status}.`);
}

async function collectPerformanceSnapshot(
  sql: postgres.Sql,
  summary: ScaleSummary
): Promise<PerformanceSnapshot> {
  const lifecycleMs = summary.vaultMs + summary.notifyMs + summary.shredMs;
  const selectedJobs = summary.purgeRequests + summary.deleteRequests;
  const latencyRows = await sql<TaskLatencyRow[]>`
    SELECT
      task_type,
      percentile_cont(0.95) WITHIN GROUP (
        ORDER BY EXTRACT(EPOCH FROM (task.completed_at - task.created_at)) * 1000
      )::float AS p95_ms
    FROM dpdp_control.task_queue AS task
    JOIN dpdp_control.erasure_jobs AS job ON job.id = task.erasure_job_id
    WHERE task.completed_at IS NOT NULL
      AND (job.subject_opaque_id LIKE 'usr_purge_%' OR job.subject_opaque_id LIKE 'usr_delete_%')
    GROUP BY task_type
  `;
  const latencyByType = new Map(latencyRows.map((row) => [row.task_type, row.p95_ms]));
  const [globalLatency] = await sql<{ p95_ms: number | null }[]>`
    SELECT percentile_cont(0.95) WITHIN GROUP (
      ORDER BY EXTRACT(EPOCH FROM (task.completed_at - task.created_at)) * 1000
    )::float AS p95_ms
    FROM dpdp_control.task_queue AS task
    JOIN dpdp_control.erasure_jobs AS job ON job.id = task.erasure_job_id
    WHERE task.completed_at IS NOT NULL
      AND (job.subject_opaque_id LIKE 'usr_purge_%' OR job.subject_opaque_id LIKE 'usr_delete_%')
  `;
  const [lag] = await sql<{ outbox_lag: number; active_lock_waits: number; lease_extensions: number }[]>`
    SELECT
      (SELECT COUNT(*)::int FROM ${sql(engineSchema)}.outbox WHERE status <> 'processed' OR chain_status <> 'finalized') AS outbox_lag,
      (SELECT COUNT(*)::int FROM pg_stat_activity WHERE wait_event_type = 'Lock') AS active_lock_waits,
      (SELECT COUNT(*)::int FROM ${sql(engineSchema)}.outbox WHERE lease_expires_at IS NOT NULL AND attempt_count = 0) AS lease_extensions
  `;

  return {
    totalJobsPerSecond: lifecycleMs > 0 ? Math.round((selectedJobs / (lifecycleMs / 1000)) * 100) / 100 : 0,
    p95TaskLatencyMs: globalLatency?.p95_ms ?? null,
    p95VaultTaskLatencyMs: latencyByType.get("VAULT_USER") ?? null,
    p95NotifyTaskLatencyMs: latencyByType.get("NOTIFY_USER") ?? null,
    p95ShredTaskLatencyMs: latencyByType.get("SHRED_USER") ?? null,
    activeLockWaits: lag?.active_lock_waits ?? 0,
    workerOutboxLag: lag?.outbox_lag ?? 0,
    workerOutboxLeaseExtensionsObserved: lag?.lease_extensions ?? 0,
  };
}

async function assertApiEdgeCases(sql: postgres.Sql): Promise<void> {
  const edgeRequestTimestamp = new Date().toISOString();

  // Edge case: Missing authentication
  const unauthResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      subject_opaque_id: "usr_edge",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_edge",
      legal_framework: "DPDP_2023",
      request_timestamp: edgeRequestTimestamp,
      cooldown_days: 0,
      shadow_mode: false,
    }),
  });
  if (unauthResponse.status !== 401) {
    throw new Error(`Expected 401 Unauthorized, received HTTP ${unauthResponse.status}.`);
  }

  // Edge case: Invalid authentication
  const forbiddenResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: "Bearer invalid-token" },
    body: JSON.stringify({
      subject_opaque_id: "usr_edge",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_edge",
      legal_framework: "DPDP_2023",
      request_timestamp: edgeRequestTimestamp,
      cooldown_days: 0,
      shadow_mode: false,
    }),
  });
  if (forbiddenResponse.status !== 401 && forbiddenResponse.status !== 403) {
    throw new Error(`Expected 401/403 Invalid Token, received HTTP ${forbiddenResponse.status}.`);
  }

  // Edge case: Cancel non-existent job
  const cancelNotFoundResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests/${crypto.randomUUID()}/cancel`, {
    method: "POST",
    headers: tenantHeaders(false),
  });
  if (cancelNotFoundResponse.status !== 404) {
    throw new Error(`Expected 404 Not Found for missing job cancellation, received HTTP ${cancelNotFoundResponse.status}.`);
  }

  // Edge case: Missing required fields
  const missingFieldsResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      subject_opaque_id: "usr_edge",
      // missing idempotency_key
    }),
  });
  if (missingFieldsResponse.status !== 400) {
    throw new Error(`Expected 400 Bad Request for missing fields, received HTTP ${missingFieldsResponse.status}.`);
  }

  const malformedResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      subject_opaque_id: "bad@example.com",
      idempotency_key: crypto.randomUUID(),
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "dpo_edge",
      legal_framework: "DPDP_2023",
      request_timestamp: new Date().toISOString(),
      cooldown_days: 0,
      shadow_mode: false,
    }),
  });
  if (malformedResponse.status !== 400) {
    throw new Error(`Expected zero-PII validation failure, received HTTP ${malformedResponse.status}.`);
  }

  const cancelKey = crypto.randomUUID();
  const first = await submitErasure(
    "usr_bulk_0000001",
    "USER_CONSENT_WITHDRAWAL",
    cancelKey,
    30,
    edgeRequestTimestamp
  );
  const replay = await submitErasure(
    "usr_bulk_0000001",
    "USER_CONSENT_WITHDRAWAL",
    cancelKey,
    30,
    edgeRequestTimestamp
  );
  if (replay.request_id !== first.request_id || replay.idempotent_replay !== true) {
    throw new Error(`Idempotent replay did not return the original cancelled-edge job: ${JSON.stringify(replay)}`);
  }

  const conflictResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
    method: "POST",
    headers: tenantHeaders(),
    body: JSON.stringify({
      subject_opaque_id: "usr_bulk_0000002",
      idempotency_key: cancelKey,
      trigger_source: "USER_CONSENT_WITHDRAWAL",
      actor_opaque_id: "usr_bulk_0000002",
      legal_framework: "DPDP_2023",
      request_timestamp: edgeRequestTimestamp,
      cooldown_days: 30,
      shadow_mode: false,
    }),
  });
  if (conflictResponse.status !== 409) {
    throw new Error(`Expected idempotency conflict, received HTTP ${conflictResponse.status}.`);
  }

  const cancelResponse = await fetch(`${apiBaseUrl}/api/v1/erasure-requests/${cancelKey}/cancel`, {
    method: "POST",
    headers: tenantHeaders(false),
  });
  if (cancelResponse.status !== 200) {
    throw new Error(`Cancellation failed: HTTP ${cancelResponse.status} ${await cancelResponse.text()}`);
  }

  const [cancelled] = await sql<{ job_status: string; task_status: string }[]>`
    SELECT job.status AS job_status, task.status AS task_status
    FROM dpdp_control.erasure_jobs AS job
    JOIN dpdp_control.task_queue AS task ON task.erasure_job_id = job.id
    WHERE job.idempotency_key = ${cancelKey}::uuid
  `;
  if (cancelled?.job_status !== "CANCELLED" || cancelled.task_status !== "FAILED") {
    throw new Error(`Cancelled job/task state invariant failed: ${JSON.stringify(cancelled)}`);
  }

  // Edge case: Try to cancel a job that is already past cooldown (should fail if not supported)
  // We'll test this with one of the subjects later.

  console.log("API edge cases passed.");
}

async function testDeadLetterRecovery(sql: postgres.Sql): Promise<void> {
  console.log("Testing dead-letter recovery...");
  const subjectId = "usr_fail_recovery";
  const idempotencyKey = crypto.randomUUID();

  // 1. Create a job that will fail because we'll sabotage the table
  await sql`ALTER TABLE ${sql(appSchema)}.profiles RENAME COLUMN bio TO bio_sabotaged`;

  try {
    const created = await submitErasure(subjectId, "USER_CONSENT_WITHDRAWAL", idempotencyKey);
    console.log(`Created failing job ${created.request_id}`);

    // 2. Wait for it to hit DEAD_LETTER (it will retry a few times)
    // For the purpose of mega-e2e, we might want to speed this up or just check it's retrying.
    // In mega-e2e, the worker poll is fast.
    let deadLettered = false;
    for (let i = 0; i < 60; i++) {
      const [task] = await sql<{ status: string; attempt_count: number; error_text: string | null }[]>`
        SELECT status, attempt_count, error_text FROM dpdp_control.task_queue
        WHERE erasure_job_id = ${created.request_id}
      `;
      console.log(`Job ${created.request_id} task status: ${task?.status}, attempts: ${task?.attempt_count}, error: ${task?.error_text?.substring(0, 50)}`);
      if (task?.status === "DEAD_LETTER") {
        deadLettered = true;
        break;
      }
      await sleep(5000);
    }

    if (!deadLettered) {
      throw new Error(`Job ${created.request_id} did not reach DEAD_LETTER as expected.`);
    }
    console.log("Job reached DEAD_LETTER.");

    // 3. Fix the sabotage
    await sql`ALTER TABLE ${sql(appSchema)}.profiles RENAME COLUMN bio_sabotaged TO bio`;

    // 4. Requeue via Admin API
    const requeueResponse = await fetch(`${apiBaseUrl}/api/v1/admin/tasks/${created.task_id}/requeue`, {
      method: "POST",
      headers: tenantHeaders(),
    });

    if (requeueResponse.status !== 200) {
      throw new Error(`Requeue failed: HTTP ${requeueResponse.status} ${await requeueResponse.text()}`);
    }
    console.log("Job requeued successfully.");

    // 5. Verify it completes VAULTED
    console.log(`Waiting for job ${created.request_id} to reach VAULTED after requeue...`);
    let success = false;
    for (let i = 0; i < 30; i++) {
      const [job] = await sql<{ status: string }[]>`
        SELECT status FROM dpdp_control.erasure_jobs
        WHERE id = ${created.request_id}::uuid
      `;
      if (job?.status === "VAULTED") {
        success = true;
        break;
      }
      await sleep(1000);
    }
    if (!success) {
      throw new Error(`Job ${created.request_id} did not reach VAULTED after requeue.`);
    }
    console.log("Dead-letter recovery successful.");

  } finally {
    // Ensure table is fixed even if test fails
    try {
      await sql`ALTER TABLE ${sql(appSchema)}.profiles RENAME COLUMN bio_sabotaged TO bio`;
    } catch {}
  }
}

async function testHighConcurrencyIdempotency(sql: postgres.Sql): Promise<void> {
  console.log("Testing high-concurrency idempotency...");
  const subjectId = "usr_concurrent_idempotency";
  const idempotencyKey = crypto.randomUUID();
  const concurrency = 20;

  const requestTimestamp = new Date().toISOString();
  const results = await Promise.all(
    Array.from({ length: concurrency }).map(() =>
      fetch(`${apiBaseUrl}/api/v1/erasure-requests`, {
        method: "POST",
        headers: tenantHeaders(),
        body: JSON.stringify({
          subject_opaque_id: subjectId,
          idempotency_key: idempotencyKey,
          trigger_source: "USER_CONSENT_WITHDRAWAL",
          actor_opaque_id: subjectId,
          legal_framework: "DPDP_2023",
          request_timestamp: requestTimestamp,
          cooldown_days: 0,
          shadow_mode: false,
        }),
      })
    )
  );

  const statuses = results.map((r) => r.status);
  const accepted = statuses.filter((s) => s === 202).length;

  if (accepted === 0) {
    throw new Error("None of the concurrent requests were accepted.");
  }

  // With strict idempotency, all should be 202 (some with idempotent_replay: true)
  // or at least only 1 should be the original.
  console.log(`Concurrent results: ${accepted} accepted out of ${concurrency}`);

  let requestId: string | undefined;
  for (const response of results) {
    const body = (await response.json()) as ErasureCreateResponse;
    if (response.status !== 202) {
      throw new Error(`Concurrent request failed with ${response.status}: ${JSON.stringify(body)}`);
    }
    if (body.request_id) {
      requestId = body.request_id;
    }
  }

  if (requestId) {
    console.log(`Waiting for concurrent idempotency job ${requestId} to reach VAULTED...`);
    let success = false;
    for (let i = 0; i < 30; i++) {
      const [job] = await sql<{ status: string }[]>`
        SELECT status FROM dpdp_control.erasure_jobs
        WHERE id = ${requestId}::uuid
      `;
      if (job?.status === "VAULTED") {
        success = true;
        break;
      }
      await sleep(1000);
    }
    if (!success) {
      throw new Error(`Concurrent idempotency job ${requestId} did not reach VAULTED.`);
    }
    console.log(`Concurrent idempotency job ${requestId} reached VAULTED successfully.`);
  }

  console.log("High-concurrency idempotency successful.");
}

async function fastForwardNotifications(sql: postgres.Sql): Promise<void> {
  await sql`
    UPDATE dpdp_control.erasure_jobs
    SET notification_due_at = NOW(),
        updated_at = NOW()
    WHERE (subject_opaque_id LIKE 'usr_purge_%' OR subject_opaque_id LIKE 'usr_delete_%')
      AND status = 'VAULTED'
  `;

  await sql`
    UPDATE ${sql(engineSchema)}.pii_vault
    SET notification_due_at = NOW(),
        updated_at = NOW()
    WHERE root_id LIKE 'usr_purge_%' OR root_id LIKE 'usr_delete_%'
  `;
}

async function fastForwardShredding(sql: postgres.Sql): Promise<void> {
  await sql`
    UPDATE dpdp_control.erasure_jobs
    SET shred_due_at = NOW(),
        updated_at = NOW()
    WHERE (subject_opaque_id LIKE 'usr_purge_%' OR subject_opaque_id LIKE 'usr_delete_%')
      AND status = 'NOTICE_SENT'
  `;

  await sql`
    UPDATE ${sql(engineSchema)}.pii_vault
    SET retention_expiry = NOW(),
        updated_at = NOW()
    WHERE root_id LIKE 'usr_purge_%' OR root_id LIKE 'usr_delete_%'
  `;
}

async function assertMegaInvariants(
  sql: postgres.Sql,
  expectedJobs: number,
  config: MegaWorkerConfigRender
): Promise<void> {
  const [jobs] = await sql<{ total: number; shredded: number; failed: number; cancelled: number }[]>`
    SELECT
      COUNT(*)::int AS total,
      COUNT(*) FILTER (WHERE status = 'SHREDDED')::int AS shredded,
      COUNT(*) FILTER (WHERE status = 'FAILED')::int AS failed,
      COUNT(*) FILTER (WHERE status = 'CANCELLED')::int AS cancelled
    FROM dpdp_control.erasure_jobs
    WHERE subject_opaque_id LIKE 'usr_purge_%' OR subject_opaque_id LIKE 'usr_delete_%'
  `;

  if (!jobs || jobs.total !== expectedJobs || jobs.shredded !== expectedJobs || jobs.failed !== 0 || jobs.cancelled !== 0) {
    throw new Error(`Unexpected job lifecycle counts: ${JSON.stringify(jobs)}`);
  }

  const [deadTasks] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM dpdp_control.task_queue
    WHERE status = 'DEAD_LETTER'
  `;
  if ((deadTasks?.count ?? 0) !== 0) {
    throw new Error(`Expected zero Control Plane dead-letter tasks, found ${deadTasks?.count}.`);
  }

  const [deadOutbox] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM ${sql(engineSchema)}.outbox
    WHERE status = 'dead_letter'
  `;
  if ((deadOutbox?.count ?? 0) !== 0) {
    throw new Error(`Expected zero worker outbox dead letters, found ${deadOutbox?.count}.`);
  }

  const [certificates] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM dpdp_control.certificates AS cert
    JOIN dpdp_control.erasure_jobs AS job ON job.id = cert.request_id
    WHERE job.subject_opaque_id LIKE 'usr_purge_%' OR job.subject_opaque_id LIKE 'usr_delete_%'
  `;
  if ((certificates?.count ?? 0) !== expectedJobs) {
    throw new Error(`Expected ${expectedJobs} certificates, found ${certificates?.count}.`);
  }

  const [unfinishedTasks] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM dpdp_control.task_queue AS task
    JOIN dpdp_control.erasure_jobs AS job ON job.id = task.erasure_job_id
    WHERE (job.subject_opaque_id LIKE 'usr_purge_%' OR job.subject_opaque_id LIKE 'usr_delete_%')
      AND task.status <> 'COMPLETED'
  `;
  if ((unfinishedTasks?.count ?? 0) !== 0) {
    throw new Error(`Expected all selected lifecycle tasks to complete, found ${unfinishedTasks?.count} unfinished tasks.`);
  }

  const [unprocessedOutbox] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM ${sql(engineSchema)}.outbox
    WHERE status <> 'processed'
      OR chain_status <> 'finalized'
  `;
  if ((unprocessedOutbox?.count ?? 0) !== 0) {
    throw new Error(`Expected worker outbox to drain completely, found ${unprocessedOutbox?.count} unprocessed/unfinalized events.`);
  }

  await assertAuditLedgerIntegrity(sql, expectedJobs);
  await assertControlPlaneAuditVerification(expectedJobs);

  const [configHeartbeat] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM dpdp_control.audit_ledger
    WHERE event_type = 'WORKER_CONFIG_HEARTBEAT'
      AND payload->>'config_hash' = ${config.configHash}
      AND payload->>'configuration_version' = 'mega-e2e-v1'
      AND payload->>'dpo_identifier' = 'mega-e2e-dpo@example.com'
  `;
  if ((configHeartbeat?.count ?? 0) < 1) {
    throw new Error(`Expected at least one worker config heartbeat for config hash ${config.configHash}.`);
  }

  const [rawRootPii] = await sql<{ count: number }[]>`
    SELECT COUNT(*)::int AS count
    FROM ${sql(appSchema)}.users
    WHERE (id LIKE 'usr_purge_%' OR id LIKE 'usr_delete_%')
      AND (email LIKE '%@mega.example' OR full_name <> '[REDACTED]')
  `;
  if ((rawRootPii?.count ?? 0) !== 0) {
    throw new Error(`Root PII redaction invariant failed for ${rawRootPii?.count} rows.`);
  }

  const [satelliteLeak] = await sql<{ count: number }[]>`
    SELECT
      (
        (SELECT COUNT(*) FROM ${sql(appSchema)}.marketing_leads WHERE email LIKE '%@mega.example') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.system_audit_logs WHERE user_identifier LIKE 'usr_purge_%' OR user_identifier LIKE 'usr_delete_%') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.login_events WHERE user_identifier LIKE 'usr_purge_%' OR user_identifier LIKE 'usr_delete_%') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.notification_tokens WHERE user_identifier LIKE 'usr_purge_%' OR user_identifier LIKE 'usr_delete_%')
      )::int AS count
  `;
  if ((satelliteLeak?.count ?? 0) !== 0) {
    throw new Error(`Satellite mutation invariant failed for ${satelliteLeak?.count} rows.`);
  }

  const [compiledLeak] = await sql<{ count: number }[]>`
    SELECT
      (
        (SELECT COUNT(*) FROM ${sql(appSchema)}.profiles WHERE bio <> '[REDACTED]' OR address = 'Flat 42, Enterprise Road, Bengaluru') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.support_tickets WHERE subject <> '[REDACTED]' OR body LIKE 'Ticket body containing personal context%') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.support_comments WHERE body IS NOT NULL) +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.payment_methods WHERE billing_name <> '[REDACTED]' OR pan_token LIKE '411111111111%') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.account_hierarchy WHERE note <> '[REDACTED]') +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.pii_probe_documents WHERE aadhaar_number = '2000 0000 0009' OR pan_number = 'ABCPE1234F' OR credit_card_number = '4111111111111111' OR upi_id LIKE '%@upi' OR indian_mobile = '+919876543210' OR passport_number = 'A1234567' OR ip_address LIKE '192.168.%' OR nested_payload IS NOT NULL) +
        (SELECT COUNT(*) FROM ${sql(appSchema)}.logical_user_notes WHERE recovery_email LIKE '%@mega.example' OR freeform_phone = '+919876543210' OR note <> '[REDACTED]')
      )::int AS count
  `;
  if ((compiledLeak?.count ?? 0) !== 0) {
    throw new Error(`Compiled DAG mutation invariant failed for ${compiledLeak?.count} rows.`);
  }
}

async function assertControlPlaneAuditVerification(expectedJobs: number): Promise<void> {
  const response = await fetch(`${apiBaseUrl}/api/v1/admin/audit/verify?client_name=worker-1`, {
    headers: tenantHeaders(false),
  });
  if (!response.ok) {
    throw new Error(`Audit verification endpoint failed: HTTP ${response.status} ${await response.text()}`);
  }

  const result = (await response.json()) as AuditVerifyResponse;
  if (!result.valid || result.firstInvalid !== null) {
    throw new Error(`Control Plane audit verification failed: ${JSON.stringify(result)}`);
  }

  const minimumExpectedRows = expectedJobs * 3;
  if (result.checked < minimumExpectedRows) {
    throw new Error(`Audit verification checked ${result.checked} rows; expected at least ${minimumExpectedRows}.`);
  }
}

async function assertAuditLedgerIntegrity(sql: postgres.Sql, expectedJobs: number): Promise<void> {
  const rows = await sql<AuditLedgerRow[]>`
    SELECT
      ledger_seq::int AS ledger_seq,
      worker_idempotency_key,
      event_type,
      payload,
      previous_hash,
      current_hash
    FROM dpdp_control.audit_ledger
    WHERE event_type <> 'WORKER_CONFIG_HEARTBEAT'
    ORDER BY ledger_seq ASC
  `;

  const counts = new Map<string, number>();
  let expectedPreviousHash = "GENESIS";
  const rawPiiPattern =
    /@mega\.example|Purge User|Delete User|Flat 42, Enterprise Road|411111111111|push-token-|AvantiiMegaBrowser/i;

  for (const row of rows) {
    const payloadText = JSON.stringify(row.payload);
    if (rawPiiPattern.test(payloadText)) {
      throw new Error(`Audit ledger payload contains raw seeded PII marker at seq ${row.ledger_seq}.`);
    }

    assertAuditEnvelopeConsistency(row);

    if (row.previous_hash !== expectedPreviousHash) {
      throw new Error(
        `Audit WORM chain fork at seq ${row.ledger_seq}: expected previous ${expectedPreviousHash}, got ${row.previous_hash}.`
      );
    }

    const recomputed = await computeWormHash(row.previous_hash, auditHashPayload(row.payload), row.worker_idempotency_key);
    if (row.current_hash !== recomputed) {
      throw new Error(
        `Audit WORM hash mismatch at seq ${row.ledger_seq}: expected ${recomputed}, got ${row.current_hash}.`
      );
    }

    const envelope = asJsonObject(row.payload);
    const inner = asJsonObject(envelope?.payload);
    const subjectOpaqueId = (envelope?.subject_opaque_id ?? inner?.subject_opaque_id) as string | undefined;

    if (subjectOpaqueId && (subjectOpaqueId.startsWith("usr_purge_") || subjectOpaqueId.startsWith("usr_delete_"))) {
      counts.set(row.event_type, (counts.get(row.event_type) ?? 0) + 1);
    }
    expectedPreviousHash = row.current_hash;
  }

  for (const eventType of ["USER_VAULTED", "NOTIFICATION_SENT", "SHRED_SUCCESS"]) {
    const count = counts.get(eventType) ?? 0;
    if (count !== expectedJobs) {
      throw new Error(`Expected ${expectedJobs} ${eventType} audit events, found ${count}.`);
    }
  }
}

function assertAuditEnvelopeConsistency(row: AuditLedgerRow): void {
  const envelope = asJsonObject(row.payload);
  const inner = asJsonObject(envelope?.payload);
  if (!envelope || !inner) {
    return;
  }

  for (const key of ["request_id", "subject_opaque_id", "event_timestamp"]) {
    if (key in envelope && key in inner && envelope[key] !== inner[key]) {
      throw new Error(
        `Audit envelope mismatch at seq ${row.ledger_seq}: envelope.${key} does not match payload.${key}.`
      );
    }
  }
}

async function printDiagnostics(sql: postgres.Sql, label: string): Promise<void> {
  const statuses = await sql<StatusCounts[]>`
    SELECT status, COUNT(*)::int AS count
    FROM dpdp_control.erasure_jobs
    WHERE subject_opaque_id LIKE 'usr_purge_%' OR subject_opaque_id LIKE 'usr_delete_%'
    GROUP BY status
    ORDER BY status
  `;
  const tasks = await sql<TaskCounts[]>`
    SELECT status, task_type, COUNT(*)::int AS count
    FROM dpdp_control.task_queue
    GROUP BY status, task_type
    ORDER BY status, task_type
  `;
  console.log(JSON.stringify({ label, statuses, tasks }, null, 2));
  for (let index = 1; index <= workerCount; index += 1) {
    const name = workerContainerName(index);
    console.log(`\n--- ${name} logs ---`);
    console.log(run(["docker", "logs", "--tail", "120", name], false));
  }
}

async function getBootstrapWorkerClientId(sql: postgres.Sql): Promise<string> {
  const [client] = await sql<{ id: string }[]>`
    SELECT id::text AS id
    FROM dpdp_control.clients
    WHERE name = 'worker-1'
    LIMIT 1
  `;
  if (!client) {
    throw new Error("Control Plane bootstrap worker client worker-1 was not created.");
  }
  return client.id;
}

async function startWorkers(sql: postgres.Sql): Promise<void> {
  const workerClientId = await getBootstrapWorkerClientId(sql);
  run(
    ["docker", ...composeArgs, "up", "-d", "--build", "--scale", `worker=${workerCount}`],
    true,
    { ...composeEnv(), API_CLIENT_ID: workerClientId }
  );
}

async function main(): Promise<void> {
  requireCapacity();
  const summary: ScaleSummary = {
    totalUsers,
    purgeRequests,
    deleteRequests,
    workerCount,
    seedMs: 0,
    introspectorMs: 0,
    submitMs: 0,
    vaultMs: 0,
    notifyMs: 0,
    shredMs: 0,
  };

  const sql = postgres(databaseUrl, {
    max: 5,
    idle_timeout: 5,
    connect_timeout: 10,
  });

  try {
    cleanupMegaWorkers();
    run(["docker", ...composeArgs, "down", "-v"], false, composeEnv());
    run(["docker", ...composeArgs, "up", "-d", "--build", "postgres"], true, composeEnv());
    await waitForSql(sql, 60_000);

    const seedStart = Date.now();
    await seedEnterpriseDatabase(sql);
    summary.seedMs = Date.now() - seedStart;

    const introspectorStart = Date.now();
    const introspectorAccuracy = await auditIntrospectorAccuracy(sql);
    summary.introspectorMs = Date.now() - introspectorStart;

    const workerConfig = await renderMegaWorkerConfig(sql, introspectorAccuracy);

    run(["docker", ...composeArgs, "up", "-d", "--build", "api"], true, composeEnv());
    await waitForUrl(`${apiBaseUrl}/ready`, 90_000);

    await startWorkers(sql);
    await waitForEngineSchema(sql, 90_000);
    await Promise.all(Array.from({ length: workerCount }, (_, index) => waitForWorkerContainerReady(index + 1, 90_000)));

    const subjects = await buildRequestSubjects(sql);
    const submitStart = Date.now();
    await mapLimit(subjects, requestConcurrency, (subject) =>
      submitErasure(subject.subjectId, subject.triggerSource, subject.idempotencyKey, 0, subject.requestTimestamp)
    );
    if (subjects.length > 0) {
      const replay = await submitErasure(
        subjects[0]!.subjectId,
        subjects[0]!.triggerSource,
        subjects[0]!.idempotencyKey,
        0,
        subjects[0]!.requestTimestamp
      );
      if (replay.idempotent_replay !== true) {
        throw new Error(`Selected request idempotent replay was not detected: ${JSON.stringify(replay)}`);
      }
    }
    summary.submitMs = Date.now() - submitStart;

    const expectedJobs = subjects.length;
    const vaultStart = Date.now();
    await waitForStatusCount(sql, "VAULTED", expectedJobs, jobTimeoutMs);
    summary.vaultMs = Date.now() - vaultStart;

    // Run edge cases after main jobs are safely vaulted
    await assertApiEdgeCases(sql);
    await testHighConcurrencyIdempotency(sql);
    await testDeadLetterRecovery(sql);

    await fastForwardNotifications(sql);

    const notifyStart = Date.now();
    await waitForStatusCount(sql, "NOTICE_SENT", expectedJobs, jobTimeoutMs);
    summary.notifyMs = Date.now() - notifyStart;

    await fastForwardShredding(sql);

    const shredStart = Date.now();
    await waitForStatusCount(sql, "SHREDDED", expectedJobs, jobTimeoutMs);
    summary.shredMs = Date.now() - shredStart;

    await assertMegaInvariants(sql, expectedJobs, workerConfig);
    const performance = await collectPerformanceSnapshot(sql, summary);
    console.log(JSON.stringify({ ok: true, ...workerConfig, summary, performance }, null, 2));
  } catch (error) {
    await printDiagnostics(sql, error instanceof Error ? error.message : String(error)).catch(() => undefined);
    throw error;
  } finally {
    await sql.end();
    if (!keepUp) {
      cleanupMegaWorkers();
      run(["docker", ...composeArgs, "down", "-v"], false, composeEnv());
    }
  }
}

await main();
