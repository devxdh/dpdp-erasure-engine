import type {
  AuditLedgerVerificationResult,
  AuditLedgerRow,
  InsertAuditLedgerEventInput,
  InsertWorkerConfigHeartbeatInput,
  RepositoryContext,
} from "./types";
import { fail } from "@/errors";
import { computeWormHash } from "../hash";

/**
 * Reads the latest WORM hash pointer for a client in O(1) using the sequence index.
 *
 * @param context - Repository SQL context.
 * @param clientId - Worker client id.
 * @returns Current chain head hash or `null` for genesis state.
 */
export async function getLatestAuditHash(
  context: RepositoryContext,
  clientId: string
): Promise<string | null> {
  const [row] = await context.sql<{ current_hash: string }[]>`
    SELECT current_hash
    FROM ${context.sql(context.schema)}.audit_ledger
    WHERE client_id = ${clientId}
      AND event_type <> 'WORKER_CONFIG_HEARTBEAT'
    ORDER BY ledger_seq DESC
    LIMIT 1
  `;
  return row?.current_hash ?? null;
}

/**
 * Appends one audit ledger event with idempotent conflict handling.
 *
 * @param context - Repository SQL context.
 * @param input - Event envelope and chain hashes.
 * @returns `true` when inserted, `false` when conflict indicates replay.
 */
export async function insertAuditLedgerEvent(
  context: RepositoryContext,
  input: InsertAuditLedgerEventInput
): Promise<boolean> {
  const rows = await context.sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext(${`audit-ledger:${input.clientId}`}))`;

    const [existing] = await tx<{ id: string }[]>`
      SELECT id
      FROM ${tx(context.schema)}.audit_ledger
      WHERE worker_idempotency_key = ${input.idempotencyKey}
      LIMIT 1
    `;
    if (existing) {
      return [];
    }

    const [head] = await tx<{ current_hash: string }[]>`
      SELECT current_hash
      FROM ${tx(context.schema)}.audit_ledger
      WHERE client_id = ${input.clientId}
        AND event_type <> 'WORKER_CONFIG_HEARTBEAT'
      ORDER BY ledger_seq DESC
      LIMIT 1
    `;
    const latestHash = head?.current_hash ?? "GENESIS";
    if (input.previousHash !== latestHash) {
      fail({
        code: "API_OUTBOX_PREVIOUS_HASH_INVALID",
        title: "Outbox chain head mismatch",
        detail: "previous_hash does not match the serialized audit ledger hash.",
        status: 409,
        category: "concurrency",
        retryable: true,
        context: {
          clientId: input.clientId,
        },
      });
    }

    return tx<{ id: string }[]>`
      INSERT INTO ${tx(context.schema)}.audit_ledger (
        organization_id,
        client_id,
        worker_idempotency_key,
        event_type,
        payload,
        previous_hash,
        current_hash,
        created_at
      ) VALUES (
        ${input.organizationId},
        ${input.clientId},
        ${input.idempotencyKey},
        ${input.eventType},
        ${tx.json(input.payload as import("postgres").JSONValue)},
        ${input.previousHash},
        ${input.currentHash},
        ${input.now}
      )
      ON CONFLICT (worker_idempotency_key) DO NOTHING
      RETURNING id
    `;
  });

  return rows.length > 0;
}

/**
 * Appends an idempotent worker-config heartbeat marker to the audit ledger.
 *
 * Heartbeat rows intentionally do not advance the WORM chain head: `previous_hash` and
 * `current_hash` are set to the same value so worker outbox chain validation remains stable.
 *
 * @param context - Repository SQL context.
 * @param input - Worker config heartbeat metadata.
 * @returns `true` when inserted, `false` when already observed for this config hash.
 */
export async function insertWorkerConfigHeartbeat(
  context: RepositoryContext,
  input: InsertWorkerConfigHeartbeatInput
): Promise<boolean> {
  const latestHash = (await getLatestAuditHash(context, input.clientId)) ?? "GENESIS";
  const rows = await context.sql<{ id: string }[]>`
    INSERT INTO ${context.sql(context.schema)}.audit_ledger (
      organization_id,
      client_id,
      worker_idempotency_key,
      event_type,
      payload,
      previous_hash,
      current_hash,
      created_at
    ) VALUES (
      ${input.organizationId},
      ${input.clientId},
      ${`worker-config:${input.clientId}:${input.configHash}`},
      'WORKER_CONFIG_HEARTBEAT',
      ${context.sql.json({
    config_hash: input.configHash,
    configuration_version: input.configVersion ?? null,
    dpo_identifier: input.dpoIdentifier ?? null,
    observed_at: input.now.toISOString(),
  } as import("postgres").JSONValue)},
      ${latestHash},
      ${latestHash},
      ${input.now}
    )
    ON CONFLICT (worker_idempotency_key) DO NOTHING
    RETURNING id
  `;

  return rows.length > 0;
}

/**
 * Fetches a previously ingested audit event by its global idempotency key.
 *
 * @param context - Repository SQL context.
 * @param idempotencyKey - Worker idempotency key.
 * @returns Matching audit event or `null`.
 */
export async function getAuditEventByIdempotencyKey(
  context: RepositoryContext,
  idempotencyKey: string
): Promise<AuditLedgerRow | null> {
  const [row] = await context.sql<AuditLedgerRow[]>`
    SELECT *
    FROM ${context.sql(context.schema)}.audit_ledger
    WHERE worker_idempotency_key = ${idempotencyKey}
  `;
  return row ?? null;
}

/**
 * Streams audit ledger rows for operator export and external archival jobs.
 *
 * @param context - Repository SQL context.
 * @param filters - Optional client and sequence window filters.
 * @returns Ordered audit rows from oldest to newest.
 */
export async function listAuditLedgerEvents(
  context: RepositoryContext,
  filters: {
    organizationId?: string;
    clientName?: string;
    afterLedgerSeq?: number;
  } = {}
): Promise<AuditLedgerRow[]> {
  return context.sql<AuditLedgerRow[]>`
    SELECT al.*
    FROM ${context.sql(context.schema)}.audit_ledger AS al
    JOIN ${context.sql(context.schema)}.clients AS c
      ON c.id = al.client_id
    WHERE (${filters.organizationId ?? null}::uuid IS NULL OR al.organization_id = ${filters.organizationId ?? null})
      AND (${filters.clientName ?? null}::text IS NULL OR c.name = ${filters.clientName ?? null})
      AND (${filters.afterLedgerSeq ?? null}::bigint IS NULL OR al.ledger_seq > ${filters.afterLedgerSeq ?? null})
    ORDER BY al.ledger_seq ASC
  `;
}

function extractHashPayload(payload: unknown): unknown {
  if (payload && typeof payload === "object" && !Array.isArray(payload) && "payload" in payload) {
    return (payload as { payload: unknown }).payload;
  }

  return payload;
}

/**
 * Recomputes tenant/client audit chains from genesis and reports the first violation.
 *
 * Worker config heartbeat rows are integrity-checked as markers but do not advance the chain head.
 * Tenant-wide verification tracks a separate head for every worker client because each client
 * appends under an independent advisory lock and therefore has an independent WORM chain.
 *
 * @param context - Repository SQL context.
 * @param filters - Tenant and optional client filter.
 * @returns Verification result safe for admin/API responses.
 */
export async function verifyAuditLedgerChain(
  context: RepositoryContext,
  filters: { organizationId: string; clientName?: string }
): Promise<AuditLedgerVerificationResult> {
  const rows = await listAuditLedgerEvents(context, {
    organizationId: filters.organizationId,
    clientName: filters.clientName,
  });

  const heads = new Map<string, string>();
  let checked = 0;

  for (const row of rows) {
    checked += 1;
    const expectedPreviousHash = heads.get(row.client_id) ?? "GENESIS";

    if (row.event_type === "WORKER_CONFIG_HEARTBEAT") {
      if (row.previous_hash !== row.current_hash) {
        return {
          valid: false,
          checked,
          head: expectedPreviousHash,
          heads: Object.fromEntries(heads),
          firstInvalid: {
            ledger_seq: row.ledger_seq,
            actual_previous_hash: row.previous_hash,
            actual_current_hash: row.current_hash,
            reason: "heartbeat_mismatch",
          },
        };
      }

      continue;
    }

    if (row.previous_hash !== expectedPreviousHash) {
      return {
        valid: false,
        checked,
        head: expectedPreviousHash,
        heads: Object.fromEntries(heads),
        firstInvalid: {
          ledger_seq: row.ledger_seq,
          expected_previous_hash: expectedPreviousHash,
          actual_previous_hash: row.previous_hash,
          actual_current_hash: row.current_hash,
          reason: "previous_hash_mismatch",
        },
      };
    }

    const expectedCurrentHash = await computeWormHash(
      row.previous_hash,
      extractHashPayload(row.payload),
      row.worker_idempotency_key
    );
    if (row.current_hash !== expectedCurrentHash) {
      return {
        valid: false,
        checked,
        head: expectedPreviousHash,
        heads: Object.fromEntries(heads),
        firstInvalid: {
          ledger_seq: row.ledger_seq,
          expected_current_hash: expectedCurrentHash,
          actual_previous_hash: row.previous_hash,
          actual_current_hash: row.current_hash,
          reason: "current_hash_mismatch",
        },
      };
    }

    heads.set(row.client_id, row.current_hash);
  }

  const resolvedHeads = Object.fromEntries(heads);
  const singleHead = filters.clientName && rows[0] ? heads.get(rows[0].client_id) : undefined;

  return {
    valid: true,
    checked,
    head: singleHead ?? (heads.size === 1 ? Array.from(heads.values())[0]! : "MULTI_CLIENT"),
    heads: resolvedHeads,
    firstInvalid: null,
  };
}
