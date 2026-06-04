/**
 * Provisions the worker engine schema (`pii_vault`, `user_keys`, `outbox`) and supporting indexes.
 *
 * The migration is idempotent and safe to execute on every boot.
 */

import { assertIdentifier, getLogger } from "@/utils";
import type { Sql } from "@/types";

const logger = getLogger({ component: "migrations" })

/**
 * Applies worker schema migrations for vaulting, shredding, notification, and outbox processing.
 *
 * @param sql - Postgres pool connection.
 * @param engineSchema - Target worker schema name.
 * @returns Promise resolved once all DDL has been applied.
 * @throws {WorkerError} When schema identifier validation fails.
 */
export async function runMigrations(
  sql: Sql,
  engineSchema: string = "dpdp_engine"
) {
  const safeEngineSchema = assertIdentifier(engineSchema, "engine schema name")

  logger.info({ engineSchema: safeEngineSchema }, "Provisioning DPDP engine schema");

  await sql.begin(async (tx) => {
    await tx`CREATE EXTENSION IF NOT EXISTS pgcrypto`;
    await tx`CREATE SCHEMA IF NOT EXISTS ${tx(engineSchema)}`;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeEngineSchema)}.pii_vault (
        user_uuid_hash TEXT primary key,
        request_id TEXT,
        tenant_id TEXT NOT NULL DEFAULT '',
        root_schema TEXT NOT NULL,
        root_id TEXT NOT NULL,
        pseudonym TEXT NOT NULL,
        encrypted_pii JSONB NOT NULL,
        salt TEXT NOT NULL,
        dependency_count INTEGER NOT NULL DEFAULT 0,
        trigger_source TEXT,
        legal_framework TEXT,
        actor_opaque_id TEXT,
        applied_rule_name TEXT,
        applied_rule_citation TEXT,
        retention_expiry TIMESTAMPTZ NOT NULL,
        notification_due_at TIMESTAMPTZ NOT NULL,
        notification_sent_at TIMESTAMPTZ,
        notification_lock_id UUID,
        notification_lock_expires_at TIMESTAMPTZ,
        shredded_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeEngineSchema)}.pii_vault
        ADD COLUMN IF NOT EXISTS request_id TEXT,
        ADD COLUMN IF NOT EXISTS tenant_id TEXT NOT NULL DEFAULT '',
        ADD COLUMN IF NOT EXISTS root_schema TEXT,
        ADD COLUMN IF NOT EXISTS root_table TEXT,
        ADD COLUMN IF NOT EXISTS root_id TEXT,
        ADD COLUMN IF NOT EXISTS pseudonym TEXT,
        ADD COLUMN IF NOT EXISTS dependency_count INTEGER NOT NULL DEFAULT 0,
        ADD COLUMN IF NOT EXISTS trigger_source TEXT,
        ADD COLUMN IF NOT EXISTS legal_framework TEXT,
        ADD COLUMN IF NOT EXISTS actor_opaque_id TEXT,
        ADD COLUMN IF NOT EXISTS applied_rule_name TEXT,
        ADD COLUMN IF NOT EXISTS applied_rule_citation TEXT,
        ADD COLUMN IF NOT EXISTS notification_due_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS notification_sent_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS notification_lock_id UUID,
        ADD COLUMN IF NOT EXISTS notification_lock_expires_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS shredded_at TIMESTAMPTZ,
        ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS pii_vault_root_lookup_idx
      ON ${tx(safeEngineSchema)}.pii_vault (root_schema, root_table, root_id, tenant_id)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS pii_vault_retention_idx
      ON ${tx(safeEngineSchema)}.pii_vault (retention_expiry, notification_due_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS pii_vault_request_idx
      ON ${tx(safeEngineSchema)}.pii_vault (request_id)
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeEngineSchema)}.notification_receipts (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_uuid_hash TEXT NOT NULL REFERENCES ${tx(safeEngineSchema)}.pii_vault(user_uuid_hash) ON DELETE CASCADE,
        request_id TEXT,
        idempotency_key TEXT NOT NULL UNIQUE,
        provider TEXT NOT NULL,
        provider_message_id TEXT,
        template_version TEXT NOT NULL,
        template_hash TEXT NOT NULL,
        sent_at TIMESTAMPTZ NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS notification_receipts_request_idx
      ON ${tx(safeEngineSchema)}.notification_receipts (request_id, sent_at DESC)
    `;


    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeEngineSchema)}.user_keys (
        user_uuid_hash TEXT PRIMARY KEY REFERENCES ${tx(safeEngineSchema)}.pii_vault(user_uuid_hash) ON DELETE CASCADE,
        encrypted_dek BYTEA NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeEngineSchema)}.blob_objects (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_uuid_hash TEXT NOT NULL REFERENCES ${tx(safeEngineSchema)}.pii_vault(user_uuid_hash) ON DELETE CASCADE,
        request_id TEXT,
        tenant_id TEXT NOT NULL DEFAULT '',
        root_schema TEXT NOT NULL,
        root_table TEXT NOT NULL,
        root_id TEXT NOT NULL,
        source_table TEXT NOT NULL,
        source_column TEXT NOT NULL,
        provider TEXT NOT NULL,
        action TEXT NOT NULL,
        retention_mode TEXT NOT NULL DEFAULT 'governance',
        region TEXT NOT NULL,
        expected_bucket_owner TEXT,
        bucket TEXT NOT NULL,
        object_key TEXT NOT NULL,
        version_id TEXT NOT NULL,
        e_tag TEXT,
        masked_value TEXT NOT NULL,
        legal_hold_status TEXT NOT NULL DEFAULT 'ON',
        legal_hold_applied_at TIMESTAMPTZ,
        overwrite_status TEXT NOT NULL DEFAULT 'not_requested',
        overwrite_e_tag TEXT,
        overwrite_version_id TEXT,
        overwrite_applied_at TIMESTAMPTZ,
        shred_status TEXT NOT NULL DEFAULT 'pending',
        shred_receipt JSONB,
        shredded_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT blob_objects_provider_check CHECK (provider IN ('aws_s3')),
        CONSTRAINT blob_objects_action_check CHECK (action IN ('versioned_hard_delete', 'hard_delete', 'overwrite', 'legal_hold_only')),
        CONSTRAINT blob_objects_retention_mode_check CHECK (retention_mode IN ('governance', 'compliance')),
        CONSTRAINT blob_objects_hold_status_check CHECK (legal_hold_status IN ('ON', 'OFF', 'not_supported')),
        CONSTRAINT blob_objects_overwrite_status_check CHECK (overwrite_status IN ('not_requested', 'applied')),
        CONSTRAINT blob_objects_shred_status_check CHECK (shred_status IN ('pending', 'purged', 'captured_version_deleted', 'retained_by_policy'))
      )
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS blob_objects_identity_idx
      ON ${tx(safeEngineSchema)}.blob_objects (
        user_uuid_hash,
        source_table,
        source_column,
        bucket,
        object_key,
        version_id
      )
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS blob_objects_shred_idx
      ON ${tx(safeEngineSchema)}.blob_objects (user_uuid_hash, shred_status)
    `

    await tx`
      CREATE INDEX IF NOT EXISTS blob_objects_object_idx
      ON ${tx(safeEngineSchema)}.blob_objects (provider, bucket, object_key, shred_status)
    `

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeEngineSchema)}.outbox (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        idempotency_key TEXT NOT NULL UNIQUE,
        user_uuid_hash TEXT NOT NULL,
        event_type VARCHAR(50) NOT NULL,
        payload JSONB NOT NULL,
        previous_hash TEXT NOT NULl,
        current_hash TEXT NOT NULL,
        chain_status VARCHAR(20) NOT NULL DEFAULT 'finalized',
        status VARCHAR(20) NOT NULL DEFAULT 'pending',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        lease_token UUID,
        lease_expires_at TIMESTAMPTZ,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processed_at TIMESTAMPTZ,
        last_error TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT outbox_chain_status_check CHECK (chain_status IN ('pending', 'finalized')),
        CONSTRAINT outbox_status_check CHECK (status IN ('pending', 'leased', 'processed', 'dead_letter'))
      )
    `

    await tx`
      ALTER TABLE ${tx(safeEngineSchema)}.outbox
      ADD COLUMN IF NOT EXISTS idempotency_key TEXT,
      ADD COLUMN IF NOT EXISTS previous_hash TEXT,
      ADD COLUMN IF NOT EXISTS current_hash TEXT,
      ADD COLUMN IF NOT EXISTS chain_status VARCHAR(20) NOT NULL DEFAULT 'finalized',
      ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'pending',
      ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS lease_token UUID,
      ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS last_error TEXT,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS outbox_idempotency_key_idx
      ON ${tx(safeEngineSchema)}.outbox (idempotency_key)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS outbox_due_events_idx
      ON ${tx(safeEngineSchema)}.outbox (status, next_attempt_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS outbox_chain_tail_idx
      ON ${tx(safeEngineSchema)}.outbox (created_at DESC, id DESC)
      INCLUDE (current_hash)
      WHERE current_hash IS NOT NULL AND chain_status = 'finalized'
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS outbox_chain_finalize_idx
      ON ${tx(safeEngineSchema)}.outbox (chain_status, created_at, id)
      WHERE chain_status = 'pending'
    `;
  });

  logger.info({ engineSchema: safeEngineSchema }, "DPDP engine schema provisioned");
}