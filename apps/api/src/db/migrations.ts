import type postgres from "postgres";
import { assertIdentifier } from "./identifiers";

/**
 * Provisions the control-plane schema and tables.
 *
 * @param sql - Postgres connection pool.
 * @param controlSchema - Target schema name for control-plane tables.
 * @returns Promise resolved once all DDL has been applied.
 * @throws {ApiError} When schema identifier validation fails.
 */
export async function migrateApiSchema(sql: postgres.Sql, controlSchema: string = "dpdp_control") {
  const safeSchema = assertIdentifier(controlSchema, "control schema name");

  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtext(${`compliance-api-migration:${safeSchema}`}))`;
    await tx`CREATE EXTENSION IF NOT EXISTS pgcrypto`;
    await tx`CREATE SCHEMA IF NOT EXISTS ${tx(safeSchema)}`;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.schema_migrations (
        version TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.organizations (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT NOT NULL UNIQUE,
        billing_plan TEXT NOT NULL DEFAULT 'pilot',
        certificate_archive_retention_days INTEGER NOT NULL DEFAULT 365,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.organizations
      ADD COLUMN IF NOT EXISTS certificate_archive_retention_days INTEGER NOT NULL DEFAULT 365
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email TEXT NOT NULL,
        hashed_password TEXT,
        oidc_provider_id TEXT,
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        role TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (hashed_password IS NOT NULL OR oidc_provider_id IS NOT NULL)
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.auth_users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name TEXT,
        email TEXT NOT NULL UNIQUE,
        email_verified TIMESTAMPTZ,
        image TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.auth_accounts (
        user_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.auth_users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_account_id TEXT NOT NULL,
        refresh_token TEXT,
        access_token TEXT,
        expires_at INTEGER,
        token_type TEXT,
        scope TEXT,
        id_token TEXT,
        session_state TEXT,
        oauth_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (provider, provider_account_id)
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.auth_sessions (
        session_token TEXT PRIMARY KEY,
        user_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.auth_users(id) ON DELETE CASCADE,
        expires TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.auth_verification_tokens (
        identifier TEXT NOT NULL,
        token TEXT NOT NULL,
        expires TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (identifier, token)
      )
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.users DROP CONSTRAINT IF EXISTS users_role_check`;
    await tx`ALTER TABLE ${tx(safeSchema)}.users DROP CONSTRAINT IF EXISTS users_email_key`;
    await tx`
      ALTER TABLE ${tx(safeSchema)}.users
      ADD CONSTRAINT users_role_check CHECK (role IN ('OWNER', 'ADMIN', 'AUDITOR'))
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.api_keys (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        hashed_key TEXT NOT NULL UNIQUE,
        label TEXT NOT NULL,
        scopes TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used_at TIMESTAMPTZ
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.api_rate_limits (
        bucket_key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        reset_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.external_subject_mappings (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        external_subject_hash TEXT NOT NULL,
        subject_opaque_id TEXT NOT NULL,
        tenant_id TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (organization_id, provider, external_subject_hash)
      )
    `;

    await tx`
      INSERT INTO ${tx(safeSchema)}.organizations (id, name, billing_plan)
      VALUES ('00000000-0000-0000-0000-000000000001'::uuid, 'bootstrap', 'internal')
      ON CONFLICT (name) DO NOTHING
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.clients (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        name TEXT NOT NULL UNIQUE,
        worker_api_key_hash TEXT NOT NULL,
        display_name TEXT,
        current_key_id TEXT NOT NULL DEFAULT 'bootstrap',
        webhook_signing_secret TEXT,
        webhook_previous_signing_secret TEXT,
        webhook_secret_rotated_at TIMESTAMPTZ,
        webhook_previous_secret_expires_at TIMESTAMPTZ,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        shadow_success_count INTEGER NOT NULL DEFAULT 0,
        shadow_required_successes INTEGER NOT NULL DEFAULT 100,
        live_mutation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        live_mutation_enabled_at TIMESTAMPTZ,
        require_approved_config BOOLEAN NOT NULL DEFAULT FALSE,
        rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_authenticated_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.worker_request_replays (
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        signature_hash TEXT NOT NULL,
        request_timestamp TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (client_id, signature_hash)
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.clients
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS display_name TEXT,
      ADD COLUMN IF NOT EXISTS current_key_id TEXT NOT NULL DEFAULT 'bootstrap',
      ADD COLUMN IF NOT EXISTS webhook_signing_secret TEXT,
      ADD COLUMN IF NOT EXISTS webhook_previous_signing_secret TEXT,
      ADD COLUMN IF NOT EXISTS webhook_secret_rotated_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS webhook_previous_secret_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT TRUE,
      ADD COLUMN IF NOT EXISTS shadow_success_count INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS shadow_required_successes INTEGER NOT NULL DEFAULT 100,
      ADD COLUMN IF NOT EXISTS live_mutation_enabled BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS live_mutation_enabled_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS require_approved_config BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS rotated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS last_authenticated_at TIMESTAMPTZ
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.worker_config_releases (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        config_hash TEXT NOT NULL,
        configuration_version TEXT NOT NULL,
        dpo_identifier TEXT NOT NULL,
        legal_review_date DATE,
        status TEXT NOT NULL DEFAULT 'APPROVED',
        allowed_live_mutation BOOLEAN NOT NULL DEFAULT FALSE,
        approved_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        notes TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT worker_config_releases_status_check CHECK (status IN ('APPROVED', 'REVOKED'))
      )
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS worker_config_releases_client_hash_uidx
      ON ${tx(safeSchema)}.worker_config_releases (client_id, config_hash)
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.clients
      SET organization_id = (SELECT id FROM ${tx(safeSchema)}.organizations WHERE name = 'bootstrap')
      WHERE organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.clients
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.clients
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.clients DROP CONSTRAINT IF EXISTS clients_name_key`;
    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS clients_organization_name_uidx
      ON ${tx(safeSchema)}.clients (organization_id, name)
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.erasure_jobs (
        id UUID PRIMARY KEY,
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        idempotency_key UUID NOT NULL,
        subject_opaque_id TEXT NOT NULL,
        trigger_source TEXT NOT NULL,
        actor_opaque_id TEXT NOT NULL,
        legal_framework TEXT NOT NULL,
        applied_rule_name TEXT,
        applied_rule_citation TEXT,
        request_timestamp TIMESTAMPTZ NOT NULL,
        tenant_id TEXT,
        cooldown_days INTEGER NOT NULL,
        shadow_mode BOOLEAN NOT NULL DEFAULT FALSE,
        webhook_url TEXT,
        status TEXT NOT NULL,
        vault_due_at TIMESTAMPTZ NOT NULL,
        notification_due_at TIMESTAMPTZ,
        shred_due_at TIMESTAMPTZ,
        shredded_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.erasure_jobs
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS idempotency_key UUID,
      ADD COLUMN IF NOT EXISTS subject_opaque_id TEXT,
      ADD COLUMN IF NOT EXISTS trigger_source TEXT,
      ADD COLUMN IF NOT EXISTS actor_opaque_id TEXT,
      ADD COLUMN IF NOT EXISTS legal_framework TEXT,
      ADD COLUMN IF NOT EXISTS applied_rule_name TEXT,
      ADD COLUMN IF NOT EXISTS applied_rule_citation TEXT,
      ADD COLUMN IF NOT EXISTS request_timestamp TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS tenant_id TEXT,
      ADD COLUMN IF NOT EXISTS cooldown_days INTEGER,
      ADD COLUMN IF NOT EXISTS shadow_mode BOOLEAN NOT NULL DEFAULT FALSE,
      ADD COLUMN IF NOT EXISTS webhook_url TEXT,
      ADD COLUMN IF NOT EXISTS vault_due_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS notification_due_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS shred_due_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS shredded_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.erasure_jobs AS ej
      SET organization_id = c.organization_id
      FROM ${tx(safeSchema)}.clients AS c
      WHERE ej.client_id = c.id
        AND ej.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.erasure_jobs
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.erasure_jobs
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.erasure_jobs DROP CONSTRAINT IF EXISTS erasure_jobs_status_check`;
    await tx`
      ALTER TABLE ${tx(safeSchema)}.erasure_jobs
      ADD CONSTRAINT erasure_jobs_status_check
      CHECK (status IN ('WAITING_COOLDOWN', 'EXECUTING', 'VAULTED', 'NOTICE_SENT', 'SHREDDED', 'FAILED', 'CANCELLED'))
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.task_queue (
        id UUID PRIMARY KEY,
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        erasure_job_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE CASCADE,
        task_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        status TEXT NOT NULL,
        worker_client_name TEXT,
        leased_at TIMESTAMPTZ,
        lease_expires_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        shadow_burn_in_recorded_at TIMESTAMPTZ,
        error_text TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.task_queue
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS worker_client_name TEXT,
      ADD COLUMN IF NOT EXISTS leased_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS completed_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS shadow_burn_in_recorded_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS attempt_count INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS dead_lettered_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS error_text TEXT,
      ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.task_queue AS tq
      SET organization_id = c.organization_id
      FROM ${tx(safeSchema)}.clients AS c
      WHERE tq.client_id = c.id
        AND tq.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.task_queue
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.task_queue
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.task_queue DROP CONSTRAINT IF EXISTS task_queue_status_check`;
    await tx`
      ALTER TABLE ${tx(safeSchema)}.task_queue
      ADD CONSTRAINT task_queue_status_check CHECK (status IN ('QUEUED', 'DISPATCHED', 'COMPLETED', 'FAILED', 'DEAD_LETTER'))
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.webhook_ingestions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        external_reference_id TEXT NOT NULL,
        external_subject_hash TEXT NOT NULL,
        idempotency_key UUID NOT NULL,
        erasure_job_id UUID REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE SET NULL,
        task_id UUID REFERENCES ${tx(safeSchema)}.task_queue(id) ON DELETE SET NULL,
        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (organization_id, client_id, provider, external_reference_id)
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.webhook_ingestions
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS client_id UUID REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS provider TEXT,
      ADD COLUMN IF NOT EXISTS external_reference_id TEXT,
      ADD COLUMN IF NOT EXISTS external_subject_hash TEXT,
      ADD COLUMN IF NOT EXISTS idempotency_key UUID,
      ADD COLUMN IF NOT EXISTS erasure_job_id UUID REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE SET NULL,
      ADD COLUMN IF NOT EXISTS task_id UUID REFERENCES ${tx(safeSchema)}.task_queue(id) ON DELETE SET NULL,
      ADD COLUMN IF NOT EXISTS received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.audit_ledger (
        ledger_seq BIGINT GENERATED ALWAYS AS IDENTITY,
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        worker_idempotency_key TEXT NOT NULL UNIQUE,
        event_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        previous_hash TEXT NOT NULL,
        current_hash TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.audit_ledger
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.audit_ledger AS al
      SET organization_id = c.organization_id
      FROM ${tx(safeSchema)}.clients AS c
      WHERE al.client_id = c.id
        AND al.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.audit_ledger
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.audit_ledger
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.certificates (
        request_id UUID PRIMARY KEY REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE CASCADE,
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        subject_opaque_id TEXT NOT NULL,
        method TEXT NOT NULL,
        legal_framework TEXT NOT NULL,
        shredded_at TIMESTAMPTZ NOT NULL,
        payload JSONB NOT NULL,
        signature_base64 TEXT NOT NULL,
        public_key_spki_base64 TEXT NOT NULL,
        key_id TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        archived_at TIMESTAMPTZ,
        archive_status TEXT NOT NULL DEFAULT 'PENDING',
        archive_attempt_count INTEGER NOT NULL DEFAULT 0,
        archive_next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        archive_lease_token UUID,
        archive_lease_expires_at TIMESTAMPTZ,
        archive_last_error TEXT,
        archive_bucket TEXT,
        archive_object_key TEXT,
        archive_object_etag TEXT,
        archive_object_version_id TEXT,
        archive_retention_until TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.certificates
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS subject_opaque_id TEXT,
      ADD COLUMN IF NOT EXISTS method TEXT,
      ADD COLUMN IF NOT EXISTS legal_framework TEXT,
      ADD COLUMN IF NOT EXISTS shredded_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS payload JSONB,
      ADD COLUMN IF NOT EXISTS signature_base64 TEXT,
      ADD COLUMN IF NOT EXISTS public_key_spki_base64 TEXT,
      ADD COLUMN IF NOT EXISTS key_id TEXT,
      ADD COLUMN IF NOT EXISTS algorithm TEXT,
      ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS archive_status TEXT NOT NULL DEFAULT 'PENDING',
      ADD COLUMN IF NOT EXISTS archive_attempt_count INTEGER NOT NULL DEFAULT 0,
      ADD COLUMN IF NOT EXISTS archive_next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      ADD COLUMN IF NOT EXISTS archive_lease_token UUID,
      ADD COLUMN IF NOT EXISTS archive_lease_expires_at TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS archive_last_error TEXT,
      ADD COLUMN IF NOT EXISTS archive_bucket TEXT,
      ADD COLUMN IF NOT EXISTS archive_object_key TEXT,
      ADD COLUMN IF NOT EXISTS archive_object_etag TEXT,
      ADD COLUMN IF NOT EXISTS archive_object_version_id TEXT,
      ADD COLUMN IF NOT EXISTS archive_retention_until TIMESTAMPTZ,
      ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.certificates AS cert
      SET organization_id = ej.organization_id
      FROM ${tx(safeSchema)}.erasure_jobs AS ej
      WHERE cert.request_id = ej.id
        AND cert.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.certificates
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.certificates
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.certificates DROP CONSTRAINT IF EXISTS certificates_archive_status_check`;
    await tx`
      ALTER TABLE ${tx(safeSchema)}.certificates
      ADD CONSTRAINT certificates_archive_status_check
      CHECK (archive_status IN ('PENDING', 'LEASED', 'ARCHIVED', 'FAILED'))
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS certificates_archival_due_idx
      ON ${tx(safeSchema)}.certificates (archive_status, archive_next_attempt_at, archive_lease_expires_at, created_at)
      WHERE archive_status IN ('PENDING', 'LEASED', 'FAILED')
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.webhook_outbox (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        job_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE CASCADE,
        url TEXT NOT NULL,
        headers JSONB NOT NULL DEFAULT '{}'::jsonb,
        payload JSONB NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        attempt_count INTEGER NOT NULL DEFAULT 0,
        lease_token UUID,
        lease_expires_at TIMESTAMPTZ,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_error TEXT,
        processed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.webhook_outbox
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
      ADD COLUMN IF NOT EXISTS headers JSONB NOT NULL DEFAULT '{}'::jsonb,
      ADD COLUMN IF NOT EXISTS lease_token UUID,
      ADD COLUMN IF NOT EXISTS lease_expires_at TIMESTAMPTZ
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.provider_completion_targets (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        completion_url TEXT NOT NULL,
        auth_header_name TEXT,
        auth_header_value TEXT,
        is_active BOOLEAN NOT NULL DEFAULT TRUE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (organization_id, client_id, provider)
      )
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS provider_completion_targets_lookup_idx
      ON ${tx(safeSchema)}.provider_completion_targets (organization_id, client_id, provider, is_active)
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.webhook_outbox AS wh
      SET organization_id = ej.organization_id
      FROM ${tx(safeSchema)}.erasure_jobs AS ej
      WHERE wh.job_id = ej.id
        AND wh.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.webhook_outbox
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.webhook_outbox
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS webhook_outbox_retry_idx
      ON ${tx(safeSchema)}.webhook_outbox (status, next_attempt_at, lease_expires_at)
      WHERE status IN ('PENDING', 'RETRYING')
    `;

    await tx`
      DELETE FROM ${tx(safeSchema)}.webhook_outbox AS wh
      USING (
        SELECT id,
               ROW_NUMBER() OVER (PARTITION BY job_id, url ORDER BY created_at ASC, id ASC) AS row_number
        FROM ${tx(safeSchema)}.webhook_outbox
      ) AS ranked
      WHERE wh.id = ranked.id
        AND ranked.row_number > 1
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS webhook_outbox_job_url_unique_idx
      ON ${tx(safeSchema)}.webhook_outbox (job_id, url)
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.usage_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        billing_key TEXT NOT NULL UNIQUE,
        organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        client_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.clients(id) ON DELETE CASCADE,
        erasure_job_id UUID REFERENCES ${tx(safeSchema)}.erasure_jobs(id) ON DELETE SET NULL,
        audit_ledger_id UUID REFERENCES ${tx(safeSchema)}.audit_ledger(id) ON DELETE SET NULL,
        event_type TEXT NOT NULL,
        units INTEGER NOT NULL,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        occurred_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.usage_events
      ADD COLUMN IF NOT EXISTS organization_id UUID REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.billing_subscriptions (
        organization_id UUID PRIMARY KEY REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        plan_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_subscription_id TEXT,
        provider_order_id TEXT,
        provider_payment_id TEXT,
        status TEXT NOT NULL,
        current_period_start TIMESTAMPTZ,
        current_period_end TIMESTAMPTZ,
        cancel_at_period_end BOOLEAN NOT NULL DEFAULT FALSE,
        last_event_id TEXT,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CONSTRAINT billing_subscriptions_status_check
          CHECK (status IN ('TRIALING', 'ACTIVE', 'PAST_DUE', 'CANCELLED', 'EXPIRED'))
      )
    `;

    await tx`
      CREATE TABLE IF NOT EXISTS ${tx(safeSchema)}.billing_events (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        organization_id UUID NOT NULL REFERENCES ${tx(safeSchema)}.organizations(id) ON DELETE CASCADE,
        provider TEXT NOT NULL,
        provider_event_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        payload JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (organization_id, provider, provider_event_id)
      )
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS billing_events_org_created_idx
      ON ${tx(safeSchema)}.billing_events (organization_id, created_at DESC)
    `;

    await tx`
      UPDATE ${tx(safeSchema)}.usage_events AS ue
      SET organization_id = c.organization_id
      FROM ${tx(safeSchema)}.clients AS c
      WHERE ue.client_id = c.id
        AND ue.organization_id IS NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.usage_events
      ALTER COLUMN organization_id SET NOT NULL
    `;

    await tx`
      ALTER TABLE ${tx(safeSchema)}.usage_events
      ALTER COLUMN organization_id SET DEFAULT '00000000-0000-0000-0000-000000000001'::uuid
    `;

    await tx`ALTER TABLE ${tx(safeSchema)}.erasure_jobs DROP CONSTRAINT IF EXISTS erasure_jobs_idempotency_key_key`;
    await tx`DROP INDEX IF EXISTS ${tx(safeSchema)}.erasure_jobs_idempotency_key_idx`;
    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS erasure_jobs_organization_idempotency_key_uidx
      ON ${tx(safeSchema)}.erasure_jobs (organization_id, idempotency_key)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS organizations_name_idx
      ON ${tx(safeSchema)}.organizations (name)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS users_organization_idx
      ON ${tx(safeSchema)}.users (organization_id, email)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS auth_accounts_user_idx
      ON ${tx(safeSchema)}.auth_accounts (user_id)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS auth_sessions_user_expires_idx
      ON ${tx(safeSchema)}.auth_sessions (user_id, expires)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS auth_sessions_expires_idx
      ON ${tx(safeSchema)}.auth_sessions (expires)
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS users_organization_email_uidx
      ON ${tx(safeSchema)}.users (organization_id, email)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS api_keys_organization_idx
      ON ${tx(safeSchema)}.api_keys (organization_id, created_at DESC)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS api_rate_limits_reset_idx
      ON ${tx(safeSchema)}.api_rate_limits (reset_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS worker_request_replays_expires_idx
      ON ${tx(safeSchema)}.worker_request_replays (expires_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS external_subject_mappings_lookup_idx
      ON ${tx(safeSchema)}.external_subject_mappings (organization_id, provider, external_subject_hash)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS webhook_ingestions_client_received_idx
      ON ${tx(safeSchema)}.webhook_ingestions (organization_id, client_id, received_at DESC)
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS webhook_ingestions_provider_reference_uidx
      ON ${tx(safeSchema)}.webhook_ingestions (organization_id, client_id, provider, external_reference_id)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (organization_id, status, vault_due_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_client_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (client_id, status, vault_due_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_notice_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (organization_id, status, notification_due_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_client_notice_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (client_id, status, notification_due_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_shred_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (organization_id, status, shred_due_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS erasure_jobs_client_shred_due_status_idx
      ON ${tx(safeSchema)}.erasure_jobs (client_id, status, shred_due_at, created_at)
    `;

    await tx`DROP INDEX IF EXISTS ${tx(safeSchema)}.task_queue_claim_idx`;
    await tx`
      CREATE INDEX task_queue_claim_idx
      ON ${tx(safeSchema)}.task_queue (organization_id, status, next_attempt_at, lease_expires_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS task_queue_client_claim_idx
      ON ${tx(safeSchema)}.task_queue (client_id, status, next_attempt_at, lease_expires_at, created_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS task_queue_job_idx
      ON ${tx(safeSchema)}.task_queue (erasure_job_id, status)
    `;

    await tx`
      CREATE UNIQUE INDEX IF NOT EXISTS task_queue_job_type_uidx
      ON ${tx(safeSchema)}.task_queue (erasure_job_id, task_type)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS task_queue_dead_letter_idx
      ON ${tx(safeSchema)}.task_queue (organization_id, status, dead_lettered_at)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS audit_ledger_client_idx
      ON ${tx(safeSchema)}.audit_ledger (organization_id, client_id, ledger_seq DESC)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS clients_active_name_idx
      ON ${tx(safeSchema)}.clients (organization_id, is_active, name)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS usage_events_client_occurred_idx
      ON ${tx(safeSchema)}.usage_events (organization_id, client_id, occurred_at DESC)
    `;

    await tx`
      CREATE INDEX IF NOT EXISTS usage_events_event_type_idx
      ON ${tx(safeSchema)}.usage_events (event_type, occurred_at DESC)
    `;

    await tx`
      INSERT INTO ${tx(safeSchema)}.schema_migrations (version, checksum, applied_at)
      VALUES ('api_schema_v1', 'monolithic-idempotent-ddl', NOW())
      ON CONFLICT (version) DO UPDATE
      SET checksum = EXCLUDED.checksum,
          applied_at = EXCLUDED.applied_at
    `;
  });
}
