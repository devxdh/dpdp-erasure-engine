import { afterEach, describe, expect, it } from "vitest";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { readWorkerConfig } from "@modules/config";

const masterKeyHex = "42".repeat(32);
const hmacKeyBase64 = Buffer.from(new Uint8Array(32).fill(0x24)).toString("base64");

async function writeYaml(contents: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "worker-config-"));
  const path = join(directory, "compliance.worker.yml");
  await writeFile(path, contents, "utf8");
  return path;
}

async function removeYaml(path: string) {
  await rm(path, { force: true });
  await rm(dirname(path), { recursive: true, force: true });
}

describe("Worker configuration", () => {
  const pathsToDelete: string[] = [];

  afterEach(async () => {
    for (const path of pathsToDelete.splice(0, pathsToDelete.length)) {
      await removeYaml(path);
    }
  });

  it("parses strict YAML config with strongly typed graph and satellite definitions", async () => {
    const path = await writeYaml(`
      version: "1.0"
      database:
        app_schema: tenant_app
        engine_schema: tenant_engine
        replica_db_url: postgres://replica:replica@replica-host:5432/postgres
      compliance_policy:
        default_retention_years: 0
        notice_window_hours: 72
        retention_rules:
          - rule_name: PMLA_FINANCIAL
            legal_citation: "Prevention of Money Laundering Act, 2002, Sec 12"
            if_has_data_in:
              - transactions
            retention_years: 10
          - rule_name: RBI_KYC
            legal_citation: "RBI KYC Directions, 2016, Sec 38"
            if_has_data_in:
              - kyc_documents
            retention_years: 5
      graph:
        root_table: users
        root_id_column: id
        max_depth: 32
        root_pii_columns:
          email: HMAC
          full_name: STATIC_MASK
      satellite_targets:
        - table: marketing_leads
          lookup_column: email
          action: redact
          masking_rules:
            email: HMAC
        - table: audit_logs
          lookup_column: user_identifier
          action: hard_delete
      blob_targets:
        - table: users
          column: kyc_document_url
          provider: aws_s3
          region: ap-south-1
          action: versioned_hard_delete
          retention_mode: governance
          expected_bucket_owner: "123456789012"
      purge_policy:
        enabled: true
        selector:
          kind: boolean_column
          column: purge_eligible
          value: true
        max_batch_size: 50000
        actor_opaque_id: system:dpo-purge
        legal_framework: DPDP_2023
        legal_citation: "DPDP Act, 2023 Sec 12; client-approved purge schedule"
      outbox:
        batch_size: 20
        lease_seconds: 90
        max_attempts: 12
        base_backoff_ms: 1500
      security:
        notification_lease_seconds: 180
        master_key_env: DPDP_MASTER_KEY
        hmac_key_env: DPDP_HMAC_KEY
      integrity:
        expected_schema_hash: "${"1".repeat(64)}"
      legal_attestation:
        dpo_identifier: "dpo-name@client.com"
        configuration_version: "v1.2.0"
        legal_review_date: "2026-04-20"
        acknowledgment: "I confirm this configuration accurately reflects our obligations."
    `);
    pathsToDelete.push(path);

    const config = await readWorkerConfig(
      {
        DPDP_MASTER_KEY: masterKeyHex,
        DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
      },
      path
    );

    expect(config.database.app_schema).toBe("tenant_app");
    expect(config.database.engine_schema).toBe("tenant_engine");
    expect(config.database.replica_db_url).toBe("postgres://replica:replica@replica-host:5432/postgres");
    expect(config.compliance_policy.default_retention_years).toBe(0);
    expect(config.compliance_policy.notice_window_hours).toBe(72);
    expect(config.compliance_policy.retention_rules).toEqual([
      {
        rule_name: "PMLA_FINANCIAL",
        legal_citation: "Prevention of Money Laundering Act, 2002, Sec 12",
        if_has_data_in: ["transactions"],
        retention_years: 10,
      },
      {
        rule_name: "RBI_KYC",
        legal_citation: "RBI KYC Directions, 2016, Sec 38",
        if_has_data_in: ["kyc_documents"],
        retention_years: 5,
      },
    ]);
    expect(config.graph.root_table).toBe("users");
    expect(config.graph.root_id_column).toBe("id");
    expect(config.graph.root_pii_columns).toEqual({
      email: "HMAC",
      full_name: "STATIC_MASK",
    });
    expect(config.satellite_targets).toHaveLength(2);
    expect(config.blob_targets).toEqual([
      {
        table: "users",
        column: "kyc_document_url",
        lookup_column: undefined,
        provider: "aws_s3",
        region: "ap-south-1",
        action: "versioned_hard_delete",
        retention_mode: "governance",
        expected_bucket_owner: "123456789012",
        require_version_id: true,
        masking_blob_path: undefined,
      },
    ]);
    expect(config.purge_policy).toEqual({
      enabled: true,
      selector: {
        kind: "boolean_column",
        column: "purge_eligible",
        value: true,
      },
      max_batch_size: 50000,
      actor_opaque_id: "system:dpo-purge",
      legal_framework: "DPDP_2023",
      legal_citation: "DPDP Act, 2023 Sec 12; client-approved purge schedule",
    });
    expect(config.outbox.batch_size).toBe(20);
    expect(config.security.notification_lease_seconds).toBe(180);
    expect(config.legal_attestation).toEqual({
      dpo_identifier: "dpo-name@client.com",
      configuration_version: "v1.2.0",
      legal_review_date: "2026-04-20",
      acknowledgment: "I confirm this configuration accurately reflects our obligations.",
    });
    expect(Buffer.from(config.masterKey).toString("hex")).toBe(masterKeyHex);
    expect(Buffer.from(config.hmacKey).toString("base64")).toBe(hmacKeyBase64);
  });

  it("fails closed when required compliance fields are null", async () => {
    const path = await writeYaml(`
      version: "1.0"
      database:
        app_schema: tenant_app
        engine_schema: tenant_engine
      compliance_policy:
        default_retention_years: null
        notice_window_hours: 48
        retention_rules:
          - rule_name: RBI_KYC
            legal_citation: "RBI KYC Directions, 2016, Sec 38"
            if_has_data_in:
              - kyc_documents
            retention_years: 5
      graph:
        root_table: users
        root_id_column: id
        max_depth: 32
        root_pii_columns:
          email: HMAC
      satellite_targets:
        - table: marketing_leads
          lookup_column: email
          action: redact
          masking_rules:
            email: HMAC
      outbox:
        batch_size: 10
        lease_seconds: 60
        max_attempts: 10
        base_backoff_ms: 1000
      security:
        notification_lease_seconds: 120
        master_key_env: DPDP_MASTER_KEY
        hmac_key_env: DPDP_HMAC_KEY
      integrity:
        expected_schema_hash: "${"1".repeat(64)}"
      legal_attestation:
        dpo_identifier: "dpo-name@client.com"
        configuration_version: "v1.2.0"
        legal_review_date: "2026-04-20"
        acknowledgment: "I confirm this configuration accurately reflects our obligations."
    `);
    pathsToDelete.push(path);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        path
      )
    ).rejects.toThrow(/default_retention_years/i);
  });

  it("rejects malicious identifier injection in root_table", async () => {
    const path = await writeYaml(`
version: "1.0"
database:
  app_schema: tenant_app
  engine_schema: tenant_engine
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules:
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: "users; DROP TABLE clients;--"
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
satellite_targets:
  - table: marketing_leads
    lookup_column: email
    action: redact
    masking_rules:
      email: HMAC
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 1000
security:
  notification_lease_seconds: 120
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"1".repeat(64)}"
legal_attestation:
  dpo_identifier: "dpo-name@client.com"
  configuration_version: "v1.2.0"
  legal_review_date: "2026-04-20"
  acknowledgment: "I confirm this configuration accurately reflects our obligations."
`);
    pathsToDelete.push(path);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        path
      )
    ).rejects.toThrow(/invalid graph root table/i);
  });

  it("fails closed when legal_attestation is missing", async () => {
    const path = await writeYaml(`
version: "1.0"
database:
  app_schema: tenant_app
  engine_schema: tenant_engine
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules:
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: users
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
satellite_targets:
  - table: marketing_leads
    lookup_column: email
    action: redact
    masking_rules:
      email: HMAC
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 1000
security:
  notification_lease_seconds: 120
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"1".repeat(64)}"
`);
    pathsToDelete.push(path);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        path
      )
    ).rejects.toThrow(/legal_attestation/i);
  });

  it("fails closed when purge automation is enabled without an attested selector", async () => {
    const path = await writeYaml(`
version: "1.0"
database:
  app_schema: tenant_app
  engine_schema: tenant_engine
compliance_policy:
  default_retention_years: 0
  notice_window_hours: 48
  retention_rules:
    - rule_name: RBI_KYC
      legal_citation: "RBI KYC Directions, 2016, Sec 38"
      if_has_data_in:
        - kyc_documents
      retention_years: 5
graph:
  root_table: users
  root_id_column: id
  max_depth: 32
  root_pii_columns:
    email: HMAC
purge_policy:
  enabled: true
outbox:
  batch_size: 10
  lease_seconds: 60
  max_attempts: 10
  base_backoff_ms: 1000
security:
  notification_lease_seconds: 120
  master_key_env: DPDP_MASTER_KEY
  hmac_key_env: DPDP_HMAC_KEY
integrity:
  expected_schema_hash: "${"1".repeat(64)}"
legal_attestation:
  dpo_identifier: "dpo-name@client.com"
  configuration_version: "v1.2.0"
  legal_review_date: "2026-04-20"
  acknowledgment: "I confirm this configuration accurately reflects our obligations."
`);
    pathsToDelete.push(path);

    await expect(
      readWorkerConfig(
        {
          DPDP_MASTER_KEY: masterKeyHex,
          DPDP_HMAC_KEY: `base64:${hmacKeyBase64}`,
        },
        path
      )
    ).rejects.toThrow(/purge_policy\.selector/i);
  });
});
