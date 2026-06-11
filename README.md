# DPDP Erasure Engine & Compliance Worker

[![NPM Version](https://img.shields.io/npm/v/dpdp-erasure-cli.svg)](https://www.npmjs.com/package/dpdp-erasure-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Engine: Bun](https://img.shields.io/badge/Engine-Bun-%23f9f9f9?logo=bun&logoColor=black)](https://bun.sh)
[![Language: TypeScript](https://img.shields.io/badge/Language-TypeScript-blue)](https://www.typescriptlang.org)

A data erasure engine designed to facilitate workflows aligned with modern privacy regulations such as the **Digital Personal Data Protection (DPDP) Act, 2023** (Section 12 - Obligations of Data Fiduciaries regarding erasure of personal data).

---

## 1. What & Why

### The DPDP 2023 Compliance Challenge
Under Section 12 of the DPDP Act 2023, data fiduciaries must erase personal data when an individual withdraws their consent or the specified purpose is fulfilled. Implementing this in production is complex:
- **Linked Data Cascades**: Deleting a user requires tracing and wiping PII scattered across multiple tables (e.g., profiles, sessions, search logs) without breaking database constraints or foreign keys.
- **Overriding Legal Holds**: Other statutory laws (e.g., Anti-Money Laundering or tax rules) dictate that specific transaction records must be retained for years, overriding immediate deletion.
- **Audit Ledger Requirements**: You must prove to auditors that the data was permanently deleted, but the audit trail itself cannot contain the deleted PII.
- **Notice Cooldowns**: Users must receive a pre-erasure notification and a configurable cooldown window (e.g., 48 hours) to retract their request before the deletion becomes irreversible.

### How this Engine Solves it
This engine splits the operational workload into a **Control Plane (API)** for orchestrating requests and a **Data Plane (Worker)** for executing migrations. It moves personal data from application tables into an isolated encrypted vault schema, replacing production fields with static masks or HMAC hashes. After the notice cooldown window expires, the encryption keys in the vault are destroyed (cryptographic shredding), rendering the data permanently and cryptographically inaccessible.

---

## 2. Quick Start: Standalone Evaluation (Zero Local Setup)

To evaluate the engine without cloning this repository or installing Node/Bun, you can spin up the pre-packaged evaluation container directly from Docker Hub. 

This standalone container runs an isolated PostgreSQL instance, pre-seeds a mock application database, generates local keypairs, auto-signs the manifest, and boots both the API and Worker services internally.

### 1. Start the Demo Container
Run the following command:

```bash
docker run -d \
  -p 13000:3000 \
  -p 19464:9464 \
  --name dpdp-erasure-demo \
  devxdh/dpdp-erasure-engine:demo
```

### 2. Verify all Components are Healthy
Wait a few seconds, then query the Control Plane API:

```bash
curl http://localhost:13000/health
# Expected Output: {"ok":true}
```

---

## 3. Operational Pre-Checks: Shadow Mode

Before allowing any third-party engine to mutate your production database, you can run all operations in **Shadow Mode** to verify execution safety:

- **Zero Mutation Strategy**: When submitting an erasure request with `"shadow_mode": true`, the worker executes the complete data extraction, vaulting, and database masking pipeline within an isolated database transaction.
- **Auto-Rollback**: Before committing, the worker triggers a `ShadowModeRollback` error. This forces PostgreSQL to **roll back all modifications**, leaving your target tables completely untouched.
- **Validation**: The engine still returns the complete validation payload, allowing you to verify that PII classification and DAG execution succeeded without writing any mutations to disk.

### Trigger a Shadow Mode Request
Submit a POST request to the API:

```bash
curl -X POST http://localhost:13000/api/v1/erasure-requests \
  -H "Authorization: Bearer admin-secret" \
  -H "Content-Type: application/json" \
  -d '{
    "subject_opaque_id": "usr_purge_000001",
    "idempotency_key": "123e4567-e89b-12d3-a456-426614174000",
    "trigger_source": "USER_CONSENT_WITHDRAWAL",
    "actor_opaque_id": "usr_purge_000001",
    "legal_framework": "DPDP_2023",
    "request_timestamp": "2026-06-07T13:00:00Z",
    "cooldown_days": 0,
    "shadow_mode": true
  }'
```

---

## 4. Production Deployment Workflow

To deploy the engine in production against your actual application database, use the official modular Docker Hub images:

### Step 1: Introspect & Design Manifest
Run the introspection container against your database to detect PII and output a draft manifest configuration file:

```bash
docker run --rm \
  -v $(pwd):/app \
  devxdh/dpdp-erasure-engine-worker:latest \
  introspect \
  -u postgres://user:pass@your-db-host:5432/app_db \
  -r public.users \
  -s public \
  -o /app/compliance.worker.yml
```

### Step 2: Set Classification Mappings
Open `compliance.worker.yml` and review the columns. Specify which erasure method should be applied to each PII column:
- `STATIC_MASK`: Replaces values with static redaction labels (e.g. `[REDACTED]`).
- `HMAC`: Hashes the values, allowing you to lookup records without retaining the original PII.
- `NULL`: Sets the target columns to null.

### Step 3: Generate Keypair & Sign Configuration
To prevent unauthorized modification of your compliance rules, you must cryptographically sign your configuration manifest:

```bash
# Generate key pair
docker run --rm -v $(pwd):/app --entrypoint /usr/local/bin/bun devxdh/dpdp-erasure-engine-worker:latest run apps/worker/src/modules/cli/index.ts keygen

# Sign configuration manifest (this locks in the schema hash)
docker run --rm \
  -v $(pwd):/app \
  devxdh/dpdp-erasure-engine-worker:latest \
  sign \
  -c /app/compliance.worker.yml \
  -k /app/coe-private.key
```

### Step 4: Run API and Worker Containers
Start the Control Plane and Data Plane services. Mount the signed manifest file into the Worker container:

```bash
# Start API Service
docker run -d -p 13000:3000 \
  -e DATABASE_URL=postgres://user:pass@your-db-host:5432/dpdp_control \
  -e WORKER_SHARED_SECRET=secure-worker-secret \
  --name dpdp-api \
  devxdh/dpdp-erasure-engine-api:latest

# Start Worker Service
docker run -d \
  -e DB_URL=postgres://user:pass@your-db-host:5432/app_db \
  -e MAILER_WEBHOOK_URL=https://api.yourdomain.com/ready \
  -v $(pwd)/compliance.worker.yml:/app/apps/worker/compliance.worker.yaml:ro \
  --name dpdp-worker \
  devxdh/dpdp-erasure-engine-worker:latest
```

---

## 5. Introspector Limitations & Manual Oversight

Automated database scanning is a starting point, not a guarantee. Professional deployment **must** include human review:

- **Implicit Logical Links**: The introspector compiles the table relationship graph based on database foreign key constraints. If your application joins tables in-code without database-level constraints, the introspector will not detect them. You must review the `potentialLogicalLinks` output and manually add them as `satellite_targets` in `compliance.worker.yml`.
- **Dynamic JSON/Document Fields**: PII nested inside JSON or text log columns can be missed if they do not match sample thresholds. Ensure these columns are manually specified.
- **DPO Manifest Verification**: A Data Protection Officer (DPO) must audit the generated `compliance.worker.yml` to confirm that all required PII fields are mapped and that legal holds are correctly declared before signing.

---

## 6. Comprehensive Documentation

For detailed internal mechanics, architecture guides, and help integrating this engine with **Zendesk, OneTrust, or Jira**, please refer to our master documentation index:

👉 **[View the Complete Documentation Index (apps/docs)](apps/docs/README.md)**

---

## License

This project is licensed under the Apache 2.0 - see the [LICENSE](LICENSE) file for details.
