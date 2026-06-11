# Operator CLI Reference Guide (`dpdp-erasure-cli`)

[![npm version](https://badge.fury.io/js/dpdp-erasure-cli.svg)](https://badge.fury.io/js/dpdp-erasure-cli)

The **Operator CLI** (`dpdp-erasure-cli`) is the primary interface for data engineers, DevOps, and privacy operators to manage the DPDP Erasure Engine. 

It is used to introspect databases, classify PII, manage compliance manifests, sign them cryptographically, and simulate safe erasure operations locally.

---

## 🚀 Installation

This CLI requires [Bun](https://bun.sh/) for native cryptographic bindings and high-performance execution. Ensure you have Bun installed, then install the package globally:

```bash
npm install -g dpdp-erasure-cli
```

*Alternatively, if running from the monorepo root:*
```bash
bun run --cwd ./apps/worker cli <command>
```

---

## 🛠️ Interactive Console

If you run the CLI without any arguments, it will launch an interactive wizard to guide you through the available operations:

```bash
dpdp-cli
```

---

## 📚 Core Commands & Configuration Guide

### 1. `introspect` (The Core Command)
Safely analyze your database's Foreign Key (FK) Directed Acyclic Graph (DAG) offline and draft a comprehensive PII mapping manifest (`compliance.worker.yml`). This is the first step in setting up the engine.

```bash
dpdp-cli introspect \
  --url postgres://user:pass@localhost:5432/app_db \
  --root public.users \
  --schema public \
  --output ./compliance.worker.yml.draft
```

**Options:**
*   `-u, --url <url>`: PostgreSQL Connection DSN.
*   `-r, --root <table>`: The root table containing the user/subject identifier (e.g., `public.users`).
*   `-s, --schema <schema>`: The target PostgreSQL schema (defaults to `public`).
*   `-o, --output <path>`: Where to write the generated YAML draft (defaults to `compliance.worker.yml.draft`).
*   `-d, --max-depth <depth>`: Limit for recursive Foreign Key traversal (default: `32`).
*   `--sample-percent <percent>`: Percentage of data to sample using `TABLESAMPLE` for PII detection (default: `1`).
*   `--threshold <score>`: Confidence score required to flag a column as PII (default: `0.75`).
*   `--report <path>`: Write a readable Markdown report of the findings.

---

### 2. `scan` (Quick PII Check)
A lightweight, metadata-only schema scan that looks for potential PII columns based purely on naming conventions, without the heavy block sampling used by `introspect`.

```bash
dpdp-cli scan --url "postgres://user:pass@localhost:5432/app_db" --schema public
```

---

### 3. `keygen` (Security Provisioning)
Provisions secure Ed25519 cryptographic keys required to sign your configuration manifest.

```bash
dpdp-cli keygen
```
*This generates a private key file (e.g., `worker.pkcs8.key`) and a public key.*

---

### 4. `sign` (Cryptographic Manifest Lock)
To prevent unauthorized changes to data erasure rules in production, the manifest must be cryptographically signed by a Data Protection Officer (DPO) or Lead Engineer.

```bash
dpdp-cli sign --config ./compliance.worker.yml --key ./worker.pkcs8.key
```
*This generates a detached signature file (e.g., `compliance.worker.yml.sig`). The worker will fail to boot if this signature does not match the manifest.*

---

### 5. `check-integrity` & `verify-schema` (CI/CD Gates)
These commands are designed for CI/CD pipelines to ensure the live database schema matches the legal attestation hash stored in the signed manifest.

```bash
# Verify the compiled DAG and live schema hash
dpdp-cli check-integrity --url "postgres://.../app_db" --config ./compliance.worker.yml

# Check only the live schema hash against the legal attestation
dpdp-cli verify-schema --url "postgres://.../app_db" --config ./compliance.worker.yml
```
*If a developer adds a new column to the database without updating and re-signing the manifest, these commands will exit with a non-zero status.*

---

### 6. `dry-run` (Safe Erasure Simulation)
Simulates a PII vault and redaction operation for a specific user. It runs inside an isolated transaction that is automatically rolled back.

```bash
dpdp-cli dry-run --id "user_12345" --url "postgres://.../app_db" --config ./compliance.worker.yml
```
*This is the recommended safety check to help ensure your configuration captures related PII without breaking foreign keys.*

---

### 7. `graph` (Dependency Visualization)
Visualizes the recursive table dependencies (FK DAG) for a specific root table, helping you understand how data cascades down from a user.

```bash
dpdp-cli graph --table public.users --url "postgres://.../app_db"
```

---

## ⚙️ Standard Workflow Example

Setting up the engine generally follows this workflow:

1.  **Introspect** the database to generate a draft manifest:
    `dpdp-cli introspect -u postgres://... -r public.users -s public -o compliance.worker.yml`
2.  **Review & Tweak** the `compliance.worker.yml` manually (fix false positives, add missing logical links, select masking actions like `HMAC` or `SET NULL`).
3.  **Generate Keys** for signing:
    `dpdp-cli keygen`
4.  **Sign** the finalized manifest:
    `dpdp-cli sign -c compliance.worker.yml -k worker.pkcs8.key`
5.  **Dry-Run** an erasure to verify it behaves as expected:
    `dpdp-cli dry-run -i "test_user_id" -u postgres://... -c compliance.worker.yml`
6.  **Deploy** the signed manifest and the detached `.sig` file to your production Worker.

---

For architectural details and deep-dives into how the cryptographic shredding works, refer to the [Main Documentation](https://github.com/devxdh/dpdp-erasure-engine/tree/main/apps/docs).
