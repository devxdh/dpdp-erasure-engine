# DPDP Erasure Engine CLI (`dpdp-erasure-cli`)

[![npm version](https://badge.fury.io/js/dpdp-erasure-cli.svg)](https://badge.fury.io/js/dpdp-erasure-cli)

The **DPDP Erasure Engine Operator CLI** is an enterprise-grade utility designed to help data fiduciaries comply with modern privacy laws like the **Digital Personal Data Protection (DPDP) Act, 2023**.

This CLI orchestrates the Data Plane, enabling you to inspect databases for Personally Identifiable Information (PII), generate privacy compliance manifests, sign them cryptographically, and execute safe erasure operations.

---

## 🚀 Installation

This CLI relies on [Bun](https://bun.sh/) for native SQLite and cryptographic bindings. Ensure you have Bun installed, then install the package globally:

```bash
npm install -g dpdp-erasure-cli
```

---

## 🛠️ Usage

```bash
dpdp-cli [command] [options]
```

### Core Commands

*   `scan`: Run a metadata-only schema scan across your database to detect potential PII columns based on column names.
*   `introspect`: Safely analyze your database's Foreign Key (FK) DAG offline and draft a comprehensive PII mapping manifest (`compliance.worker.yml`).
*   `keygen`: Provision secure Ed25519 cryptographic keys required for configuration signing.
*   `sign`: Cryptographically sign your `compliance.worker.yml` manifest to lock in your legal attestation hash.
*   `verify`: Perform deep integrity checks to compute mandatory schema hashes and ensure nothing has drifted.
*   `check-integrity`: A CI/CD gate that fails closed unless the schema hash and compiled DAG match your live production database.
*   `verify-schema`: Similar to check-integrity, designed specifically to verify that the live schema matches the legal attestation hash.
*   `dry-run`: Simulate a full PII vault operation without mutating any production data.
*   `graph`: Visualize recursive table dependencies (FK DAG) for a specific root table.
*   `inspect`: Inspect an existing worker manifest and summarize the legal/configuration coverage.
*   `init`: Interactively provision a fresh legal compliance manifest for a new project.

### Example Workflow

**1. Introspect your database to detect PII:**
```bash
dpdp-cli introspect -u postgres://user:pass@localhost:5432/app_db -r public.users -s public -o ./compliance.worker.yml
```

**2. Generate a secure keypair:**
```bash
dpdp-cli keygen
```

**3. Cryptographically sign your manifest:**
```bash
dpdp-cli sign -c ./compliance.worker.yml -k ./coe-private.key
```

**4. Perform a dry-run to ensure safety:**
```bash
dpdp-cli dry-run -u postgres://user:pass@localhost:5432/app_db -c ./compliance.worker.yml
```

---

## 📖 Complete Documentation

For comprehensive instructions on how the entire Engine operates, including the Control Plane API and architectural overviews, please refer to the **[Official GitHub Repository](https://github.com/devxdh/dpdp-erasure-engine)**.
