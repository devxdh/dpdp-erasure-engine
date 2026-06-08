# Operator CLI Reference Guide

The Operator CLI (`@dpdp/cli`) is the primary interface for data engineers and privacy operators to manage the Erasure Engine. It is used to introspect databases, manage manifests, and manually trigger workflows.

This document serves as a reference for the available commands.

## Installation

If you are running the project locally or via Docker, the CLI is available via the package manager.

```bash
# From the root of the monorepo
npm run cli -- <command>
```

For global installation (by devxdhanadiya):
```bash
npm install -g dpdp-erasure-cli
```

## Core Commands

### 1. Introspection and Manifest Generation

The core workflow begins by scanning your databases to create a PII Manifest.

```bash
dpdp-cli introspect --dsn="postgresql://user:pass@localhost:5432/prod_db" --out=./manifest.yaml
```
**Options:**
*   `--dsn`: The Database Connection String. (Requires Read-Only permissions).
*   `--out`: The file path to save the generated YAML manifest.
*   `--use-ai`: (Optional) Connects to an LLM provider to help identify cryptically named columns.

**What it does:** Scans the database schema, flags potential PII columns, calculates the schema hash, and generates a draft `manifest.yaml` for you to review.

### 2. Manifest Validation

After manually reviewing and tweaking the generated `manifest.yaml` (e.g., changing an action from `NULLIFY` to `HMAC`), you must validate it to ensure the syntax is correct and all referenced tables exist.

```bash
dpdp-cli validate --manifest=./manifest.yaml --dsn="postgresql://user:pass@localhost:5432/prod_db"
```

**What it does:** Checks the YAML for syntax errors, verifies that all tables and columns listed actually exist in the target database, and confirms the database connection.

### 3. Syncing the Manifest

Once validated, the manifest must be uploaded to the API Control Plane so the Workers can use it.

```bash
dpdp-cli sync --manifest=./manifest.yaml --api-url="http://localhost:3000" --token="your-api-token"
```

**What it does:** Pushes the finalized manifest to the API. If the schema hash inside the manifest doesn't match what the database currently looks like, the API will reject it.

### 4. Triggering Erasure (Manual Override)

While erasures are usually triggered via webhooks from your main application, an Operator can manually trigger an erasure or a Shadow Mode run directly from the CLI.

```bash
dpdp-cli request-erasure --user-id="user_88192A" --shadow=true
```

**Options:**
*   `--user-id`: The primary identifier for the user you wish to delete.
*   `--shadow`: If set to `true`, forces the Worker into Shadow Mode. It will generate a report but roll back the database transaction, leaving data untouched.

### 5. Checking Task Status

To check the status of an ongoing or completed erasure request:

```bash
dpdp-cli status --task-id="tsk_99281"
```

**What it does:** Queries the API and returns the current state of the task (e.g., `SUBMITTED`, `PROCESSING`, `VAULTED`, `FAILED`). If failed, it will return the error logs (e.g., schema hash mismatch, foreign key violation).

---

## Best Practices for Operators

1.  **Always Run Shadow Mode First:** Before syncing a new or updated Manifest, always run a test erasure with `--shadow=true`. Check the API logs to ensure the exact correct rows were targeted and no database constraints were violated.
2.  **Integrate Introspection into CI/CD:** Add the `dpdp-cli introspect` and `validate` commands to your GitHub Actions. If a developer opens a PR that adds a new `user_phone_number` column, the CI pipeline should fail if the PII Manifest is not also updated in the same PR. This guarantees your erasure maps never fall out of date.
