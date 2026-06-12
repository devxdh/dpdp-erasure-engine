# dpdp-erasure-cli

[![npm version](https://badge.fury.io/js/dpdp-erasure-cli.svg)](https://badge.fury.io/js/dpdp-erasure-cli)

**The DPDP Erasure Engine CLI** is an automated, AI-assisted privacy toolkit that helps you securely discover, map, and cryptographically shred PII (Personally Identifiable Information) in your database. 

It acts as the control plane for the [DPDP Erasure Engine](https://github.com/devxdh/dpdp-erasure-engine), allowing Data Protection Officers (DPOs) and Software Engineers to effortlessly comply with global privacy laws (DPDP, GDPR, CCPA) without writing manual SQL deletion scripts.

---

## 🎯 What does it do?

Manually deleting a user across dozens of microservice tables is dangerous and prone to failure. `dpdp-erasure-cli` solves this by:

1. **Introspection & NLP Mapping:** Safely scans your live database (using `TABLESAMPLE` block sampling) to find hidden PII in text columns, JSON blobs, and orphaned tables.
2. **DAG Compilation:** Maps your entire Foreign Key graph to figure out the exact order tables must be deleted to avoid database constraint violations.
3. **Drafting a Manifest:** Automatically generates a `compliance.worker.yml` erasure plan that handles HMAC redaction vs. hard deletion.
4. **Cryptographic Signatures:** Locks the manifest using Ed25519 signatures so production deletion rules cannot be silently altered.
5. **Dry-Run Simulations:** Tests the erasure locally in a rolled-back PostgreSQL transaction to prove it works before you deploy.

---

## 🚀 Installation

This CLI relies on [Bun](https://bun.sh/) for native cryptographic bindings and high-performance execution.

```bash
npm install -g dpdp-erasure-cli
```

---

## 🛠️ Interactive Setup

Don't want to memorize commands? Just run the CLI with no arguments to launch the interactive wizard:

```bash
dpdp-cli
```

---

## 📚 Quick Start Guide

Setting up your database for privacy compliance follows this simple 5-step workflow:

### 1. Introspect Your Database
Safely analyze your schema to discover PII and draft the deletion manifest. The AI will even find logical links if you don't use strict Foreign Keys!

```bash
dpdp-cli introspect \
  --url "postgres://user:pass@localhost:5432/app_db" \
  --root public.users \
  --schema public \
  --output ./compliance.worker.yml
```

### 2. Review and Attest
Open the generated `compliance.worker.yml`. Review the `targets` and `join` conditions. Once you are confident, sign off by updating the `legal_attestation` block.

### 3. Generate Security Keys
Create a private/public keypair to securely sign your manifest for production environments.
```bash
dpdp-cli keygen
```

### 4. Cryptographically Sign the Manifest
Lock down the rules to prevent unauthorized changes in your CI/CD pipeline.
```bash
dpdp-cli sign --config ./compliance.worker.yml --key ./worker.pkcs8.key
```

### 5. Simulate an Erasure (Dry-Run)
Test the erasure on a specific user. This command runs entirely within an isolated transaction that is automatically rolled back, so it is 100% safe.
```bash
dpdp-cli dry-run --id "user_12345" --url "postgres://user:pass@localhost:5432/app_db" --config ./compliance.worker.yml
```

---

## 🔒 CI/CD Integrity Checks

You can use the CLI in your GitHub Actions or GitLab CI to fail builds if a developer modifies the database schema without updating the signed compliance manifest:

```bash
dpdp-cli check-integrity --url "postgres://..." --config ./compliance.worker.yml
```

---

## 📖 Deep Dive

Want to understand the cryptographic shredding architecture under the hood? Read our full documentation at the main repository:

**[DPDP Erasure Engine GitHub Repository](https://github.com/devxdh/dpdp-erasure-engine)**
