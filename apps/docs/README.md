# DPDP Erasure Engine Documentation

Welcome to the comprehensive documentation for the DPDP Erasure Engine. This directory contains detailed guides, architecture overviews, and operational manuals to help you understand, deploy, and verify the engine.

## Part 1: For Consumers & Operators (Project Capabilities)

This section covers what the Erasure Engine does, how it manages production data safely, and how it handles the complexities of data compliance without risking your production databases.

*   **[Architecture and Overview](./overview-and-architecture.md)**
    *   *What it does:* Explains the core problem (Data Sprawl, Referential Integrity) and how the engine solves it via a decentralized Vault & Masking architecture. Covers fail-closed logic and the conflict between Data Retention and Data Erasure.
*   **[Erasure Lifecycle and Shadow Mode](./erasure-lifecycle-and-shadow-mode.md)**
    *   *How it handles data:* Details the strict state machine for PII (Vaulted -> Shredded). It deeply explores **Shadow Mode**, explaining how you can simulate erasures safely against live databases inside isolated, automatically rolled-back transactions.
*   **[Integration and Help Guide](./integration-and-help-guide.md)**
    *   *How to integrate:* A direct guide for developers on how to connect the engine's API to internal dashboards, or third-party platforms like Zendesk, OneTrust, and Jira via webhooks.
*   **[Operator CLI Reference Guide](./cli-operator-reference.md)**
    *   *How to operate:* A command reference for data engineers using the CLI to introspect databases, manage manifests, and manually trigger requests.
*   **[Deployment and Configuration Reference](./deployment-and-configuration-reference.md)**
    *   *How to deploy:* The production deployment guide, featuring a full environment variables reference, API key bootstrapping explanation, and step-by-step instructions for KMS providers (AWS, GCP, Vault).

## Part 2: Deep Dive & Internal Mechanics (For Contributors)

This section provides a technical deep dive into the system's setup, internal algorithms, cryptography, and safety mechanisms. It is designed for engineers contributing to the codebase or auditing its security.

*   **[Introspector and PII Classification](./introspector-and-pii-classification.md)**
    *   *Internal Setup:* Learn how the heuristic engine automatically scans your database schemas, generates PII Manifests, and uses strict Schema Hashing to prevent dangerous configuration drift.
*   **[Cryptography and Audit Verification](./cryptography-and-audit-verification.md)**
    *   *Mechanics:* A deep dive into the cryptographic shredding process (AES-256 vaulting). Explains why keyed HMAC hashing is used for production masking and how Merkle Trees provide cryptographic evidence to auditors that data was rendered inaccessible.

