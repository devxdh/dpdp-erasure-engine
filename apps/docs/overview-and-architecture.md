# Architecture and Overview

Welcome to the DPDP Erasure Engine architecture guide. This document provides a foundational understanding of what the engine does, why it exists, and how its components work together to provide cryptographically verified data erasure.

## Project Purpose and Context

In the modern regulatory landscape (GDPR, CCPA, India's DPDP Act), companies are legally required to delete user data upon request. However, "deleting" data in a complex, microservice-based architecture is incredibly difficult:

1.  **Data Sprawl**: User data isn't in one place. It is spread across primary databases, analytical replicas, caches, and third-party SaaS tools.
2.  **Referential Integrity**: Simply deleting a user record might break foreign key constraints, orphan associated data (like orders or invoices), and crash production applications.
3.  **Proof of Erasure**: When an auditor asks, "Did you delete this user?", simply showing a log line isn't enough. You need mathematical proof that the data is gone and irreversible.
4.  **Trust**: Data teams are terrified of running automated deletion scripts on production databases. 

The **DPDP Erasure Engine** solves these problems. It is an enterprise-grade, "fail-closed" compliance system designed to execute data redaction safely, verify the erasure cryptographically, and provide absolute confidence to data teams through "Shadow Mode."

## Core Capabilities

Instead of issuing raw `DELETE FROM users` queries, the Erasure Engine acts as a **Data Vault and Redaction Controller**. 

1.  **Classification**: It scans your database schemas to find Personally Identifiable Information (PII) using AI and rule-based introspection.
2.  **Vaulting**: It extracts the sensitive PII from your production database and stores it securely in an encrypted internal vault.
3.  **Anonymization**: It replaces the PII in your production database with safe, referentially-intact placeholders (like `HMAC` hashes, `NULL` values, or `STATIC_MASK` strings). This keeps your application running without breaking foreign keys.
4.  **Shadow Mode**: It simulates the entire erasure process inside a database transaction, rolls it back, and reports what *would* have happened, proving to developers that the engine won't break production.
5.  **Shredding**: When the legal retention period expires, it cryptographically shreds the encryption key holding the vaulted data, making the PII permanently unrecoverable.

## System Architecture

The project is built around a robust, decoupled control-plane/data-plane architecture to ensure maximum security and fault tolerance.

```mermaid
graph TD
    Client[Client App / Webhook] -->|Erasure Request| API[API Control Plane]
    CLI[Operator CLI] -->|Schema Updates| API
    
    API -->|Schedules Task| DB_Control[(Control DB - Postgres)]
    
    Worker1[Worker Node] <-->|Polls for Tasks| DB_Control
    Worker2[Worker Node] <-->|Polls for Tasks| DB_Control
    
    Worker1 -->|Redacts PII| DB_Prod[(Production DB)]
    Worker1 -->|Vaults PII| DB_Vault[(Encrypted Vault DB)]
    
    Worker2 -->|Redacts PII| DB_Prod
    Worker2 -->|Vaults PII| DB_Vault
```

### 1. The API Control Plane (`apps/api`)
The API acts as the brain of the operation. It does not touch your production databases directly.
- **Responsibilities**: Receiving erasure requests, managing the PII lifecycle state machine (Submitted -> Vaulted -> Shredded), serving the Operator dashboard, and distributing work to the Worker nodes.
- **Stack**: Hono.js running on Node/Bun, backed by a control database.

### 2. The Worker Data Plane (`apps/worker`)
The Workers are the muscle. They live inside your secure VPC and are the only components that possess credentials to your production databases.
- **Responsibilities**: Executing data extraction, generating cryptographic hashes, updating production rows with masked data, and securely vaulting the original PII. 
- **Fault Tolerance**: Workers are designed to crash safely. They use a "lease" mechanism. If a Worker crashes mid-job, the API detects the expired lease and reassigns the job. The system is entirely idempotent.

### 3. The Operator CLI (`packages/cli`)
The CLI is the interface for data engineers.
- **Responsibilities**: Initializing the project, introspecting production schemas, generating PII manifests (mapping where sensitive data lives), and syncing those manifests with the API.

## Data Retention vs. Data Erasure

A core conflict in compliance is balancing **Data Erasure** (the user's right to be forgotten) with **Data Retention** (legal requirements to keep financial records for tax purposes).

The Erasure Engine handles this gracefully via the **Manifest System**:
- If an email address is in the `users` table, you might want to mask it as `deleted_user_123@anonymized.local`.
- If that same email address is in the `invoices` table, you might have a strict retention policy prohibiting modification for 7 years.
- The Engine allows you to define policies per table and per column, ensuring you comply with erasure laws without violating financial retention laws.

## Failover and Production Safety

"What happens if the API or Worker goes down? Will it corrupt my production data?"

**No.** The system is designed to be **Fail-Closed**.

1.  **Transaction Boundaries**: All database modifications within a single database are wrapped in strict `BEGIN...COMMIT` transactions. If the Worker loses power right before committing, the database rolls back the transaction entirely. No partial deletions.
2.  **Schema Hashing**: Before a Worker touches a database, it hashes the current schema structure and compares it to the Manifest. If a developer recently added a new column or dropped a table, the hash won't match, and the Worker will refuse to run. This prevents the Engine from acting on outdated assumptions.
3.  **Task Leasing**: As mentioned, if a Worker dies while processing a queue item, the API Control Plane simply re-queues it once the lease expires.

---

**Next Steps**:
* Want to know how we safely test this? Read the [Shadow Mode Guide](./erasure-lifecycle-and-shadow-mode.md).
* Want to understand how we detect PII? Read the [Introspector Guide](./introspector-and-pii-classification.md).
