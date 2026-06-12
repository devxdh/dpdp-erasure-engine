# DPDPA 2023 & Statutory Retention: Engineering Compliance Rule Book

This document serves as the absolute baseline for AI verification and architectural design against the Digital Personal Data Protection Act (DPDPA), 2023, the DPDP Rules, and overriding Indian statutory retention laws.

The DPDP Rules mandate full operational compliance, and avoidance mechanisms (e.g., hiding behind a wall of terms of service, soft deletes, or logging plaintext PII to bypass database constraints) will result in systemic regulatory penalties.

---

## Part 1: DPDP Rules Operational Directives

Your application logic and user interfaces must strictly implement the following operational mechanisms.

**1. Notice & Consent Lifecycle**

* **Itemized Notice:** Prior to data collection, the system must render a standalone notice detailing the exact PII collected, the precise purpose, and the mechanism to withdraw consent. It cannot be legally bundled into a generic terms document.
* **Granular Consent:** Consent must be captured independently for each specific purpose.
* **Frictionless Withdrawal:** The operational effort to withdraw consent must be mathematically equal to or less than the effort to grant it. If an opt-in takes two clicks in the UI, an opt-out cannot require a settings maze.
* **Consent Managers:** Architectures must be capable of integrating with registered Consent Managers via API to handle delegated, cross-platform consent lifecycles.

**2. Data Security & Cryptography**

* **Mandatory Safeguards:** The Rules explicitly demand demonstrable data-security measures, including encryption at rest, data masking/tokenization, and strict access controls. Leaving plaintext PII in a primary database table is an automatic failure during a regulatory audit.
* **Log Retention (1-Year Rule):** The Rules mandate that traffic logs and data processing logs be retained for a minimum of **1 year** to prove compliance and processing history.

**3. Breach Notification Protocol (Zero Threshold)**

* **The Rule:** Unlike the GDPR, the DPDP Rules do not feature a "likelihood of harm" threshold. *Every* personal data breach must be reported, regardless of severity.
* **SLA:** The system must trigger an immediate notification to the affected Data Principal (user) and compile a comprehensive technical report to the Data Protection Board of India (DPBI) within **72 hours**.

**4. Mandatory Erasure & The 3-Year Rule (Large Platforms)**

* If your system qualifies as a "Large-scale Data Fiduciary" (E-commerce > 20M users, Gaming > 5M users, Social Media > 20M users), user inactivity is a legally binding trigger for deletion.
* **Trigger:** 3 years from the last user contact/login.
* **Workflow Requirement:** The backend must trigger an automated job that sends a notice to the user exactly **48 hours** prior to the 3-year deadline, offering a final window to halt the deletion protocol.

**5. Children's Data Processing**

* Processing data of individuals under 18 requires verifiable parental consent.
* **Mechanism:** Your application must integrate verification via existing identity records or recognized virtual tokens. Targeted advertising or behavioral monitoring of children is strictly prohibited at the application layer.

---

## Part 2: The Override Matrix (Statutory Retention)

DPDPA erasure requests are legally voided if another Indian statute requires data retention. Your database architecture must isolate and preserve data according to these overrides, even if a user explicitly withdraws consent.

| Regulatory Framework | Target Data Category | Minimum Retention Period | Conflict Resolution (Action on Erasure Request) |
| --- | --- | --- | --- |
| **DPDP Rules** | Traffic & Data Processing Logs. | **1 Year**. | Retain for exactly 1 year to prove processing legality. |
| **CERT-In (IT Act)** | ICT System Logs (IPs, access vectors). | **180 Days** (Rolling). | Retain logs in a masked state. |
| **PMLA, 2002 (AML/KYC)** | Transaction ledgers, KYC documents, identity files. | **5 Years** post-account closure. | Deny erasure of financial ledger data. Move DEK to an isolated vault. |
| **Companies Act, 2013** | Books of accounts, invoices, payment vouchers. | **8 Financial Years**. | Retain financial records. Decouple from primary PII keys using the Erasure Engine. |
| **Income Tax Act, 1961** | Specified financial transaction records. | **8 Years**. | Retain records. Ensure aggregate reporting tables survive the user wipe. |

---

## Part 3: Architecture Verification Checklist

Our **DPDP Erasure Engine** is specifically designed to enforce and solve the following architectural constraints out-of-the-box:

**Database Schema Validation & Cryptography:**

* [x] **No Plaintext Vaulting:** The architecture utilizes cryptographic vaulting (via HMAC-SHA256 and Static Masking) to isolate and protect PII, ensuring the database engine is strictly decoupled from the real data.
* [x] **Blind Indexing:** Exact-match searches against encrypted data are handled via deterministic `HMAC` signatures, allowing secure indexing without plaintext exposure.
* [x] **Cryptographic Shredding vs Soft Deletes:** Legacy soft deletes (`deleted_at TIMESTAMP`) are completely eradicated. We rely on irreversible key destruction after a strict cooldown window to achieve provable deletion.

**Backend Application Logic:**

* [x] **Zero-Knowledge API:** The Control Plane orchestrates requests but operates with zero access to the actual database or encryption keys, which remain isolated inside the Data Plane (Worker).
* [x] **State Machine for Retention Locks:** The engine features an explicit state machine (`WAITING_COOLDOWN`, `EXECUTING`, `VAULTED`, `SHREDDED`) to handle cooldown periods and retention locks, rejecting unauthorized processing while preserving data if necessary.
* [x] **Audit Ledgers:** The Control Plane API securely tracks every cryptographic receipt and state transition into a WORM (Write-Once-Read-Many) compliant ledger to prove execution to auditors.
