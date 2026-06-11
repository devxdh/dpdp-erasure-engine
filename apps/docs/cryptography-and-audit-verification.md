# Cryptography and Audit Verification

The DPDP Erasure Engine does not just promise that data is deleted; it provides mathematical, cryptographically sound proof. This document explains how the vaulting mechanism works, how cryptographic shredding ensures irreversibility, and how auditors can verify compliance.

## The Problem with "Delete"

In traditional systems, when a company receives a deletion request, they issue a `DELETE` query or flip an `is_deleted = true` flag. 
*   **Soft Deletes**: Flipping a flag is illegal under strict interpretations of the GDPR and DPDP acts because the data is still sitting on the server in plain text.
*   **Hard Deletes**: Issuing a SQL `DELETE` destroys the data, but it leaves no proof behind. When an auditor asks, "Did you delete John Doe's data?", you have nothing to show them except empty space and a text log that could easily be faked.

We solve this using **Cryptographic Shredding**, a **WORM Hash Chain Ledger**, and **Ed25519 Certificates of Erasure**.

## Cryptographic Shredding (The Vault)

Instead of relying on database-level deletes, the Engine encrypts the data to cryptographically ensure it cannot be read.

### The Process:
1.  **Key Generation**: When a deletion request is initiated, the Engine generates a unique, highly secure Data Encryption Key (DEK) specifically for that single user using AES-256-GCM.
2.  **Vaulting**: All the PII extracted from the production database is grouped into a JSON blob. This blob is encrypted using the user's unique DEK.
3.  **Storage**: The encrypted blob is stored in the Vault Database. The DEK itself is encrypted by a master Key Management Service (KMS) key and stored alongside it.
4.  **The Shred Event**: When the legal retention/cool-down period ends, the Engine executes the final erasure. It does not touch the Vault Database. Instead, **it permanently deletes the DEK.**

### Cryptographic Advantages
Once the DEK is destroyed, the AES-256 encrypted blob in the Vault Database becomes mathematically impossible to decrypt. It is indistinguishable from random noise. 

This satisfies the legal definition of "Erasure by Anonymization." The data is physically present (as ciphertext), but it is irreversibly severed from the identity of the user.

## Audit Proof via WORM Hash Chain Ledger

To prove to an auditor that an erasure event actually happened without exposing the data, the Engine writes every state transition (e.g., `USER_VAULTED`, `SHRED_SUCCESS`) into a **WORM (Write-Once-Read-Many) Hash Chain**.

1. **The Chain Structure**: The `audit_ledger` table functions similarly to a blockchain. Every ledger row calculates its `current_hash` using the previous row's hash:
   ```text
   current_hash = SHA-256(previous_hash + canonicalJsonStringify(payload) + idempotencyKey)
   ```
2. **Immutable Integrity**: Because each hash includes the `previous_hash`, it is mathematically impossible to alter, insert, or delete a past audit log without invalidating every subsequent `current_hash` in the entire chain.
3. **Verification**: Operators and auditors can run the `/api/v1/admin/audit/verify` endpoint. This routes to `verifyAuditLedgerChain`, which recalculates the hashes from the genesis block forward. If any tampering has occurred, the engine will instantly pinpoint the exact sequence number where the breach happened.

## Ed25519 Certificates of Erasure

Once an erasure request is completely finished (shredded), the Control Plane mints a **Certificate of Erasure**. 

1. **The Payload**: The certificate details the timestamp, the opaque subject identifier, and the legal framework that triggered the erasure.
2. **The Signature**: The entire payload is cryptographically signed using an **Ed25519 Private Key** (`COE_PRIVATE_KEY_PKCS8_BASE64`) securely held by the Control Plane.
3. **The Artifact**: Consumers can export this certificate as a digitally signed PDF artifact. The PDF visibly embeds the `Signature (Ed25519)` and the `Signing Key ID`.
4. **Third-Party Verification**: Because the signature uses asymmetric cryptography, anyone with the Control Plane's Public Key (`COE_PUBLIC_KEY_SPKI_BASE64`) can verify that the certificate is authentic, was issued by the DPDP engine, and has not been altered since the moment of erasure.

## HMAC Masking in Production

As mentioned in the Introspector documentation, we often use `HMAC_SHA256` to mask unique identifiers (like emails or usernames) in the production database to prevent foreign key violations.

It is critical that this hash is a keyed HMAC and not a simple SHA256 hash. 

If we used simple `SHA256("john.doe@example.com")`, a malicious actor with a rainbow table (a massive list of pre-computed hashes for common emails) could easily reverse the hash and reveal the deleted user's email.

By using an HMAC (Hash-Based Message Authentication Code), the engine hashes the data combining it with a highly secure, secret key (`DPDP_HMAC_KEY`). Even if an attacker dumps your masked database and possesses a massive rainbow table, they cannot reverse the hashes without also stealing the server's master HMAC key.
