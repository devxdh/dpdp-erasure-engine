# Introspector and PII Classification

Before the Erasure Engine can delete Personally Identifiable Information (PII), it has to know exactly where that PII lives. In a modern architecture with hundreds of tables and thousands of columns, manually mapping this out is extremely difficult and effort intensive.

This is where the **Introspector** comes in.

## Introspector Overview

The Introspector is an intelligent schema-scanning engine built into the Operator CLI. Its job is to connect to your databases, analyze the structure, and automatically identify columns that likely contain sensitive user data.

Instead of writing configuration files by hand, you use the Introspector to generate a **PII Manifest**.

## Classification Workflow

1.  **Connection**: You provide the CLI with a read-only connection string to your database.
2.  **Schema Extraction**: The Introspector pulls down the complete schema: tables, column names, data types, and foreign key relationships.
3.  **Heuristic Analysis**: The engine passes the column names through a set of heuristic rules and regular expressions. 
    *   *Example*: If a column is named `email_address`, `user_phone`, `ssn`, or `dob`, the Introspector flags it with high confidence.
4.  **AI Classification (Optional)**: If enabled, the Introspector can utilize an LLM (Large Language Model) to evaluate ambiguously named columns based on their context and neighboring columns.
5.  **Manifest Generation**: The result is a YAML/JSON configuration file called the **Manifest**.

## The PII Manifest

The Manifest is the source of truth for the Erasure Engine. It tells the Worker nodes exactly what to look for and how to handle it.

Here is an example of what the Introspector generates:

```yaml
version: "1.0"
databases:
  primary_db:
    tables:
      users:
        columns:
          id: 
            type: primary_key
          email: 
            pii_type: EMAIL
            action: HMAC_SHA256  # Hash it so it's unreadable but maintains uniqueness
          first_name: 
            pii_type: NAME
            action: STATIC_MASK
            mask_value: "[REDACTED]"
          last_name:
            pii_type: NAME
            action: NULLIFY      # Replace with SQL NULL
      orders:
        columns:
          id:
            type: primary_key
          user_id:
            type: foreign_key
            references: users.id
          shipping_address:
            pii_type: ADDRESS
            action: STATIC_MASK
            mask_value: "Address Deleted"
```

## Supported Erasure Actions

When the Introspector flags a column, you must decide how the Erasure Engine should handle it. You cannot just "delete" the row, as that breaks foreign keys. The Engine supports several masking actions:

1.  **`NULLIFY`**: Replaces the data with an SQL `NULL`. Best for optional fields (e.g., `last_name`, `phone_number` if not required).
2.  **`STATIC_MASK`**: Replaces the data with a hardcoded string. Best for string fields that have `NOT NULL` constraints (e.g., replacing a name with `[DELETED_USER]`).
3.  **`HMAC_SHA256`**: Replaces the data with a one-way cryptographic hash. **This is critical for Foreign Keys and Unique Constraints.**
    *   *Why?* If `email` has a `UNIQUE` constraint, and you try to `STATIC_MASK` 50 users to `[DELETED]`, the database will throw a constraint error. By using `HMAC`, every deleted user gets a unique, meaningless hash, preserving database integrity while destroying the PII.

## Schema Drift and Safety

Databases change constantly. Developers add new columns and rename old ones. If the Introspector generates a Manifest on Monday, but a developer adds a `billing_address` column on Wednesday, how does the Engine know?

**Strict Schema Hashing.**

When the Introspector runs, it calculates a cryptographic hash of the *entire database schema* and embeds it in the Manifest. 

When a Worker node attempts to execute an erasure task, it first recalculates the live database schema hash. **If the live hash does not match the Manifest hash, the Worker aborts the task immediately.** 

This is a fail-closed mechanism. It prevents the engine from deleting data based on an outdated map, ensuring that newly added PII columns are never accidentally ignored during an erasure request. When this happens, the Operator CLI will alert you that you need to re-run the Introspector and update the Manifest.
